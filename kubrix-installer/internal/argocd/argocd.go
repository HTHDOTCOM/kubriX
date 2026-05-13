// Package argocd provides helpers for monitoring and managing ArgoCD Application
// sync state using the Kubernetes dynamic client (no ArgoCD CLI needed for reads).
package argocd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"

	"github.com/suxess-it/kubrix-installer/internal/kube"
	"github.com/suxess-it/kubrix-installer/internal/openbao"
)

var applicationGVR = schema.GroupVersionResource{
	Group:    "argoproj.io",
	Version:  "v1alpha1",
	Resource: "applications",
}

// statusRow holds one line of the per-loop status table.
type statusRow struct {
	app          string
	syncStatus   string
	healthStatus string
	syncDuration string
	opPhase      string
}

// SyncWaitOptions configures WaitUntilSyncedHealthy.
type SyncWaitOptions struct {
	Apps            []string
	TargetSync      string
	TargetHealth    string
	MaxWait         time.Duration
	GenerateSecrets bool
	GithubToken     string
}

// WaitUntilSyncedHealthy polls ArgoCD Application CRDs until every app in
// opts.Apps reaches the desired sync and health state, or MaxWait elapses.
// Side effects (pushsecrets, backstage config, k8s-monitoring restart) are
// triggered exactly once per app, matching the original bash behaviour.
func WaitUntilSyncedHealthy(
	ctx context.Context,
	dynClient dynamic.Interface,
	cs *kubernetes.Clientset,
	opts SyncWaitOptions,
	vault *openbao.Client,
) error {
	fmt.Printf("wait until these apps have reached sync state '%s' and health state '%s'\n",
		opts.TargetSync, opts.TargetHealth)
	fmt.Printf("apps: %s\n", strings.Join(opts.Apps, " "))
	fmt.Printf("max wait time: %.0f\n", opts.MaxWait.Seconds())

	deadline := time.Now().Add(opts.MaxWait)
	start := time.Now()

	k8sMonitoringRestarted := false
	secretsApplied := fileExists("./.secrets/secrettemp/secrets-applied")
	backstageConfigured := fileExists("./backstage-openbao-secrets-created")

	controllerPod, err := getControllerPod()
	if err != nil {
		return fmt.Errorf("get argocd controller pod: %w", err)
	}

	allSynced := false
	for time.Now().Before(deadline) {
		allSynced = true

		// Check bootstrap app and restart if stuck.
		maybeRestartBootstrapApp(ctx, dynClient, controllerPod)

		var rows []statusRow

		for _, app := range opts.Apps {
			obj, err := dynClient.Resource(applicationGVR).Namespace("argocd").
				Get(ctx, app, metav1.GetOptions{})
			if err != nil {
				rows = append(rows, statusRow{app: app, syncStatus: "-", healthStatus: "-",
					syncDuration: "-", opPhase: "-"})
				allSynced = false
				continue
			}

			raw, _ := json.Marshal(obj.Object)
			var appJSON map[string]interface{}
			_ = json.Unmarshal(raw, &appJSON)

			syncStatus := nestedStr(appJSON, "status", "sync", "status")
			healthStatus := nestedStr(appJSON, "status", "health", "status")
			opPhase := nestedStr(appJSON, "status", "operationState", "phase")
			startedAt := strings.TrimSuffix(
				nestedStr(appJSON, "status", "operationState", "startedAt"), "Z")
			finishedAt := strings.TrimSuffix(
				nestedStr(appJSON, "status", "operationState", "finishedAt"), "Z")

			// ---- per-app side effects ----

			if app == "sx-openbao" &&
				syncStatus == opts.TargetSync && healthStatus == opts.TargetHealth &&
				!secretsApplied && opts.GenerateSecrets {

				fmt.Println("sx-openbao is synced and healthy — applying pushsecrets")
				fmt.Println()
				if vault != nil {
					if waitErr := vault.WaitForNamespaceAndMount(ctx, 120*time.Second); waitErr == nil {
						fmt.Println("applying pushsecrets")
						_ = kube.ApplyFile("./.secrets/secrettemp/pushsecrets.yaml")
						_ = touchFile("./.secrets/secrettemp/secrets-applied")
						secretsApplied = true
						fmt.Println("waiting for all pushsecrets to sync...")
						_ = kube.RunKubectl("wait", "pushsecret",
							"--all-namespaces", "--all",
							"--for=condition=Ready=True", "--timeout=120s")
						fmt.Println("--------------------")
					} else {
						fmt.Printf("WARNING: skipping pushsecrets: %v\n", waitErr)
					}
				}
			}

			if app == "sx-backstage" && syncStatus == opts.TargetSync && !backstageConfigured {
				fmt.Println("sx-backstage is synced — creating openbao secrets")
				fmt.Println()
				if vault != nil {
					if bsErr := vault.CreateBackstageSecrets(ctx, cs, opts.GithubToken); bsErr != nil {
						fmt.Printf("WARNING: create backstage secrets: %v\n", bsErr)
					}
				}
				_ = touchFile("./backstage-openbao-secrets-created")
				backstageConfigured = true
				fmt.Println("--------------------")
			}

			if app == "sx-k8s-monitoring" &&
				syncStatus == opts.TargetSync && healthStatus == opts.TargetHealth &&
				!k8sMonitoringRestarted {

				_ = argoCDExec(controllerPod, "app", "sync", app, "--async", "--core")
				k8sMonitoringRestarted = true
			}

			// Refresh degraded/progressing apps to help ArgoCD reassess.
			if healthStatus == "Degraded" || healthStatus == "Progressing" {
				_ = argoCDExec(controllerPod, "app", "get", app, "--refresh", "--core")
			}

			// Compute sync duration and restart stuck or failed syncs.
			syncDuration := "-"
			if startedAt != "" {
				t0, err0 := parseTimestamp(startedAt)
				if err0 == nil {
					var elapsed time.Duration
					if finishedAt != "" {
						if t1, err1 := parseTimestamp(finishedAt); err1 == nil {
							elapsed = t1.Sub(t0)
						}
					} else {
						elapsed = time.Since(t0)
					}
					syncDuration = fmt.Sprintf("%.0f", elapsed.Seconds())

					stuck := (opPhase == "Running" && elapsed > 300*time.Second) ||
						opPhase == "Failed" || opPhase == "Error"
					if stuck {
						fmt.Printf("sync of app %s gets terminated because it took longer than 300 seconds or failed\n", app)
						_ = argoCDExec(controllerPod, "app", "terminate-op", app, "--core")
						fmt.Println("wait for 10 seconds")
						time.Sleep(10 * time.Second)
						fmt.Printf("restart sync for app %s\n", app)
						_ = argoCDExec(controllerPod, "app", "sync", app, "--async", "--core")
					}
				}
			}

			if syncStatus != opts.TargetSync || healthStatus != opts.TargetHealth {
				allSynced = false
			}

			rows = append(rows, statusRow{
				app:          app,
				syncStatus:   syncStatus,
				healthStatus: healthStatus,
				syncDuration: syncDuration,
				opPhase:      opPhase,
			})
		}

		printStatusTable(rows)

		if allSynced {
			fmt.Printf("%s apps are synced\n", strings.Join(opts.Apps, " "))
			break
		}

		elapsed := time.Since(start)
		fmt.Println("--------------------")
		fmt.Printf("elapsed time: %.0f seconds\n", elapsed.Seconds())
		fmt.Printf("max wait time: %.0f seconds\n", opts.MaxWait.Seconds())
		fmt.Println("wait another 10 seconds")
		fmt.Println("--------------------")
		showNodeResources()
		fmt.Println("--------------------")
		time.Sleep(10 * time.Second)
	}

	if !allSynced {
		fmt.Println("not all apps synced and healthy after limit reached :(")
		AnalyzeUnhealthyApps(ctx, dynClient, opts.Apps, opts.TargetSync, opts.TargetHealth)
		return fmt.Errorf("not all apps synced within %s", opts.MaxWait)
	}

	fmt.Println("all apps are synced.")
	return nil
}

// AnalyzeUnhealthyApps prints diagnostic information for every app that has
// not reached the target sync/health state.
func AnalyzeUnhealthyApps(
	ctx context.Context,
	dynClient dynamic.Interface,
	apps []string,
	targetSync, targetHealth string,
) {
	controllerPod, _ := getControllerPod()

	for _, app := range apps {
		obj, err := dynClient.Resource(applicationGVR).Namespace("argocd").
			Get(ctx, app, metav1.GetOptions{})
		if err != nil {
			continue
		}
		raw, _ := json.Marshal(obj.Object)
		var appJSON map[string]interface{}
		_ = json.Unmarshal(raw, &appJSON)

		sync := nestedStr(appJSON, "status", "sync", "status")
		health := nestedStr(appJSON, "status", "health", "status")
		if sync != targetSync || health != targetHealth {
			analyzeApp(app, controllerPod)
		}
	}

	fmt.Println("===== k8sgpt analyze =====")
	runCmd("k8sgpt", "analyze")
	fmt.Println("===== kubectl describe node ======")
	_ = kube.RunKubectl("describe", "node")
	fmt.Println("===== kubectl top node  ======")
	_ = kube.RunKubectl("top", "node")
	fmt.Println("===== kubectl get nodes ======")
	_ = kube.RunKubectl("get", "nodes", "-o", "yaml")
	fmt.Println("===== crossplane managed ======")
	_ = kube.RunKubectl("get", "managed")
	_ = kube.RunKubectl("get", "managed", "-o", "yaml")
	_ = kube.RunKubectl("get", "pkg")
	_ = kube.RunKubectl("get", "pkg", "-o", "yaml")
}

func analyzeApp(app, controllerPod string) {
	ns, _ := kube.RunKubectlOutput(
		"get", "applications", "-n", "argocd", app,
		"-o=jsonpath={.spec.destination.namespace}",
	)

	fmt.Println("------------------")
	fmt.Printf("starting analyzing unhealthy/unsynced app '%s'\n", app)
	fmt.Println("------------------")

	fmt.Printf("kubectl get application -n argocd %s -o yaml\n", app)
	_ = kube.RunKubectl("get", "application", "-n", "argocd", app, "-o", "yaml")
	fmt.Println("------------------")

	fmt.Printf("argocd app get %s --show-operation -o json\n", app)
	_ = argoCDExec(controllerPod, "app", "get", app, "--show-operation", "-o", "json", "--core")
	fmt.Println("------------------")

	if ns != "" {
		fmt.Printf("kubectl get events -n %s --sort-by='.lastTimestamp'\n", ns)
		_ = kube.RunKubectl("get", "events", "-n", ns, "--sort-by=.lastTimestamp")
		fmt.Println("------------------")

		fmt.Printf("kubectl get pods -n %s\n", ns)
		_ = kube.RunKubectl("get", "pods", "-n", ns)
		fmt.Println("------------------")

		fmt.Printf("kubectl describe pod -n %s\n", ns)
		_ = kube.RunKubectl("describe", "pod", "-n", ns)
		fmt.Println("------------------")

		// Print logs for all pods in the namespace.
		fmt.Printf("kubectl logs all pods -n %s\n", ns)
		_ = kube.RunKubectl("logs", "-n", ns, "--all-containers=true",
			"--selector=", "--ignore-errors=true", "--prefix=true")
		fmt.Println("------------------")
	}

	fmt.Printf("finished analyzing degraded app '%s'\n", app)
	fmt.Println("------------------")
}

func maybeRestartBootstrapApp(ctx context.Context, dynClient dynamic.Interface, controllerPod string) {
	obj, err := dynClient.Resource(applicationGVR).Namespace("argocd").
		Get(ctx, "sx-bootstrap-app", metav1.GetOptions{})
	if err != nil {
		return
	}
	raw, _ := json.Marshal(obj.Object)
	var appJSON map[string]interface{}
	_ = json.Unmarshal(raw, &appJSON)

	phase := nestedStr(appJSON, "status", "operationState", "phase")
	if phase == "Failed" || phase == "Error" {
		fmt.Println("sx-bootstrap-app sync failed. Restarting sync ...")
		_ = argoCDExec(controllerPod, "app", "terminate-op", "sx-bootstrap-app", "--core")
		_ = argoCDExec(controllerPod, "app", "sync", "sx-bootstrap-app", "--async", "--core")
	}
}

func getControllerPod() (string, error) {
	return kube.RunKubectlOutput(
		"get", "pod", "-n", "argocd",
		"-l", "app.kubernetes.io/name=argocd-application-controller",
		"-o", "jsonpath={.items[0].metadata.name}",
	)
}

func argoCDExec(pod string, args ...string) error {
	kubectlArgs := append([]string{"exec", pod, "-n", "argocd", "--", "argocd"}, args...)
	return kube.RunKubectl(kubectlArgs...)
}

func showNodeResources() {
	fmt.Println()
	fmt.Println("Node resource consumption")
	fmt.Println("-------------------------")
	_ = kube.RunKubectl("top", "node")
}

func printStatusTable(rows []statusRow) {
	fmt.Printf("%-40s %-15s %-15s %-15s %-15s\n",
		"app", "sync-status", "health-status", "sync-duration", "operation-phase")
	for _, r := range rows {
		fmt.Printf("%-40s %-15s %-15s %-15s %-15s\n",
			r.app, r.syncStatus, r.healthStatus, r.syncDuration, r.opPhase)
	}
}

func runCmd(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	_ = cmd.Run()
}

// --- helpers ---

func nestedStr(m map[string]interface{}, keys ...string) string {
	cur := m
	for i, k := range keys {
		v, ok := cur[k]
		if !ok {
			return ""
		}
		if i == len(keys)-1 {
			s, _ := v.(string)
			return s
		}
		cur, ok = v.(map[string]interface{})
		if !ok {
			return ""
		}
	}
	return ""
}

func parseTimestamp(ts string) (time.Time, error) {
	// Strip fractional seconds if present.
	if idx := strings.Index(ts, "."); idx != -1 {
		ts = ts[:idx]
	}
	return time.ParseInLocation("2006-01-02T15:04:05", ts, time.UTC)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func touchFile(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	return f.Close()
}
