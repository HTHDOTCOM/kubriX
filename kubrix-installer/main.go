package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/suxess-it/kubrix-installer/internal/argocd"
	"github.com/suxess-it/kubrix-installer/internal/bootstrap"
	"github.com/suxess-it/kubrix-installer/internal/config"
	"github.com/suxess-it/kubrix-installer/internal/kube"
	"github.com/suxess-it/kubrix-installer/internal/openbao"
	"github.com/suxess-it/kubrix-installer/internal/prereqs"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	// Print version metadata.
	fmt.Printf("Version: %s\n", envOr("APP_VERSION", "unknown"))
	fmt.Printf("Revision: %s\n", envOr("VCS_REF", "unknown"))
	if data, err := os.ReadFile("/etc/image-version"); err == nil {
		fmt.Println("Image metadata:")
		fmt.Print(string(data))
	}

	// Load and validate all KUBRIX_* environment variables.
	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// Check required external tools.
	if err := prereqs.CheckAll(cfg.Bootstrap); err != nil {
		return err
	}

	// Bootstrap: clone upstream, template, push to downstream.
	if cfg.Bootstrap {
		if err := runBootstrap(ctx, cfg); err != nil {
			return fmt.Errorf("bootstrap: %w", err)
		}
	}

	// When running inside the kubriX installer Job, clone the target repo first.
	if cfg.Installer {
		if err := cloneTargetRepo(cfg); err != nil {
			return fmt.Errorf("clone target repo: %w", err)
		}
	}

	// KinD-specific cluster setup.
	if cfg.ClusterType == "kind" {
		if err := setupKind(ctx, cfg); err != nil {
			return fmt.Errorf("kind setup: %w", err)
		}
	}

	// Install ArgoCD via Helm.
	fmt.Println("installing bootstrap argocd ...")
	if err := kube.RunHelm("repo", "add", "argo-cd", "https://argoproj.github.io/argo-helm"); err != nil {
		return err
	}
	if err := kube.RunHelm("repo", "update"); err != nil {
		return err
	}
	if err := kube.RunHelm(
		"upgrade", "--install", "sx-argocd", "argo-cd",
		"--repo", "https://argoproj.github.io/argo-helm",
		"--version", "9.4.17",
		"--namespace", "argocd",
		"--create-namespace",
		"--set", "configs.cm.application.resourceTrackingMethod=annotation",
		"-f", "bootstrap-argocd-values.yaml",
		"--wait",
	); err != nil {
		return fmt.Errorf("helm install argocd: %w", err)
	}

	// Register the kubriX git repo inside the ArgoCD application-controller pod.
	fmt.Println("add kubriX repo in argocd pod")
	controllerPod, err := kube.RunKubectlOutput(
		"get", "pod", "-n", "argocd",
		"-l", "app.kubernetes.io/name=argocd-application-controller",
		"-o", "jsonpath={.items[0].metadata.name}",
	)
	if err != nil {
		return fmt.Errorf("get argocd controller pod: %w", err)
	}
	if err := kube.RunKubectl(
		"exec", controllerPod, "-n", "argocd", "--",
		"argocd", "repo", "add", cfg.Repo,
		"--username", cfg.RepoUsername,
		"--password", cfg.RepoPassword,
		"--core",
	); err != nil {
		return fmt.Errorf("argocd repo add: %w", err)
	}

	// Generate secrets and optionally apply them.
	fmt.Println("Generating default secrets...")
	if err := runScript("./.secrets/createsecret.sh"); err != nil {
		return fmt.Errorf("createsecret.sh: %w", err)
	}
	if cfg.GenerateSecrets {
		if err := kube.ApplyFile("./.secrets/secrettemp/secrets.yaml"); err != nil {
			return fmt.Errorf("apply secrets: %w", err)
		}
	}

	// Apply the bootstrap ArgoCD Application (repo URL and branch substituted).
	if err := bootstrap.PatchAndApplyBootstrapApp(cfg.TargetType, cfg.Repo, cfg.RepoBranch); err != nil {
		return fmt.Errorf("apply bootstrap app: %w", err)
	}

	// Parse the app list from the target chart values file.
	valuesFile := filepath.Join("platform-apps", "target-chart",
		fmt.Sprintf("values-%s.yaml", cfg.TargetType))
	baseApps, err := bootstrap.ParseAppsFromValuesFile(valuesFile)
	if err != nil {
		return fmt.Errorf("parse apps from %s: %w", valuesFile, err)
	}
	argoApps := config.ExcludeApps(baseApps, cfg.AppExclude)

	// Build Kubernetes clients.
	cs, err := kube.NewClientset()
	if err != nil {
		return fmt.Errorf("kubernetes clientset: %w", err)
	}
	dynClient, err := kube.NewDynamicClient()
	if err != nil {
		return fmt.Errorf("dynamic client: %w", err)
	}

	// Ensure the k8s-monitoring namespace exists (needed for PrometheusRules).
	if err := kube.EnsureNamespace(ctx, cs, "k8s-monitoring"); err != nil {
		return fmt.Errorf("ensure k8s-monitoring namespace: %w", err)
	}

	// Initialise the OpenBao client if OpenBao is part of this stack.
	var vault *openbao.Client
	if containsApp(argoApps, "sx-openbao") {
		if v, vErr := openbao.NewClientFromCluster(ctx, cs); vErr == nil {
			vault = v
		}
	}

	// Wait for all apps to reach Synced + Healthy.
	if err := argocd.WaitUntilSyncedHealthy(ctx, dynClient, cs, argocd.SyncWaitOptions{
		Apps:            argoApps,
		TargetSync:      "Synced",
		TargetHealth:    "Healthy",
		MaxWait:         time.Duration(cfg.BootstrapMaxWaitTime) * time.Second,
		GenerateSecrets: cfg.GenerateSecrets,
		GithubToken:     cfg.BackstageGithubToken,
	}, vault); err != nil {
		return err
	}

	// OpenBao OIDC group-alias setup (needed for all clusters, see issue #422).
	if containsApp(argoApps, "sx-openbao") && vault != nil {
		if err := vault.SetupGroupAliases(ctx); err != nil {
			fmt.Printf("WARNING: setup group aliases: %v\n", err)
		}
	}

	// GitHub Codespaces: inject Backstage environment overrides.
	if os.Getenv("CODESPACES") == "true" && containsApp(argoApps, "sx-backstage") {
		if err := setupCodespaces(ctx, cfg, dynClient); err != nil {
			fmt.Printf("WARNING: codespaces setup: %v\n", err)
		}
	}

	// Remove ephemeral pushsecrets (secrets now live in OpenBao).
	_ = kube.RunKubectl("delete", "-f", "./.secrets/secrettemp/pushsecrets.yaml")

	// On KinD, print the root CA cert for browser import.
	if cfg.ClusterType == "kind" {
		fmt.Println("Installation finished! On KinD clusters we create self-signed certificates for our platform services. You probably need to import this CA cert in your browser to accept the certificates:")
		_ = kube.RunKubectl(
			"get", "secret", "kind-kubrix-ca-key-pair", "-n", "cert-manager",
			"-o", `jsonpath={['data']['tls\.crt']}`,
		)
	}

	return nil
}

// runBootstrap handles the full upstream-clone → template → push workflow.
func runBootstrap(ctx context.Context, cfg *config.Config) error {
	home, _ := os.UserHomeDir()
	bootstrapDir := filepath.Join(home, "bootstrap-kubriX")

	if _, err := os.Stat(bootstrapDir); err == nil {
		fmt.Println("bootstrap-kubriX already exists. We will delete it.")
		if err := os.RemoveAll(bootstrapDir); err != nil {
			return err
		}
	}
	repoDir := filepath.Join(bootstrapDir, "kubriX-repo")
	if err := os.MkdirAll(repoDir, 0755); err != nil {
		return err
	}
	if err := os.Chdir(repoDir); err != nil {
		return err
	}

	if err := bootstrap.CheckDownstreamRepoOrg(cfg); err != nil {
		return err
	}
	repo, err := bootstrap.CloneFromUpstream(cfg)
	if err != nil {
		return err
	}
	if err := bootstrap.TemplateDownstreamRepo(cfg); err != nil {
		return err
	}
	return bootstrap.PushToDownstream(repo, cfg)
}

// cloneTargetRepo checks out the target repo when running inside the installer Job.
func cloneTargetRepo(cfg *config.Config) error {
	home, _ := os.UserHomeDir()
	destDir := filepath.Join(home, "kubriX")

	fmt.Printf("checkout kubriX to %s ...\n", destDir)
	if err := os.MkdirAll(destDir, 0755); err != nil {
		return err
	}

	cloneURL := cfg.RepoProto() + cfg.RepoUsername + ":" + cfg.RepoPassword + "@" + cfg.RepoURL()
	cloneCmd := exec.Command("git", "clone", cloneURL, destDir)
	cloneCmd.Stdout = os.Stdout
	cloneCmd.Stderr = os.Stderr
	if err := cloneCmd.Run(); err != nil {
		return fmt.Errorf("git clone: %w", err)
	}

	if err := os.Chdir(destDir); err != nil {
		return err
	}
	checkoutCmd := exec.Command("git", "checkout", cfg.RepoBranch)
	checkoutCmd.Stdout = os.Stdout
	checkoutCmd.Stderr = os.Stderr
	return checkoutCmd.Run()
}

// setupKind performs KinD-specific cluster initialisation.
func setupKind(ctx context.Context, cfg *config.Config) error {
	cs, err := kube.NewClientset()
	if err != nil {
		return err
	}

	if err := patchCoreDNS(); err != nil {
		return fmt.Errorf("patch CoreDNS: %w", err)
	}

	rootCert := "/etc/tls/kind-kubrix-root-tls.crt"
	rootKey := "/etc/tls/kind-kubrix-tls.key"

	namespaces := []struct {
		ns     string
		secret string
		isTLS  bool
	}{
		{"cert-manager", "kind-kubrix-ca-key-pair", true},
		{"backstage", "kind-kubrix-cacert", false},
		{"openbao", "ca-cert", false},
		{"vault", "ca-cert", false},
		{"testkube", "ca-cert", false},
	}

	for _, entry := range namespaces {
		if err := kube.EnsureNamespace(ctx, cs, entry.ns); err != nil {
			return err
		}
		if entry.isTLS {
			if err := applyFromDryRun("kubectl", "create", "secret", "tls", entry.secret,
				"--key", rootKey, "--cert", rootCert,
				"-n", entry.ns, "--dry-run=client", "-o", "yaml"); err != nil {
				return err
			}
		} else {
			if err := applyFromDryRun("kubectl", "create", "secret", "generic", entry.secret,
				"--from-file=ca.crt="+rootCert,
				"-n", entry.ns, "--dry-run=client", "-o", "yaml"); err != nil {
				return err
			}
		}
	}

	// testkube git credentials.
	if err := applyFromDryRun("kubectl", "create", "secret", "generic", "git-credentials",
		"-n", "testkube",
		"--from-literal=username="+cfg.RepoUsername,
		"--from-literal=token="+cfg.RepoPassword,
		"--dry-run=client", "-o", "yaml"); err != nil {
		return err
	}

	// metrics-server with insecure kubelet TLS for KinD.
	fmt.Println("installing metrics-server in KinD")
	if err := kube.RunHelm("repo", "add", "metrics-server",
		"https://kubernetes-sigs.github.io/metrics-server/"); err != nil {
		return err
	}
	if err := kube.RunHelm("repo", "update"); err != nil {
		return err
	}
	return kube.RunHelm(
		"upgrade", "--install",
		"--set", "args={--kubelet-insecure-tls}",
		"metrics-server", "metrics-server/metrics-server",
		"--namespace", "kube-system",
	)
}

// setupCodespaces injects GitHub Codespaces URL overrides into the backstage secret.
func setupCodespaces(ctx context.Context, cfg *config.Config, dynClient interface{}) error {
	codespaceName := os.Getenv("CODESPACE_NAME")
	domain := os.Getenv("GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN")
	baseURL := fmt.Sprintf("https://%s-6691.%s", codespaceName, domain)

	_ = kube.RunKubectl("delete", "secret", "-n", "backstage", "codespaces-secret",
		"--ignore-not-found=true")

	if err := applyFromDryRun("kubectl",
		"create", "secret", "generic", "-n", "backstage", "codespaces-secret",
		"--from-literal=APP_CONFIG_app_baseUrl="+baseURL,
		"--from-literal=APP_CONFIG_backend_baseUrl="+baseURL,
		"--from-literal=APP_CONFIG_backend_cors_origin="+baseURL,
		"--from-literal=APP_CONFIG_auth_provider_github_development_callbackUrl="+
			baseURL+"/api/auth/github/handler/frame",
		"--dry-run=client", "-o", "yaml"); err != nil {
		return err
	}

	_ = kube.RunKubectl("rollout", "restart", "deployment", "sx-backstage", "-n", "backstage")

	cs, err := kube.NewClientset()
	if err != nil {
		return err
	}
	dynCl, err := kube.NewDynamicClient()
	if err != nil {
		return err
	}
	return argocd.WaitUntilSyncedHealthy(ctx, dynCl, cs, argocd.SyncWaitOptions{
		Apps:         []string{"sx-backstage"},
		TargetSync:   "Synced",
		TargetHealth: "Healthy",
		MaxWait:      600 * time.Second,
	}, nil)
}

// patchCoreDNS injects a nip.io → traefik rewrite rule into the coredns ConfigMap.
func patchCoreDNS() error {
	out, err := kube.RunKubectlOutput("get", "configmap", "coredns", "-n", "kube-system", "-o", "yaml")
	if err != nil {
		return err
	}

	rewrite := []string{
		"        rewrite stop {",
		`          name regex ^(.*)\\.127-0-0-1\\.nip\\.io\\.?$ sx-traefik.traefik.svc.cluster.local`,
		"          answer auto",
		"        }",
	}

	var patched []string
	for _, line := range strings.Split(out, "\n") {
		patched = append(patched, line)
		if strings.Contains(line, "ready") {
			patched = append(patched, rewrite...)
		}
	}

	const tmpFile = "coredns-configmap.yaml"
	if err := os.WriteFile(tmpFile, []byte(strings.Join(patched, "\n")), 0644); err != nil {
		return err
	}
	defer os.Remove(tmpFile)

	if err := kube.ApplyFile(tmpFile); err != nil {
		return err
	}
	if err := kube.RunKubectl("rollout", "restart", "deployment", "coredns", "-n", "kube-system"); err != nil {
		return err
	}
	return kube.RunKubectl("-n", "kube-system", "rollout", "status", "deployment/coredns")
}

// applyFromDryRun runs a kubectl create --dry-run=client -o yaml command and
// pipes the YAML output through kubectl apply -f - for idempotent apply.
func applyFromDryRun(program string, args ...string) error {
	cmd := exec.Command(program, args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("%s %s: %w", program, strings.Join(args, " "), err)
	}
	return kube.ApplyStdin(out)
}

// runScript executes a shell script and streams its output.
func runScript(path string) error {
	cmd := exec.Command("/bin/bash", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func containsApp(apps []string, name string) bool {
	for _, a := range apps {
		if a == name {
			return true
		}
	}
	return false
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
