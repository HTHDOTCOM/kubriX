// Package openbao provides a minimal HTTP client for the OpenBao (Vault-compatible)
// REST API, covering the operations performed by install-platform.sh.
package openbao

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"time"

	"k8s.io/client-go/kubernetes"

	"github.com/suxess-it/kubrix-installer/internal/kube"
)

// Client holds the connection details for an OpenBao instance.
type Client struct {
	BaseURL    string
	Token      string
	httpClient *http.Client
}

// NewClientFromCluster resolves the OpenBao hostname via the cluster ingress
// and retrieves the root token from the openbao-init secret.
func NewClientFromCluster(ctx context.Context, cs *kubernetes.Clientset) (*Client, error) {
	hosts, err := kube.GetIngressHosts(ctx, cs, "openbao")
	if err != nil || len(hosts) == 0 {
		return nil, fmt.Errorf("cannot resolve OpenBao ingress hostname: %w", err)
	}

	token, err := kube.GetSecretValue(ctx, cs, "openbao", "openbao-init", "root_token")
	if err != nil {
		return nil, fmt.Errorf("cannot get OpenBao root token: %w", err)
	}

	return &Client{
		BaseURL:    "https://" + hosts[0],
		Token:      token,
		httpClient: insecureHTTPClient(),
	}, nil
}

// WaitForNamespaceAndMount polls until the kubrix/ namespace and kubrix-kv/ KV
// mount are both visible, or until the timeout elapses.
func (c *Client) WaitForNamespaceAndMount(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	const poll = 5 * time.Second

	for time.Now().Before(deadline) {
		fmt.Printf("[%s] checking OpenBao namespace and mount readiness...\n",
			time.Now().UTC().Format(time.RFC3339))

		nsBody, err := c.list(ctx, "/v1/sys/namespaces", "")
		if err != nil || !strings.Contains(nsBody, `"kubrix/"`) {
			fmt.Println("waiting for namespace kubrix/ ...")
			time.Sleep(poll)
			continue
		}

		mountsBody, err := c.get(ctx, "/v1/sys/mounts", "kubrix/")
		if err != nil || !strings.Contains(mountsBody, `"kubrix-kv/"`) {
			fmt.Println("waiting for mount kubrix-kv/ in namespace kubrix/ ...")
			time.Sleep(poll)
			continue
		}

		fmt.Println("OpenBao namespace kubrix/ and mount kubrix-kv/ are ready")
		return nil
	}

	return fmt.Errorf("WARNING: OpenBao namespace/mount not ready after %s", timeout)
}

// PatchSecret sends a PATCH request to update fields in an existing KV v2 secret.
func (c *Client) PatchSecret(ctx context.Context, namespace, path string, data map[string]interface{}) error {
	payload := map[string]interface{}{"data": data}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	url := c.BaseURL + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPatch, url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	c.setHeaders(req, namespace)
	req.Header.Set("Content-Type", "application/merge-patch+json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("patch %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("patch %s: status %d: %s", path, resp.StatusCode, string(respBody))
	}
	return nil
}

// SetupGroupAliases creates an OIDC group alias for each identity group that
// does not already have one, matching the behaviour of install-platform.sh.
func (c *Client) SetupGroupAliases(ctx context.Context) error {
	aliasesBody, err := c.list(ctx, "/v1/identity/group-alias/id", "kubrix")
	if err != nil {
		return fmt.Errorf("list group aliases: %w", err)
	}

	var aliasesResp map[string]interface{}
	if err := json.Unmarshal([]byte(aliasesBody), &aliasesResp); err != nil {
		return err
	}

	data, _ := aliasesResp["data"].(map[string]interface{})
	keys, _ := data["keys"].([]interface{})
	if len(keys) > 0 {
		return nil
	}

	fmt.Println("No group aliases found. Setting up group aliases...")

	groupListBody, err := c.list(ctx, "/v1/identity/group/name", "kubrix")
	if err != nil {
		return fmt.Errorf("list groups: %w", err)
	}

	authBody, err := c.get(ctx, "/v1/sys/auth", "kubrix")
	if err != nil {
		return fmt.Errorf("get sys/auth: %w", err)
	}
	var authResp map[string]interface{}
	if err := json.Unmarshal([]byte(authBody), &authResp); err != nil {
		return err
	}
	oidcMount, _ := authResp["oidc/"].(map[string]interface{})
	accessor, _ := oidcMount["accessor"].(string)
	fmt.Printf("OIDC Accessor: %s\n", accessor)

	var groupListResp map[string]interface{}
	if err := json.Unmarshal([]byte(groupListBody), &groupListResp); err != nil {
		return err
	}
	groupData, _ := groupListResp["data"].(map[string]interface{})
	groupNames, _ := groupData["keys"].([]interface{})

	for _, gn := range groupNames {
		groupName, ok := gn.(string)
		if !ok {
			continue
		}
		fmt.Printf("Processing group: %s\n", groupName)

		groupBody, err := c.get(ctx, "/v1/identity/group/name/"+groupName, "kubrix")
		if err != nil {
			fmt.Printf("WARNING: cannot get group %s: %v\n", groupName, err)
			continue
		}
		var groupResp map[string]interface{}
		if err := json.Unmarshal([]byte(groupBody), &groupResp); err != nil {
			continue
		}
		groupDataField, _ := groupResp["data"].(map[string]interface{})
		groupID, _ := groupDataField["id"].(string)
		if groupID == "" || groupID == "null" {
			continue
		}

		aliasPayload := map[string]string{
			"name":           groupName,
			"mount_accessor": accessor,
			"canonical_id":   groupID,
		}
		body, _ := json.Marshal(aliasPayload)
		url := c.BaseURL + "/v1/identity/group-alias"
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return err
		}
		c.setHeaders(req, "kubrix")
		resp, err := c.httpClient.Do(req)
		if err != nil {
			fmt.Printf("WARNING: create group alias for %s: %v\n", groupName, err)
			continue
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		fmt.Printf("Group alias created for %s: %s\n", groupName, string(respBody))
	}

	return nil
}

// CreateBackstageSecrets stores the GitHub token, ArgoCD token, and Grafana
// token into OpenBao so Backstage can read them at runtime.
func (c *Client) CreateBackstageSecrets(ctx context.Context, cs *kubernetes.Clientset, githubToken string) error {
	fmt.Println("adding special configuration for sx-backstage")

	// Empty codespaces-secret still required by Backstage for GitHub Codespaces.
	// Use kubectl dry-run piped into apply to get idempotent create-or-replace.
	dryRunOut, _ := exec.CommandContext(ctx, "kubectl",
		"create", "secret", "generic", "-n", "backstage", "codespaces-secret",
		"--dry-run=client", "-o", "yaml").Output()
	if len(dryRunOut) > 0 {
		_ = kube.ApplyStdin(dryRunOut)
	}

	// Store GitHub token.
	if err := c.PatchSecret(ctx, "kubrix", "/v1/kubrix-kv/data/portal/backstage/base",
		map[string]interface{}{"GITHUB_TOKEN": githubToken}); err != nil {
		return fmt.Errorf("store GITHUB_TOKEN: %w", err)
	}

	// Generate ArgoCD token via kubectl exec into the application-controller pod.
	controllerPod, err := kube.RunKubectlOutput(
		"get", "pod", "-n", "argocd",
		"-l", "app.kubernetes.io/name=argocd-application-controller",
		"-o", "jsonpath={.items[0].metadata.name}",
	)
	if err != nil {
		return fmt.Errorf("get argocd controller pod: %w", err)
	}

	argocdToken, err := kube.RunKubectlOutput(
		"exec", controllerPod, "-n", "argocd", "--",
		"argocd", "account", "generate-token", "--account", "backstage", "--core",
	)
	if err != nil {
		return fmt.Errorf("generate argocd token: %w", err)
	}
	if err := c.PatchSecret(ctx, "kubrix", "/v1/kubrix-kv/data/portal/backstage/base",
		map[string]interface{}{"ARGOCD_AUTH_TOKEN": argocdToken}); err != nil {
		return fmt.Errorf("store ARGOCD_AUTH_TOKEN: %w", err)
	}

	// Generate Grafana token if Grafana is present.
	grafanaToken, err := c.generateGrafanaToken(ctx, cs)
	if err != nil {
		fmt.Printf("WARNING: could not generate Grafana token: %v — using 'dummy'\n", err)
		grafanaToken = "dummy"
	}
	if err := c.PatchSecret(ctx, "kubrix", "/v1/kubrix-kv/data/portal/backstage/base",
		map[string]interface{}{"GRAFANA_TOKEN": grafanaToken}); err != nil {
		return fmt.Errorf("store GRAFANA_TOKEN: %w", err)
	}

	return nil
}

func (c *Client) generateGrafanaToken(ctx context.Context, cs *kubernetes.Clientset) (string, error) {
	hosts, err := kube.GetIngressHosts(ctx, cs, "grafana")
	if err != nil || len(hosts) == 0 {
		return "dummy", nil
	}
	hostname := hosts[0]

	user := "admin"
	password := "prom-operator"
	// Try reading admin credentials from the well-known secret.
	if u, err := kube.GetSecretValue(ctx, cs, "grafana", "grafana-admin-secret", "userKey"); err == nil {
		user = u
	}
	if p, err := kube.GetSecretValue(ctx, cs, "grafana", "grafana-admin-secret", "passwordKey"); err == nil {
		password = p
	}

	baseURL := "https://" + hostname
	client := insecureHTTPClient()

	// Create service account.
	saPayload := `{"name":"backstage","role":"Viewer","isDisabled":false}`
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/serviceaccounts", strings.NewReader(saPayload))
	req.SetBasicAuth(user, password)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var saResp map[string]interface{}
	if err := json.Unmarshal(body, &saResp); err != nil {
		return "", err
	}
	id := fmt.Sprintf("%v", saResp["id"])

	// Create token for the service account.
	tokPayload := `{"name":"backstage"}`
	req2, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		baseURL+"/api/serviceaccounts/"+id+"/tokens", strings.NewReader(tokPayload))
	req2.SetBasicAuth(user, password)
	req2.Header.Set("Content-Type", "application/json")
	resp2, err := client.Do(req2)
	if err != nil {
		return "", err
	}
	defer resp2.Body.Close()
	body2, _ := io.ReadAll(resp2.Body)
	var tokResp map[string]interface{}
	if err := json.Unmarshal(body2, &tokResp); err != nil {
		return "", err
	}
	token, _ := tokResp["key"].(string)
	return token, nil
}

// --- internal HTTP helpers ---

func (c *Client) get(ctx context.Context, path, namespace string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+path, nil)
	if err != nil {
		return "", err
	}
	c.setHeaders(req, namespace)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func (c *Client) list(ctx context.Context, path, namespace string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, "LIST", c.BaseURL+path, nil)
	if err != nil {
		return "", err
	}
	c.setHeaders(req, namespace)
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return string(body), nil
}

func (c *Client) setHeaders(req *http.Request, namespace string) {
	req.Header.Set("X-Vault-Token", c.Token)
	if namespace != "" {
		req.Header.Set("X-Vault-Namespace", namespace)
	}
}

func insecureHTTPClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		},
		Timeout: 30 * time.Second,
	}
}
