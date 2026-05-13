// Package bootstrap handles cloning the upstream kubriX repo, rendering
// customer-specific templates with gomplate, and pushing to the downstream repo.
package bootstrap

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	gogit "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/config"
	"github.com/go-git/go-git/v5/plumbing"
	githttp "github.com/go-git/go-git/v5/plumbing/transport/http"

	kubrixcfg "github.com/suxess-it/kubrix-installer/internal/config"
)

// CheckDownstreamRepoOrg verifies via the GitHub API that the downstream repo
// is owned by an organisation (not a personal account). Only runs for github.com.
func CheckDownstreamRepoOrg(cfg *kubrixcfg.Config) error {
	repoURL := cfg.RepoURL()
	parts := strings.SplitN(repoURL, "/", 3)
	if len(parts) < 3 || parts[0] != "github.com" {
		return nil
	}
	owner := parts[1]
	repo := strings.TrimSuffix(parts[2], ".git")

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s", owner, repo)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, apiURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Authorization", "Bearer "+cfg.RepoPassword)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("prereq check failed: unable to read repository '%s/%s' from GitHub API: %w", owner, repo, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("prereq check failed: GitHub API returned %d for '%s/%s'", resp.StatusCode, owner, repo)
	}

	var repoJSON map[string]interface{}
	if err := json.Unmarshal(body, &repoJSON); err != nil {
		return fmt.Errorf("parse GitHub API response: %w", err)
	}

	owner_, _ := repoJSON["owner"].(map[string]interface{})
	ownerType, _ := owner_["type"].(string)
	if ownerType != "Organization" {
		return fmt.Errorf("prereq check failed: repository '%s/%s' is not owned by an organization account", owner, repo)
	}
	return nil
}

// CloneFromUpstream clones the upstream kubriX repo into the current directory.
// If UpstreamRepoPassword is set, credentials are embedded in the clone URL.
func CloneFromUpstream(cfg *kubrixcfg.Config) (*gogit.Repository, error) {
	fmt.Printf("bootstrap from upstream repo %s to downstream repo %s\n", cfg.UpstreamRepo, cfg.Repo)
	fmt.Printf("checkout kubriX upstream to %s ...\n", mustGetwd())

	cloneOpts := &gogit.CloneOptions{
		URL:      cfg.UpstreamRepo,
		Progress: os.Stdout,
	}
	if strings.TrimSpace(cfg.UpstreamRepoPassword) != "" {
		cloneOpts.Auth = &githttp.BasicAuth{
			Username: cfg.UpstreamRepoUsername,
			Password: cfg.UpstreamRepoPassword,
		}
	}

	repo, err := gogit.PlainClone(".", false, cloneOpts)
	if err != nil {
		return nil, fmt.Errorf("clone upstream repo: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return nil, err
	}
	if err := wt.Checkout(&gogit.CheckoutOptions{
		Branch: plumbing.NewRemoteReferenceName("origin", cfg.UpstreamBranch),
		Create: false,
	}); err != nil {
		return nil, fmt.Errorf("checkout branch %s: %w", cfg.UpstreamBranch, err)
	}

	gitCfg, err := repo.Config()
	if err != nil {
		return nil, err
	}
	gitCfg.User.Name = "kubrix-installer[kubrix-bot]"
	gitCfg.User.Email = "kubrix-installer[kubrix-bot]@users.noreply.github.com"
	if err := repo.SetConfig(gitCfg); err != nil {
		return nil, fmt.Errorf("set git config: %w", err)
	}

	if !cfg.BootstrapKeepHistory {
		// Create an orphan branch to hide upstream commit history.
		// go-git doesn't have a direct orphan option; we point HEAD at a new
		// branch reference that has no commits yet — the next commit becomes root.
		publishRef := plumbing.NewBranchReferenceName("publish")
		if err := repo.Storer.SetReference(
			plumbing.NewSymbolicReference(plumbing.HEAD, publishRef),
		); err != nil {
			return nil, fmt.Errorf("create orphan branch: %w", err)
		}
	}

	return repo, nil
}

// TemplateDownstreamRepo writes customer-config.yaml and renders .yaml.tmpl
// files using gomplate, then optionally excludes apps via yq.
func TemplateDownstreamRepo(cfg *kubrixcfg.Config) error {
	repoURL := cfg.RepoURL()
	parts := strings.SplitN(repoURL, "/", 3)
	repoOrg := ""
	repoName := ""
	if len(parts) >= 3 {
		repoOrg = parts[1]
		repoName = strings.TrimSuffix(parts[2], ".git")
	}

	customerConfig := fmt.Sprintf(`clusterType: %s
cloudProvider: %s
dnsProvider: %s
certManagerDnsProvider: %s
tShirtSize: %s
securityStrict: %v
haEnabled: %v
domain: %s
gitRepo: %s
gitRepoOrg: %s
gitRepoName: %s
gitUser: %s
metalLbIp: %s
`,
		cfg.ClusterType,
		cfg.CloudProvider,
		cfg.DNSProvider,
		cfg.CertManagerDNSProvider,
		cfg.TShirtSize,
		cfg.SecurityStrict,
		cfg.HAEnabled,
		cfg.Domain,
		cfg.Repo,
		repoOrg,
		repoName,
		cfg.GitUserName,
		cfg.MetallbIP,
	)

	if err := os.WriteFile("bootstrap/customer-config.yaml", []byte(customerConfig), 0644); err != nil {
		return fmt.Errorf("write customer-config.yaml: %w", err)
	}

	fmt.Println("the current customer-config is like this:")
	fmt.Println("----")
	fmt.Print(customerConfig)
	fmt.Println("----")

	fmt.Println("rendering values templates ...")
	if err := runGomplate("bootstrap/customer-config.yaml", "platform-apps", "platform-apps"); err != nil {
		return err
	}
	if err := runGomplate("bootstrap/customer-config.yaml", "backstage-resources", "backstage-resources"); err != nil {
		return err
	}

	if cfg.AppExclude != "" {
		fmt.Printf("exclude apps %s from platform-apps/target-chart/values-%s.yaml\n", cfg.AppExclude, cfg.TargetType)
		valuesFile := fmt.Sprintf("platform-apps/target-chart/values-%s.yaml", cfg.TargetType)
		// Build a yq expression to remove excluded apps from the applications list.
		expr := fmt.Sprintf(
			`((env(KUBRIX_APP_EXCLUDE) // "") | split(" ") | map(select(length>0))) as $ex | .applications |= map(. as $a | select(($ex | contains([$a.name])) | not))`,
		)
		cmd := exec.Command("yq", "e", expr, "-i", valuesFile)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		cmd.Env = append(os.Environ(), "KUBRIX_APP_EXCLUDE="+cfg.AppExclude)
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("yq exclude apps: %w", err)
		}
	}

	return nil
}

// PushToDownstream commits all changes and pushes to the customer repo.
func PushToDownstream(repo *gogit.Repository, cfg *kubrixcfg.Config) error {
	fmt.Printf("Push kubriX gitops files to %s\n", cfg.Repo)

	customerURL := cfg.RepoProto() + cfg.RepoPassword + "@" + cfg.RepoURL()
	if _, err := repo.CreateRemote(&config.RemoteConfig{
		Name: "customer",
		URLs: []string{customerURL},
	}); err != nil {
		return fmt.Errorf("add customer remote: %w", err)
	}

	wt, err := repo.Worktree()
	if err != nil {
		return err
	}
	if err := wt.AddWithOptions(&gogit.AddOptions{All: true}); err != nil {
		return fmt.Errorf("git add -A: %w", err)
	}

	if _, err := wt.Commit("add customer specific modifications during bootstrap", &gogit.CommitOptions{}); err != nil {
		return fmt.Errorf("git commit: %w", err)
	}

	pushAuth := &githttp.BasicAuth{
		Username: cfg.RepoUsername,
		Password: cfg.RepoPassword,
	}
	srcBranch := cfg.UpstreamBranch
	if !cfg.BootstrapKeepHistory {
		srcBranch = "publish"
	}
	refSpec := config.RefSpec(fmt.Sprintf("refs/heads/%s:refs/heads/main", srcBranch))
	pushOpts := &gogit.PushOptions{
		RemoteName: "customer",
		RefSpecs:   []config.RefSpec{refSpec},
		Auth:       pushAuth,
		Progress:   os.Stdout,
	}
	if err := repo.Push(pushOpts); err != nil {
		return fmt.Errorf("push to customer: %w", err)
	}
	return nil
}

// ParseAppsFromValuesFile reads a Helm values YAML and returns the list of app
// names found under `applications[*].name`, each prefixed with "sx-".
func ParseAppsFromValuesFile(valuesFile string) ([]string, error) {
	content, err := os.ReadFile(valuesFile)
	if err != nil {
		return nil, fmt.Errorf("read values file %s: %w", valuesFile, err)
	}

	var apps []string
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "- name:") {
			name := strings.TrimSpace(strings.TrimPrefix(trimmed, "- name:"))
			if name != "" {
				apps = append(apps, "sx-"+name)
			}
		}
	}
	return apps, nil
}

// PatchAndApplyBootstrapApp reads bootstrap-app-<targetType>.yaml, substitutes
// the repo URL and branch, then pipes the result through kubectl apply.
func PatchAndApplyBootstrapApp(targetType, repo, branch string) error {
	file := fmt.Sprintf("bootstrap-app-%s.yaml", targetType)
	content, err := os.ReadFile(file)
	if err != nil {
		return fmt.Errorf("read %s: %w", file, err)
	}

	var patched []string
	for _, line := range strings.Split(string(content), "\n") {
		stripped := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(stripped, "targetRevision:"):
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			line = indent + "targetRevision: " + branch
		case strings.HasPrefix(stripped, "repoURL:"):
			indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
			line = indent + "repoURL: " + repo
		}
		patched = append(patched, line)
	}

	cmd := exec.Command("kubectl", "apply", "-n", "argocd", "-f", "-")
	cmd.Stdin = strings.NewReader(strings.Join(patched, "\n"))
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func runGomplate(contextFile, inputDir, outputDir string) error {
	outputMap := filepath.Join(outputDir, "{{ .in | strings.ReplaceAll \".yaml.tmpl\" \".yaml\" }}")
	cmd := exec.Command("gomplate",
		"--context", "kubriX="+contextFile,
		"--input-dir", inputDir,
		"--include", "*.yaml.tmpl",
		"--output-map", outputMap,
	)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func mustGetwd() string {
	wd, _ := os.Getwd()
	return wd
}
