package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all KUBRIX_* environment variables used by the installer.
type Config struct {
	Repo                 string
	RepoBranch           string
	RepoUsername         string
	RepoPassword         string
	BackstageGithubToken string
	TargetType           string
	ClusterType          string
	BootstrapMaxWaitTime int
	Installer            bool
	GenerateSecrets      bool
	GitUserName          string
	MetallbIP            string
	Bootstrap            bool
	AppExclude           string
	InstallDebug         bool

	// populated only when Bootstrap=true
	BootstrapKeepHistory   bool
	UpstreamRepo           string
	UpstreamBranch         string
	UpstreamRepoUsername   string
	UpstreamRepoPassword   string
	Domain                 string
	DNSProvider            string
	CloudProvider          string
	TShirtSize             string
	SecurityStrict         bool
	HAEnabled              bool
	CertManagerDNSProvider string
}

// checkVar reads an env var, applies a default if empty, validates against an
// optional pipe-separated allowed list, and prints what was resolved.
func checkVar(name string, secret bool, def string, allowed string) (string, error) {
	val := os.Getenv(name)
	if val == "" {
		if def != "" {
			val = def
			if secret {
				fmt.Printf("set %s to sane default. Value is a secret.\n", name)
			} else {
				fmt.Printf("set %s to sane default '%s'\n", name, val)
			}
		} else {
			return "", fmt.Errorf("prereq check failed: variable '%s' is blank or not set", name)
		}
	}

	if allowed != "" {
		valid := false
		for _, a := range strings.Split(allowed, "|") {
			if val == a {
				valid = true
				break
			}
		}
		if !valid {
			return "", fmt.Errorf("prereq check failed: variable '%s' has invalid value '%s'. Valid values: %s",
				name, val, strings.ReplaceAll(allowed, "|", ", "))
		}
	}

	if secret {
		fmt.Printf("%s is set. Value is a secret.\n", name)
	} else {
		fmt.Printf("%s is set to '%s'\n", name, val)
	}
	return val, nil
}

func checkBool(name, def string) (bool, error) {
	v, err := checkVar(name, false, def, "true|false")
	if err != nil {
		return false, err
	}
	return v == "true", nil
}

func checkInt(name, def string) (int, error) {
	v, err := checkVar(name, false, def, "")
	if err != nil {
		return 0, err
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("variable '%s': expected integer, got '%s'", name, v)
	}
	return n, nil
}

func sha256Short(s string) string {
	h := sha256.Sum256([]byte(s))
	return fmt.Sprintf("%x", h)[:10]
}

// Load reads and validates all required KUBRIX_* environment variables.
func Load() (*Config, error) {
	c := &Config{}
	var err error

	fmt.Println()
	fmt.Println("Checking prereqs ...")

	if c.Repo, err = checkVar("KUBRIX_REPO", false, "", ""); err != nil {
		return nil, err
	}
	if c.RepoBranch, err = checkVar("KUBRIX_REPO_BRANCH", false, "main", ""); err != nil {
		return nil, err
	}
	if c.RepoUsername, err = checkVar("KUBRIX_REPO_USERNAME", false, "dummy", ""); err != nil {
		return nil, err
	}
	if c.RepoPassword, err = checkVar("KUBRIX_REPO_PASSWORD", true, "", ""); err != nil {
		return nil, err
	}

	// BackstageGithubToken defaults to RepoPassword when unset.
	if tok := os.Getenv("KUBRIX_BACKSTAGE_GITHUB_TOKEN"); tok != "" {
		fmt.Println("KUBRIX_BACKSTAGE_GITHUB_TOKEN is set. Value is a secret.")
		c.BackstageGithubToken = tok
	} else {
		fmt.Println("set KUBRIX_BACKSTAGE_GITHUB_TOKEN to sane default. Value is a secret.")
		c.BackstageGithubToken = c.RepoPassword
	}

	if c.TargetType, err = checkVar("KUBRIX_TARGET_TYPE", false, "kubrix-oss-stack", ""); err != nil {
		return nil, err
	}
	if c.ClusterType, err = checkVar("KUBRIX_CLUSTER_TYPE", false, "k8s", ""); err != nil {
		return nil, err
	}
	if c.BootstrapMaxWaitTime, err = checkInt("KUBRIX_BOOTSTRAP_MAX_WAIT_TIME", "2400"); err != nil {
		return nil, err
	}
	if c.Installer, err = checkBool("KUBRIX_INSTALLER", "false"); err != nil {
		return nil, err
	}
	if c.GenerateSecrets, err = checkBool("KUBRIX_GENERATE_SECRETS", "true"); err != nil {
		return nil, err
	}
	if c.GitUserName, err = checkVar("KUBRIX_GIT_USER_NAME", false, "dummy", ""); err != nil {
		return nil, err
	}
	if c.MetallbIP, err = checkVar("KUBRIX_METALLB_IP", false, " ", ""); err != nil {
		return nil, err
	}
	if c.Bootstrap, err = checkBool("KUBRIX_BOOTSTRAP", "false"); err != nil {
		return nil, err
	}

	if c.Bootstrap {
		if err = c.loadBootstrapVars(); err != nil {
			return nil, err
		}
	}

	c.AppExclude = os.Getenv("KUBRIX_APP_EXCLUDE")
	c.InstallDebug = os.Getenv("KUBRIX_INSTALL_DEBUG") == "true"

	fmt.Println("Prereq checks finished successfully.")
	fmt.Println()
	return c, nil
}

func (c *Config) loadBootstrapVars() error {
	var err error

	if c.BootstrapKeepHistory, err = checkBool("KUBRIX_BOOTSTRAP_KEEP_HISTORY", "true"); err != nil {
		return err
	}
	if c.UpstreamRepo, err = checkVar("KUBRIX_UPSTREAM_REPO", false, "https://github.com/suxess-it/kubriX", ""); err != nil {
		return err
	}
	if c.UpstreamBranch, err = checkVar("KUBRIX_UPSTREAM_BRANCH", false, "main", ""); err != nil {
		return err
	}
	if c.UpstreamRepoUsername, err = checkVar("KUBRIX_UPSTREAM_REPO_USERNAME", false, "dummy", ""); err != nil {
		return err
	}
	if c.UpstreamRepoPassword, err = checkVar("KUBRIX_UPSTREAM_REPO_PASSWORD", true, " ", ""); err != nil {
		return err
	}

	// Domain defaults to a deterministic hash of the repo URL.
	if d := os.Getenv("KUBRIX_DOMAIN"); d != "" {
		fmt.Printf("KUBRIX_DOMAIN is set to '%s'\n", d)
		c.Domain = d
	} else {
		c.Domain = fmt.Sprintf("demo-%s.kubrix.cloud", sha256Short(c.Repo))
		fmt.Printf("set KUBRIX_DOMAIN to sane default '%s'\n", c.Domain)
	}

	if c.DNSProvider, err = checkVar("KUBRIX_DNS_PROVIDER", false, "ionos", "none|aws|azure|cloudflare|ionos|stackit"); err != nil {
		return err
	}
	if c.CloudProvider, err = checkVar("KUBRIX_CLOUD_PROVIDER", false, "on-prem", "on-prem|aks|peak|metalstack"); err != nil {
		return err
	}
	if c.TShirtSize, err = checkVar("KUBRIX_TSHIRT_SIZE", false, "small", ""); err != nil {
		return err
	}
	if c.SecurityStrict, err = checkBool("KUBRIX_SECURITY_STRICT", "false"); err != nil {
		return err
	}
	if c.HAEnabled, err = checkBool("KUBRIX_HA_ENABLED", "false"); err != nil {
		return err
	}
	if c.CertManagerDNSProvider, err = checkVar("KUBRIX_CERT_MANAGER_DNS_PROVIDER", false, "none", "none|aws"); err != nil {
		return err
	}
	return nil
}

// RepoProto returns the URL scheme (e.g. "https://") extracted from Repo.
func (c *Config) RepoProto() string {
	if idx := strings.Index(c.Repo, "://"); idx != -1 {
		return c.Repo[:idx+3]
	}
	return ""
}

// RepoURL returns Repo with the protocol prefix stripped.
func (c *Config) RepoURL() string {
	proto := c.RepoProto()
	return strings.TrimPrefix(c.Repo, proto)
}

// UpstreamRepoProto returns the URL scheme for the upstream repo.
func (c *Config) UpstreamRepoProto() string {
	if idx := strings.Index(c.UpstreamRepo, "://"); idx != -1 {
		return c.UpstreamRepo[:idx+3]
	}
	return ""
}

// UpstreamRepoURL returns UpstreamRepo with the protocol prefix stripped.
func (c *Config) UpstreamRepoURL() string {
	proto := c.UpstreamRepoProto()
	return strings.TrimPrefix(c.UpstreamRepo, proto)
}

// ExcludeApps filters apps by removing entries whose name (without the "sx-"
// prefix) appears in the space-separated AppExclude list.
func ExcludeApps(apps []string, excludeList string) []string {
	if excludeList == "" {
		return apps
	}
	excluded := strings.Fields(excludeList)
	filtered := make([]string, 0, len(apps))
	for _, app := range apps {
		skip := false
		for _, ex := range excluded {
			if app == "sx-"+ex {
				skip = true
				break
			}
		}
		if !skip {
			filtered = append(filtered, app)
		}
	}
	return filtered
}
