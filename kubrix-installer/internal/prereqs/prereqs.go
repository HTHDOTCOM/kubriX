package prereqs

import (
	"fmt"
	"os/exec"
	"strings"
)

// CheckTool verifies a named tool is reachable and prints its version string.
func CheckTool(name string, args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("prereq check failed: %s not found (%w)", name, err)
	}
	// Print only the first line of the version output.
	version := strings.SplitN(strings.TrimSpace(string(out)), "\n", 2)[0]
	fmt.Printf("%s found with version '%s'\n", name, version)
	return nil
}

// CheckAll verifies every tool the installer depends on.
// Pass needsGomplate=true when the bootstrap path is active.
func CheckAll(needsGomplate bool) error {
	type tool struct {
		name string
		args []string
	}

	tools := []tool{
		{"yq", []string{"yq", "--version"}},
		{"jq", []string{"jq", "--version"}},
		{"kubectl", []string{"kubectl", "version", "--client=true"}},
		{"helm", []string{"helm", "version"}},
		{"curl", []string{"curl", "-V"}},
		{"k8sgpt", []string{"k8sgpt", "version"}},
	}

	if needsGomplate {
		tools = append([]tool{{"gomplate", []string{"gomplate", "-v"}}}, tools...)
	}

	for _, t := range tools {
		if err := CheckTool(t.name, t.args...); err != nil {
			return err
		}
	}
	return nil
}
