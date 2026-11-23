package main

import (
	"github.com/awebai/aw/awconfig"
	"os"
)

func ensureConnectTargetClean(workingDir string) error {
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return err
	}
	return ensureIdentityCreationTargetClean(awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(workingDir)})
}

// Identity creation never overwrites another principal (docs/cli-identity-selection.md:40-49).
func ensureIdentityCreationTargetClean(home awconfig.IdentityHome) error {
	for _, rel := range []string{"signing.key", "identity.yaml", "team-certs", "workspace.yaml", "grant.yaml"} {
		path, err := awconfig.IdentityHomePath(home, rel)
		if err != nil {
			return err
		}
		if _, err := os.Stat(path); err == nil {
			return usageError("refusing to overwrite existing %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
