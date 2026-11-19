package main

import (
	"github.com/awebai/aw/awconfig"
	"os"
)

func ensureConnectTargetClean(workingDir string) error {
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return err
	}
	paths := []string{
		awconfig.WorktreeSigningKeyPath(workingDir),
		awconfig.WorktreeIdentityPath(workingDir),
		awconfig.TeamCertificatesDir(workingDir),
		awconfig.WorktreeWorkspacePath(workingDir),
	}
	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return usageError("refusing to overwrite existing %s", path)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}
