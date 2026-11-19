package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// snapshotAwTree records the set of paths currently present under .aw so a
// later failure can remove exactly what the current run created. A nil map
// means .aw itself did not exist.
func snapshotAwTree(workingDir string, identityHomes ...string) (map[string]bool, error) {
	awDir := identityHomeForOperation(workingDir, identityHomes...)
	if _, err := os.Stat(awDir); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	existing := map[string]bool{}
	err := filepath.WalkDir(awDir, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		existing[path] = true
		return nil
	})
	if err != nil {
		return nil, err
	}
	return existing, nil
}

// rollbackAwTree removes every path under .aw that is not in the snapshot,
// preserving everything that existed before (including resumable
// partial-init state). If .aw did not exist at snapshot time and nothing of
// it remains, the directory itself is removed.
func rollbackAwTree(workingDir string, snapshot map[string]bool, identityHomes ...string) {
	awDir := identityHomeForOperation(workingDir, identityHomes...)
	if _, err := os.Stat(awDir); err != nil {
		return
	}
	var created []string
	_ = filepath.WalkDir(awDir, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if snapshot == nil || !snapshot[path] {
			created = append(created, path)
		}
		return nil
	})
	// Remove deepest paths first so directories empty out before removal.
	for i := len(created) - 1; i >= 0; i-- {
		if err := os.Remove(created[i]); err != nil && !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Warning: rollback could not remove %s: %v\n", created[i], err)
		}
	}
	if snapshot == nil {
		pruneEmptyAwDir(workingDir, identityHomes...)
	}
}

func identityHomeForOperation(workingDir string, identityHomes ...string) string {
	if len(identityHomes) > 0 && strings.TrimSpace(identityHomes[0]) != "" {
		return filepath.Clean(identityHomes[0])
	}
	return filepath.Join(filepath.Clean(workingDir), ".aw")
}

// pruneEmptyAwDir removes .aw when it exists and is empty.
func pruneEmptyAwDir(workingDir string, identityHomes ...string) {
	awDir := identityHomeForOperation(workingDir, identityHomes...)
	if entries, err := os.ReadDir(awDir); err == nil && len(entries) == 0 {
		_ = os.Remove(awDir)
	}
}
