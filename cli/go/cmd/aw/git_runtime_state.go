package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

const awebRuntimeExcludePattern = ".aw/"

func ensureAwebRuntimeGitIgnored(workingDir string) error {
	root, err := currentGitWorktreeRootFromDir(workingDir)
	if err != nil {
		return nil
	}
	excludePath, err := gitPath(root, "info/exclude")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(excludePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read git exclude %s: %w", excludePath, err)
	}
	if hasAwebRuntimeExclude(data) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(excludePath), 0o755); err != nil {
		return fmt.Errorf("create git exclude dir: %w", err)
	}
	var addition string
	if len(data) > 0 && !bytes.HasSuffix(data, []byte("\n")) {
		addition += "\n"
	}
	addition += "\n# aweb local runtime state\n" + awebRuntimeExcludePattern + "\n"
	if err := appendFile(excludePath, []byte(addition), 0o644); err != nil {
		return fmt.Errorf("update git exclude %s: %w", excludePath, err)
	}
	return nil
}

func hasAwebRuntimeExclude(data []byte) bool {
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == awebRuntimeExcludePattern || trimmed == "/.aw/" || trimmed == ".aw" || trimmed == "/.aw" {
			return true
		}
	}
	return false
}

func ensureAwebRuntimeUntrackedForAddWorktree(root string) error {
	paths, err := trackedAwebRuntimePaths(root)
	if err != nil {
		return err
	}
	if len(paths) == 0 {
		return nil
	}
	var sb strings.Builder
	sb.WriteString("cannot create a new worktree because aweb runtime files are tracked in this git repo:\n")
	for _, path := range paths {
		sb.WriteString("  ")
		sb.WriteString(path)
		sb.WriteString("\n")
	}
	sb.WriteString("\n")
	sb.WriteString("These files are local private per-worktree state. Tracking them makes new worktrees inherit the parent signing key, team certificates, and workspace binding.\n\n")
	sb.WriteString("To fix this repo safely while keeping the local .aw files on disk:\n")
	sb.WriteString("  printf '\\n.aw/\\n' >> .gitignore\n")
	sb.WriteString("  git rm --cached -r .aw\n")
	sb.WriteString("  git add .gitignore\n")
	sb.WriteString("  git commit -m \"Untrack aweb runtime state\"\n\n")
	sb.WriteString("Then re-run `aw workspace add-worktree`.")
	return usageError("%s", sb.String())
}

func trackedAwebRuntimePaths(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "--", ".aw")
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list tracked aweb runtime files: %w", err)
	}
	var paths []string
	for _, raw := range bytes.Split(out, []byte{0}) {
		path := strings.TrimSpace(string(raw))
		if path == "" {
			continue
		}
		if path == ".aw" || strings.HasPrefix(path, ".aw/") {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return paths, nil
}

func gitPath(root, path string) (string, error) {
	cmd := exec.Command("git", "-C", root, "rev-parse", "--git-path", path)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("resolve git path %s: %w", path, err)
	}
	resolved := strings.TrimSpace(string(out))
	if resolved == "" {
		return "", fmt.Errorf("git returned empty path for %s", path)
	}
	if filepath.IsAbs(resolved) {
		return resolved, nil
	}
	return filepath.Join(root, resolved), nil
}

func appendFile(path string, data []byte, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(data); err != nil {
		return err
	}
	return nil
}
