package run

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func detectWorktreeGitDir(workDir string) (string, error) {
	root := strings.TrimSpace(workDir)
	if root == "" {
		return "", nil
	}

	gitPath := filepath.Join(root, ".git")
	info, err := os.Stat(gitPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", fmt.Errorf("stat %s: %w", gitPath, err)
	}
	if info.IsDir() {
		return "", nil
	}

	content, err := os.ReadFile(gitPath)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", gitPath, err)
	}

	line := strings.TrimSpace(string(content))
	const prefix = "gitdir:"
	if !strings.HasPrefix(line, prefix) {
		return "", fmt.Errorf("parse %s: missing gitdir prefix", gitPath)
	}

	gitDir := strings.TrimSpace(line[len(prefix):])
	if gitDir == "" {
		return "", fmt.Errorf("parse %s: missing gitdir path", gitPath)
	}
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(root, gitDir)
	}

	return filepath.Clean(gitDir), nil
}
