package awconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/internal/pathpreflight"
)

const IdentityHomeEnv = "AWEB_IDENTITY_HOME"

type IdentityHomeSource string

const (
	IdentityHomeDefault IdentityHomeSource = "default"
	IdentityHomeEnvVar  IdentityHomeSource = "environment"
	IdentityHomeFlag    IdentityHomeSource = "flag"
)

type IdentityHome struct {
	Root   string
	Source IdentityHomeSource
}

func (h IdentityHome) External() bool {
	return h.Source == IdentityHomeFlag || h.Source == IdentityHomeEnvVar
}

func ResolveIdentityHome(workingDir, explicit string) (IdentityHome, error) {
	workingDir = strings.TrimSpace(workingDir)
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return IdentityHome{}, err
		}
		workingDir = wd
	}
	canonicalWorkingDir, err := filepath.Abs(workingDir)
	if err != nil {
		return IdentityHome{}, fmt.Errorf("canonicalize working directory: %w", err)
	}
	if evaluated, evalErr := filepath.EvalSymlinks(canonicalWorkingDir); evalErr == nil {
		canonicalWorkingDir = evaluated
	}

	source := IdentityHomeDefault
	root := filepath.Join(canonicalWorkingDir, ".aw")
	if value := strings.TrimSpace(os.Getenv(IdentityHomeEnv)); value != "" {
		source = IdentityHomeEnvVar
		root = value
	}
	if value := strings.TrimSpace(explicit); value != "" {
		source = IdentityHomeFlag
		root = value
	}
	if !filepath.IsAbs(root) {
		return IdentityHome{}, fmt.Errorf("%s must be an absolute path", identityHomeSourceName(source))
	}
	root = filepath.Clean(root)
	if source != IdentityHomeDefault {
		if err := pathpreflight.PreflightDir(root, "identity home", pathpreflight.Options{}); err != nil {
			return IdentityHome{}, err
		}
	}
	return IdentityHome{Root: root, Source: source}, nil
}

func identityHomeSourceName(source IdentityHomeSource) string {
	switch source {
	case IdentityHomeFlag:
		return "--identity-home"
	case IdentityHomeEnvVar:
		return IdentityHomeEnv
	default:
		return "identity home"
	}
}

func preflightIdentityFile(path, label string) error {
	return pathpreflight.PreflightFile(path, label, pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func preflightIdentityDir(path, label string) error {
	return pathpreflight.PreflightDir(path, label, pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func WorktreeIdentityHome(worktreeDir string) string {
	return filepath.Join(filepath.Clean(worktreeDir), ".aw")
}

func WorktreeIdentityPath(worktreeDir string) string {
	return filepath.Join(WorktreeIdentityHome(worktreeDir), "identity.yaml")
}

func WorktreeWorkspacePath(worktreeDir string) string {
	return filepath.Join(WorktreeIdentityHome(worktreeDir), "workspace.yaml")
}

func WorktreeContextPath(worktreeDir string) string {
	return filepath.Join(WorktreeIdentityHome(worktreeDir), "context")
}

func WorktreeStoredIdentityPath(worktreeDir, storedPath string) (string, error) {
	return IdentityHomeStoredPath(IdentityHome{Root: WorktreeIdentityHome(worktreeDir)}, storedPath)
}

func IdentityHomeStoredPath(home IdentityHome, storedPath string) (string, error) {
	storedPath = strings.TrimSpace(storedPath)
	storedPath = strings.TrimPrefix(storedPath, ".aw/")
	return IdentityHomePath(home, storedPath)
}

func IdentityHomePath(home IdentityHome, relativePath string) (string, error) {
	relativePath = filepath.FromSlash(strings.TrimSpace(relativePath))
	if relativePath == "" || filepath.IsAbs(relativePath) || strings.Contains(relativePath, "\\") {
		return "", fmt.Errorf("identity path must be a relative forward-slash path: %q", relativePath)
	}
	clean := filepath.Clean(relativePath)
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("identity path escapes identity home: %q", relativePath)
	}
	path := filepath.Join(home.Root, clean)
	options := pathpreflight.Options{}
	if home.Source == "" || home.Source == IdentityHomeDefault {
		options = pathpreflight.AllowTempAmbientSymlinkPrefix()
	}
	if err := pathpreflight.PreflightFile(path, "identity file", options); err != nil {
		return "", err
	}
	return path, nil
}
