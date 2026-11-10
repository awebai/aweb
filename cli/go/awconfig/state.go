package awconfig

import (
	"os"
	"path/filepath"

	"github.com/awebai/aw/internal/atomicfile"
)

func DefaultUserStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "aw"), nil
}

func DefaultAWIDStateDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".awid"), nil
}

func PathInUserState(elem ...string) (string, error) {
	root, err := DefaultUserStateDir()
	if err != nil {
		return "", err
	}
	parts := append([]string{root}, elem...)
	return filepath.Join(parts...), nil
}

func PathInAWIDState(elem ...string) (string, error) {
	root, err := DefaultAWIDStateDir()
	if err != nil {
		return "", err
	}
	parts := append([]string{root}, elem...)
	return filepath.Join(parts...), nil
}

func DefaultKnownAgentsPath() (string, error) {
	return PathInUserState("known_agents.yaml")
}

func DefaultRunConfigPath() (string, error) {
	return PathInUserState("run.json")
}

func DefaultLogsDir() (string, error) {
	return PathInUserState("logs")
}

func DefaultControllersDir() (string, error) {
	return PathInAWIDState("controllers")
}

func LegacyControllersDir() (string, error) {
	return PathInUserState("controllers")
}

// atomicWriteFile writes data to path using temp-file-and-rename
// with 0600 permissions (suitable for secrets).
func atomicWriteFile(path string, data []byte) error {
	return atomicWriteFileMode(path, data, 0o600)
}

// atomicWriteFileMode writes data to path using temp-file-and-rename,
// creating a missing directory with 0700 permissions.
// The temp file is chmod'd to mode before any data is written.
func atomicWriteFileMode(path string, data []byte, mode os.FileMode) error {
	return atomicfile.Options{Mode: mode, ParentMode: 0o700}.Write(path, data)
}
