package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeIdentity struct {
	DID       string `yaml:"did"`
	StableID  string `yaml:"stable_id"`
	Custody   string `yaml:"custody"`
	Lifetime  string `yaml:"lifetime"`
	CreatedAt string `yaml:"created_at"`
}

func DefaultWorktreeIdentityRelativePath() string {
	return filepath.Join(".aw", "identity.yaml")
}

func FindWorktreeIdentityPath(startDir string) (string, error) {
	p := filepath.Join(filepath.Clean(startDir), DefaultWorktreeIdentityRelativePath())
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	return "", os.ErrNotExist
}

func LoadWorktreeIdentityFrom(path string) (*WorktreeIdentity, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state WorktreeIdentity
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func LoadWorktreeIdentityFromDir(startDir string) (*WorktreeIdentity, string, error) {
	p, err := FindWorktreeIdentityPath(startDir)
	if err != nil {
		return nil, "", err
	}
	state, err := LoadWorktreeIdentityFrom(p)
	if err != nil {
		return nil, "", err
	}
	return state, p, nil
}

func SaveWorktreeIdentityTo(path string, state *WorktreeIdentity) error {
	if state == nil {
		return errors.New("nil identity state")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func WorktreeRootFromIdentityPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "identity.yaml" {
		return filepath.Dir(filepath.Dir(clean))
	}
	return filepath.Dir(filepath.Dir(clean))
}
