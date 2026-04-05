package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type ResolvedIdentity struct {
	WorkingDir     string
	IdentityPath   string
	SigningKeyPath string
	DID            string
	StableID       string
	Address        string
	Handle         string
	Domain         string
	Custody        string
	Lifetime       string
	RegistryURL    string
	RegistryStatus string
	CreatedAt      string
}

type WorktreeIdentity struct {
	DID            string `yaml:"did"`
	StableID       string `yaml:"stable_id"`
	Address        string `yaml:"address,omitempty"`
	Custody        string `yaml:"custody"`
	Lifetime       string `yaml:"lifetime"`
	RegistryURL    string `yaml:"registry_url,omitempty"`
	RegistryStatus string `yaml:"registry_status,omitempty"`
	CreatedAt      string `yaml:"created_at"`
}

func DefaultWorktreeIdentityRelativePath() string {
	return filepath.Join(".aw", "identity.yaml")
}

func DefaultWorktreeSigningKeyRelativePath() string {
	return filepath.Join(".aw", "signing.key")
}

func WorktreeSigningKeyPath(root string) string {
	return filepath.Join(filepath.Clean(root), DefaultWorktreeSigningKeyRelativePath())
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
	return filepath.Dir(filepath.Dir(filepath.Clean(path)))
}

func ResolveIdentity(workingDir string) (*ResolvedIdentity, error) {
	workingDir = strings.TrimSpace(workingDir)
	if workingDir == "" {
		wd, err := os.Getwd()
		if err != nil {
			return nil, err
		}
		workingDir = wd
	}

	identity, identityPath, err := LoadWorktreeIdentityFromDir(workingDir)
	if err != nil {
		return nil, err
	}
	root := WorktreeRootFromIdentityPath(identityPath)
	if strings.TrimSpace(root) == "" {
		root = workingDir
	}

	resolved := &ResolvedIdentity{
		WorkingDir:     root,
		IdentityPath:   identityPath,
		SigningKeyPath: WorktreeSigningKeyPath(root),
		DID:            strings.TrimSpace(identity.DID),
		StableID:       strings.TrimSpace(identity.StableID),
		Address:        strings.TrimSpace(identity.Address),
		Custody:        strings.TrimSpace(identity.Custody),
		Lifetime:       strings.TrimSpace(identity.Lifetime),
		RegistryURL:    strings.TrimSpace(identity.RegistryURL),
		RegistryStatus: strings.TrimSpace(identity.RegistryStatus),
		CreatedAt:      strings.TrimSpace(identity.CreatedAt),
	}
	if domain, handle, ok := cutResolvedIdentityAddress(resolved.Address); ok {
		resolved.Domain = domain
		resolved.Handle = handle
	} else if resolved.Address != "" {
		resolved.Handle = resolved.Address
	}
	return resolved, nil
}

func cutResolvedIdentityAddress(address string) (string, string, bool) {
	domain, handle, ok := strings.Cut(strings.TrimSpace(address), "/")
	if !ok || strings.TrimSpace(domain) == "" || strings.TrimSpace(handle) == "" {
		return "", "", false
	}
	return strings.TrimSpace(domain), strings.TrimSpace(handle), true
}
