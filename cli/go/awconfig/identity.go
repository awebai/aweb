package awconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

const WorktreeIdentitySchemaVersion = 2

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
	IdentityScope  string
	// Lifetime is a deprecated-read-compat mirror of IdentityScope. New identity
	// config writes identity_scope; keep this populated while downstream callers
	// migrate from persistent/ephemeral helpers.
	Lifetime       string
	RegistryURL    string
	RegistryStatus string
	CreatedAt      string
}

type WorktreeIdentity struct {
	SchemaVersion int    `yaml:"schema_version,omitempty"`
	DID           string `yaml:"did"`
	StableID      string `yaml:"stable_id,omitempty"`
	Address       string `yaml:"address,omitempty"`
	Custody       string `yaml:"custody"`
	IdentityScope string `yaml:"identity_scope,omitempty"`
	// Lifetime is deprecated-read-compat for pre-v2 identity.yaml files. Loaders
	// accept lifetime=persistent/ephemeral and normalize it to identity_scope;
	// writers intentionally omit lifetime.
	Lifetime       string `yaml:"lifetime,omitempty"`
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
	if err := normalizeWorktreeIdentityScope(&state); err != nil {
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
	out := *state
	if err := normalizeWorktreeIdentityScope(&out); err != nil {
		return err
	}
	if strings.TrimSpace(out.IdentityScope) == "" {
		return errors.New("identity_scope is required")
	}
	out.SchemaVersion = WorktreeIdentitySchemaVersion
	out.Lifetime = ""
	data, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func normalizeWorktreeIdentityScope(state *WorktreeIdentity) error {
	if state == nil {
		return errors.New("nil identity state")
	}
	rawScope := strings.TrimSpace(state.IdentityScope)
	rawLifetime := strings.TrimSpace(state.Lifetime)
	if rawScope == "" && rawLifetime == "" {
		return nil
	}
	scope := ""
	if rawScope != "" {
		scope = awid.NormalizeIdentityScope(rawScope)
		if scope != awid.IdentityModeLocal && scope != awid.IdentityModeGlobal {
			return fmt.Errorf("identity_scope must be %q or %q", awid.IdentityModeLocal, awid.IdentityModeGlobal)
		}
	}
	if rawLifetime != "" {
		legacyLifetime := awid.NormalizeLifetime(rawLifetime)
		if legacyLifetime != awid.LifetimeEphemeral && legacyLifetime != awid.LifetimePersistent {
			return fmt.Errorf("deprecated lifetime must be %q or %q", awid.LifetimeEphemeral, awid.LifetimePersistent)
		}
		compatScope := awid.NormalizeIdentityScope(legacyLifetime)
		if scope != "" && scope != compatScope {
			return fmt.Errorf("identity_scope %q conflicts with deprecated lifetime %q", rawScope, rawLifetime)
		}
		if scope == "" {
			scope = compatScope
		}
	}
	state.IdentityScope = scope
	state.Lifetime = awid.LegacyLifetimeForIdentityScope(scope)
	return nil
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

	identityScope := strings.TrimSpace(identity.IdentityScope)
	resolved := &ResolvedIdentity{
		WorkingDir:     root,
		IdentityPath:   identityPath,
		SigningKeyPath: WorktreeSigningKeyPath(root),
		DID:            strings.TrimSpace(identity.DID),
		StableID:       strings.TrimSpace(identity.StableID),
		Address:        strings.TrimSpace(identity.Address),
		Custody:        strings.TrimSpace(identity.Custody),
		IdentityScope:  identityScope,
		Lifetime:       strings.TrimSpace(identity.Lifetime),
		RegistryURL:    strings.TrimSpace(identity.RegistryURL),
		RegistryStatus: strings.TrimSpace(identity.RegistryStatus),
		CreatedAt:      strings.TrimSpace(identity.CreatedAt),
	}
	if domain, handle, ok := CutIdentityAddress(resolved.Address); ok {
		resolved.Domain = domain
		resolved.Handle = handle
	} else if resolved.Address != "" {
		resolved.Handle = resolved.Address
	}
	return resolved, nil
}

func CutIdentityAddress(address string) (string, string, bool) {
	domain, handle, ok := strings.Cut(strings.TrimSpace(address), "/")
	if !ok || strings.TrimSpace(domain) == "" || strings.TrimSpace(handle) == "" {
		return "", "", false
	}
	return strings.TrimSpace(domain), strings.TrimSpace(handle), true
}
