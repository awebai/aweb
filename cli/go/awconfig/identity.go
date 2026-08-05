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
	WorkingDir           string
	IdentityHome         string
	ExternalIdentityHome bool
	IdentityPath         string
	SigningKeyPath       string
	DID                  string
	StableID             string
	Address              string
	Handle               string
	Domain               string
	Custody              string
	IdentityScope        string
	RegistryURL          string
	RegistryStatus       string
	CreatedAt            string
}

type WorktreeIdentity struct {
	SchemaVersion  int    `yaml:"schema_version,omitempty"`
	DID            string `yaml:"did"`
	StableID       string `yaml:"stable_id,omitempty"`
	Address        string `yaml:"address,omitempty"`
	Custody        string `yaml:"custody"`
	IdentityScope  string `yaml:"identity_scope,omitempty"`
	RegistryURL    string `yaml:"registry_url,omitempty"`
	RegistryStatus string `yaml:"registry_status,omitempty"`
	CreatedAt      string `yaml:"created_at"`
}

// worktreeIdentityWire is the pre-v2 identity.yaml decode boundary. Lifetime
// is intentionally absent from WorktreeIdentity so compatibility input is
// normalized to identity_scope before entering the canonical model.
type worktreeIdentityWire struct {
	SchemaVersion  int    `yaml:"schema_version,omitempty"`
	DID            string `yaml:"did"`
	StableID       string `yaml:"stable_id,omitempty"`
	Address        string `yaml:"address,omitempty"`
	Custody        string `yaml:"custody"`
	IdentityScope  string `yaml:"identity_scope,omitempty"`
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
	return filepath.Join(WorktreeIdentityHome(root), "signing.key")
}

func FindWorktreeIdentityPath(startDir string) (string, error) {
	p := WorktreeIdentityPath(startDir)
	if err := preflightIdentityFile(p, "identity file"); err != nil {
		return "", err
	}
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	return "", os.ErrNotExist
}

func LoadWorktreeIdentityFrom(path string) (*WorktreeIdentity, error) {
	if err := preflightIdentityFile(path, "identity file"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var wire worktreeIdentityWire
	if err := yaml.Unmarshal(data, &wire); err != nil {
		return nil, err
	}
	state := WorktreeIdentity{
		SchemaVersion:  wire.SchemaVersion,
		DID:            wire.DID,
		StableID:       wire.StableID,
		Address:        wire.Address,
		Custody:        wire.Custody,
		IdentityScope:  wire.IdentityScope,
		RegistryURL:    wire.RegistryURL,
		RegistryStatus: wire.RegistryStatus,
		CreatedAt:      wire.CreatedAt,
	}
	if err := normalizeWorktreeIdentityScope(&state, wire.Lifetime); err != nil {
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
	if err := preflightIdentityFile(path, "identity file"); err != nil {
		return err
	}
	if state == nil {
		return errors.New("nil identity state")
	}
	out := *state
	if err := normalizeWorktreeIdentityScope(&out, ""); err != nil {
		return err
	}
	if strings.TrimSpace(out.IdentityScope) == "" {
		return errors.New("identity_scope is required")
	}
	out.SchemaVersion = WorktreeIdentitySchemaVersion
	data, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func normalizeWorktreeIdentityScope(state *WorktreeIdentity, legacyLifetime string) error {
	if state == nil {
		return errors.New("nil identity state")
	}
	rawScope := strings.TrimSpace(state.IdentityScope)
	rawLifetime := strings.TrimSpace(legacyLifetime)
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
		compatScope := awid.IdentityScopeFromLegacyLifetime(rawLifetime)
		if compatScope != awid.IdentityModeLocal && compatScope != awid.IdentityModeGlobal {
			return fmt.Errorf("deprecated lifetime must be %q or %q", "ephemeral", "persistent")
		}
		if scope != "" && scope != compatScope {
			return fmt.Errorf("identity_scope %q conflicts with deprecated lifetime %q", rawScope, rawLifetime)
		}
		if scope == "" {
			scope = compatScope
		}
	}
	state.IdentityScope = scope
	return nil
}

func WorktreeRootFromIdentityPath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Dir(filepath.Dir(filepath.Clean(path)))
}

func ResolveIdentityFromHome(workingDir, identityHome string) (*ResolvedIdentity, error) {
	workingDir = strings.TrimSpace(workingDir)
	identityHome = filepath.Clean(strings.TrimSpace(identityHome))
	home := IdentityHome{Root: identityHome}
	identityPath, err := IdentityHomePath(home, "identity.yaml")
	if err != nil {
		return nil, err
	}
	signingKeyPath, err := IdentityHomePath(home, "signing.key")
	if err != nil {
		return nil, err
	}
	identity, err := LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		return nil, err
	}
	resolved, err := resolvedIdentityFromState(workingDir, identityHome, identityPath, signingKeyPath, identity)
	if err != nil {
		return nil, err
	}
	return resolved, nil
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

	return resolvedIdentityFromState(root, "", identityPath, WorktreeSigningKeyPath(root), identity)
}

func resolvedIdentityFromState(workingDir, identityHome, identityPath, signingKeyPath string, identity *WorktreeIdentity) (*ResolvedIdentity, error) {
	identityScope := strings.TrimSpace(identity.IdentityScope)
	resolved := &ResolvedIdentity{
		WorkingDir:     workingDir,
		IdentityHome:   identityHome,
		IdentityPath:   identityPath,
		SigningKeyPath: signingKeyPath,
		DID:            strings.TrimSpace(identity.DID),
		StableID:       strings.TrimSpace(identity.StableID),
		Address:        strings.TrimSpace(identity.Address),
		Custody:        strings.TrimSpace(identity.Custody),
		IdentityScope:  identityScope,
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
