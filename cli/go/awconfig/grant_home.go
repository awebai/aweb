package awconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

const GrantHomeSchemaVersion = 1

// GrantSubject identifies the durable identity a session grant acts for.
type GrantSubject struct {
	DIDAW   string `yaml:"did_aw,omitempty"`
	DIDKey  string `yaml:"did_key,omitempty"`
	Address string `yaml:"address,omitempty"`
	Alias   string `yaml:"alias,omitempty"`
}

// GrantHome is the grant.yaml state of a self-contained grant home: a scoped,
// expiring, revocable session credential derived from a durable identity. A
// grant home carries only the session key; the subject's root keys never
// enter it.
type GrantHome struct {
	Version   int          `yaml:"version"`
	GrantID   string       `yaml:"grant_id"`
	TeamID    string       `yaml:"team_id"`
	Subject   GrantSubject `yaml:"subject"`
	Scopes    []string     `yaml:"scopes,omitempty"`
	ExpiresAt string       `yaml:"expires_at"`
	AwebURL   string       `yaml:"aweb_url"`
	MintedAt  string       `yaml:"minted_at,omitempty"`
}

func GrantHomeStatePath(root string) string {
	return filepath.Join(filepath.Clean(root), "grant.yaml")
}

func GrantHomeSigningKeyPath(root string) string {
	return filepath.Join(filepath.Clean(root), "grant-signing.key")
}

// IsGrantHome reports whether root is a grant home. Presence of grant.yaml is
// the discriminator: a grant home is a valid identity home even though it has
// no signing.key, identity.yaml, or workspace.yaml.
func IsGrantHome(root string) bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return false
	}
	info, err := os.Stat(GrantHomeStatePath(root))
	return err == nil && info.Mode().IsRegular()
}

func LoadGrantHome(root string) (*GrantHome, error) {
	path := GrantHomeStatePath(root)
	if err := preflightIdentityFile(path, "grant file"); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state GrantHome
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	if err := state.validate(); err != nil {
		return nil, fmt.Errorf("invalid grant home %s: %w", path, err)
	}
	return &state, nil
}

func SaveGrantHomeTo(path string, state *GrantHome) error {
	if err := preflightIdentityFile(path, "grant file"); err != nil {
		return err
	}
	if state == nil {
		return errors.New("nil grant state")
	}
	if err := state.validate(); err != nil {
		return err
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func (g *GrantHome) validate() error {
	if g == nil {
		return errors.New("nil grant state")
	}
	if g.Version != GrantHomeSchemaVersion {
		return fmt.Errorf("unsupported grant.yaml version %d (want %d)", g.Version, GrantHomeSchemaVersion)
	}
	if strings.TrimSpace(g.GrantID) == "" {
		return errors.New("grant.yaml is missing grant_id")
	}
	if strings.TrimSpace(g.TeamID) == "" {
		return errors.New("grant.yaml is missing team_id")
	}
	if strings.TrimSpace(g.AwebURL) == "" {
		return errors.New("grant.yaml is missing aweb_url")
	}
	if strings.TrimSpace(g.ExpiresAt) == "" {
		return errors.New("grant.yaml is missing expires_at")
	}
	return nil
}
