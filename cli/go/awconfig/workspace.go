package awconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeWorkspace struct {
	AwebURL         string `yaml:"aweb_url,omitempty"`
	TeamID          string `yaml:"team_id,omitempty"`
	WorkspaceID     string `yaml:"workspace_id"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	AgentType       string `yaml:"agent_type,omitempty"`
	RoleName        string `yaml:"role_name,omitempty"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
}

type worktreeWorkspaceYAML struct {
	AwebURL         string `yaml:"aweb_url,omitempty"`
	TeamID          string `yaml:"team_id,omitempty"`
	WorkspaceID     string `yaml:"workspace_id"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	AgentType       string `yaml:"agent_type,omitempty"`
	RoleName        string `yaml:"role_name,omitempty"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
}

const legacyWorkspaceFormatError = "workspace.yaml uses removed server_url. Run `aw init` to reinitialize this worktree."
const legacyWorkspaceAPIKeyError = "workspace.yaml uses removed api_key auth. Run `aw init` to reinitialize this worktree with team certificate auth."
const legacyWorkspaceTeamAddressError = "workspace.yaml uses removed team_address. team_address was renamed to team_id with colon-form value; run `aw init` to regenerate this worktree."
const legacyWorkspaceRemovedFieldsErrorPrefix = "workspace.yaml uses removed fields"
const workspaceUnsupportedFieldsErrorPrefix = "workspace.yaml contains unsupported fields"

var canonicalWorkspaceYAMLKeys = map[string]struct{}{
	"aweb_url":         {},
	"team_id":          {},
	"workspace_id":     {},
	"repo_id":          {},
	"canonical_origin": {},
	"alias":            {},
	"human_name":       {},
	"agent_type":       {},
	"role_name":        {},
	"hostname":         {},
	"workspace_path":   {},
	"updated_at":       {},
}

var removedWorkspaceYAMLKeys = map[string]struct{}{
	"awid_url":        {},
	"cloud_url":       {},
	"custody":         {},
	"did":             {},
	"identity_handle": {},
	"identity_id":     {},
	"lifetime":        {},
	"namespace_slug":  {},
	"project_id":      {},
	"project_slug":    {},
	"role":            {},
	"signing_key":     {},
	"stable_id":       {},
}

func (w *WorktreeWorkspace) syncURLFields() {
	if w == nil {
		return
	}
	w.AwebURL = strings.TrimSpace(w.AwebURL)
}

func (w *WorktreeWorkspace) normalize() {
	if w == nil {
		return
	}
	w.syncURLFields()
	w.TeamID = strings.TrimSpace(w.TeamID)
	w.WorkspaceID = strings.TrimSpace(w.WorkspaceID)
	w.RepoID = strings.TrimSpace(w.RepoID)
	w.CanonicalOrigin = strings.TrimSpace(w.CanonicalOrigin)
	w.Alias = strings.TrimSpace(w.Alias)
	w.HumanName = strings.TrimSpace(w.HumanName)
	w.AgentType = strings.TrimSpace(w.AgentType)
	w.RoleName = strings.TrimSpace(w.RoleName)
	w.Hostname = strings.TrimSpace(w.Hostname)
	w.WorkspacePath = strings.TrimSpace(w.WorkspacePath)
	w.UpdatedAt = strings.TrimSpace(w.UpdatedAt)
}

func (w *WorktreeWorkspace) HasBinding() bool {
	if w == nil {
		return false
	}
	return strings.TrimSpace(w.AwebURL) != "" && strings.TrimSpace(w.TeamID) != ""
}

func (w *WorktreeWorkspace) HasTeamBinding() bool {
	if w == nil {
		return false
	}
	return strings.TrimSpace(w.AwebURL) != "" && strings.TrimSpace(w.TeamID) != ""
}

func inspectWorkspaceYAMLKeys(value *yaml.Node) (bool, bool, bool, []string, []string) {
	if value == nil || value.Kind != yaml.MappingNode {
		return false, false, false, nil, nil
	}
	removed := make([]string, 0, 8)
	unsupported := make([]string, 0, 4)
	hasServerURL := false
	hasAPIKey := false
	hasLegacyTeamAddress := false
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := strings.TrimSpace(value.Content[i].Value)
		if key == "" {
			continue
		}
		if _, ok := canonicalWorkspaceYAMLKeys[key]; ok {
			continue
		}
		switch key {
		case "server_url":
			hasServerURL = true
		case "api_key":
			hasAPIKey = true
		case "team_address":
			hasLegacyTeamAddress = true
		default:
			if _, ok := removedWorkspaceYAMLKeys[key]; ok {
				removed = append(removed, key)
			} else {
				unsupported = append(unsupported, key)
			}
		}
	}
	sort.Strings(removed)
	sort.Strings(unsupported)
	return hasServerURL, hasAPIKey, hasLegacyTeamAddress, removed, unsupported
}

func (w *WorktreeWorkspace) UnmarshalYAML(value *yaml.Node) error {
	var raw worktreeWorkspaceYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}
	hasServerURL, hasAPIKey, hasLegacyTeamAddress, removed, unsupported := inspectWorkspaceYAMLKeys(value)
	if hasServerURL {
		return errors.New(legacyWorkspaceFormatError)
	}
	if hasAPIKey {
		return errors.New(legacyWorkspaceAPIKeyError)
	}
	if hasLegacyTeamAddress {
		return errors.New(legacyWorkspaceTeamAddressError)
	}
	if len(removed) > 0 {
		return fmt.Errorf("%s: %s. Run `aw init` to reinitialize this worktree.", legacyWorkspaceRemovedFieldsErrorPrefix, strings.Join(removed, ", "))
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("%s: %s. Remove them and keep only the canonical workspace binding keys.", workspaceUnsupportedFieldsErrorPrefix, strings.Join(unsupported, ", "))
	}

	*w = WorktreeWorkspace{
		AwebURL:         raw.AwebURL,
		TeamID:          raw.TeamID,
		WorkspaceID:     raw.WorkspaceID,
		RepoID:          raw.RepoID,
		CanonicalOrigin: raw.CanonicalOrigin,
		Alias:           raw.Alias,
		HumanName:       raw.HumanName,
		AgentType:       raw.AgentType,
		RoleName:        raw.RoleName,
		Hostname:        raw.Hostname,
		WorkspacePath:   raw.WorkspacePath,
		UpdatedAt:       raw.UpdatedAt,
	}
	w.normalize()
	return nil
}

func (w WorktreeWorkspace) MarshalYAML() (any, error) {
	w.normalize()
	return worktreeWorkspaceYAML{
		AwebURL:         w.AwebURL,
		TeamID:          w.TeamID,
		WorkspaceID:     w.WorkspaceID,
		RepoID:          w.RepoID,
		CanonicalOrigin: w.CanonicalOrigin,
		Alias:           w.Alias,
		HumanName:       w.HumanName,
		AgentType:       w.AgentType,
		RoleName:        w.RoleName,
		Hostname:        w.Hostname,
		WorkspacePath:   w.WorkspacePath,
		UpdatedAt:       w.UpdatedAt,
	}, nil
}

func DefaultWorktreeWorkspaceRelativePath() string {
	return filepath.Join(".aw", "workspace.yaml")
}

func FindWorktreeWorkspacePath(startDir string) (string, error) {
	p := filepath.Join(filepath.Clean(startDir), DefaultWorktreeWorkspaceRelativePath())
	if _, err := os.Stat(p); err == nil {
		return p, nil
	}
	return "", os.ErrNotExist
}

func LoadWorktreeWorkspaceFrom(path string) (*WorktreeWorkspace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func LoadWorktreeWorkspaceFromDir(startDir string) (*WorktreeWorkspace, string, error) {
	p, err := FindWorktreeWorkspacePath(startDir)
	if err != nil {
		return nil, "", err
	}
	state, err := LoadWorktreeWorkspaceFrom(p)
	if err != nil {
		return nil, "", err
	}
	return state, p, nil
}

func SaveWorktreeWorkspaceTo(path string, state *WorktreeWorkspace) error {
	if state == nil {
		return errors.New("nil workspace state")
	}
	state.normalize()

	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}

	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}

func WorktreeRootFromWorkspacePath(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	return filepath.Dir(filepath.Dir(filepath.Clean(path)))
}
