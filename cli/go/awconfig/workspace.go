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

type WorktreeMembership struct {
	TeamID      string `yaml:"team_id"`
	Alias       string `yaml:"alias,omitempty"`
	RoleName    string `yaml:"role_name,omitempty"`
	WorkspaceID string `yaml:"workspace_id,omitempty"`
	CertPath    string `yaml:"cert_path"`
	JoinedAt    string `yaml:"joined_at,omitempty"`
}

type WorktreeWorkspace struct {
	AwebURL         string               `yaml:"aweb_url,omitempty"`
	APIKey          string               `yaml:"api_key,omitempty"`
	ActiveTeam      string               `yaml:"active_team,omitempty"`
	Memberships     []WorktreeMembership `yaml:"memberships,omitempty"`
	HumanName       string               `yaml:"human_name,omitempty"`
	AgentType       string               `yaml:"agent_type,omitempty"`
	RepoID          string               `yaml:"repo_id,omitempty"`
	CanonicalOrigin string               `yaml:"canonical_origin,omitempty"`
	Hostname        string               `yaml:"hostname,omitempty"`
	WorkspacePath   string               `yaml:"workspace_path,omitempty"`
	UpdatedAt       string               `yaml:"updated_at,omitempty"`
}

type worktreeMembershipYAML struct {
	TeamID      string `yaml:"team_id"`
	Alias       string `yaml:"alias,omitempty"`
	RoleName    string `yaml:"role_name,omitempty"`
	WorkspaceID string `yaml:"workspace_id,omitempty"`
	CertPath    string `yaml:"cert_path"`
	JoinedAt    string `yaml:"joined_at,omitempty"`
}

type worktreeWorkspaceYAML struct {
	AwebURL         string                   `yaml:"aweb_url,omitempty"`
	APIKey          string                   `yaml:"api_key,omitempty"`
	ActiveTeam      string                   `yaml:"active_team,omitempty"`
	Memberships     []worktreeMembershipYAML `yaml:"memberships,omitempty"`
	HumanName       string                   `yaml:"human_name,omitempty"`
	AgentType       string                   `yaml:"agent_type,omitempty"`
	RepoID          string                   `yaml:"repo_id,omitempty"`
	CanonicalOrigin string                   `yaml:"canonical_origin,omitempty"`
	Hostname        string                   `yaml:"hostname,omitempty"`
	WorkspacePath   string                   `yaml:"workspace_path,omitempty"`
	UpdatedAt       string                   `yaml:"updated_at,omitempty"`
}

type LegacySingleTeamWorkspace struct {
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
const legacyWorkspaceTeamAddressError = "workspace.yaml uses removed team_address. team_address was renamed to team_id with colon-form value; run `aw init` to regenerate this worktree."
const legacyWorkspaceSingleTeamError = "workspace.yaml uses single-team shape. Run `aw workspace migrate-multi-team`."
const legacyWorkspaceRemovedFieldsErrorPrefix = "workspace.yaml uses removed fields"
const workspaceUnsupportedFieldsErrorPrefix = "workspace.yaml contains unsupported fields"

var canonicalWorkspaceYAMLKeys = map[string]struct{}{
	"aweb_url":         {},
	"api_key":          {},
	"active_team":      {},
	"memberships":      {},
	"human_name":       {},
	"agent_type":       {},
	"repo_id":          {},
	"canonical_origin": {},
	"hostname":         {},
	"workspace_path":   {},
	"updated_at":       {},
}

var canonicalMembershipYAMLKeys = map[string]struct{}{
	"team_id":      {},
	"alias":        {},
	"role_name":    {},
	"workspace_id": {},
	"cert_path":    {},
	"joined_at":    {},
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

func (m *WorktreeMembership) normalize() {
	if m == nil {
		return
	}
	m.TeamID = strings.TrimSpace(m.TeamID)
	m.Alias = strings.TrimSpace(m.Alias)
	m.RoleName = strings.TrimSpace(m.RoleName)
	m.WorkspaceID = strings.TrimSpace(m.WorkspaceID)
	m.CertPath = filepath.ToSlash(strings.TrimSpace(m.CertPath))
	m.JoinedAt = strings.TrimSpace(m.JoinedAt)
}

func (w *WorktreeWorkspace) syncURLFields() {
	if w == nil {
		return
	}
	w.AwebURL = strings.TrimSpace(w.AwebURL)
	w.APIKey = strings.TrimSpace(w.APIKey)
}

func (w *WorktreeWorkspace) normalize() {
	if w == nil {
		return
	}
	w.syncURLFields()
	w.ActiveTeam = strings.TrimSpace(w.ActiveTeam)
	w.HumanName = strings.TrimSpace(w.HumanName)
	w.AgentType = strings.TrimSpace(w.AgentType)
	w.RepoID = strings.TrimSpace(w.RepoID)
	w.CanonicalOrigin = strings.TrimSpace(w.CanonicalOrigin)
	w.Hostname = strings.TrimSpace(w.Hostname)
	w.WorkspacePath = strings.TrimSpace(w.WorkspacePath)
	w.UpdatedAt = strings.TrimSpace(w.UpdatedAt)
	normalized := make([]WorktreeMembership, 0, len(w.Memberships))
	for _, membership := range w.Memberships {
		membership.normalize()
		if membership.TeamID == "" && membership.CertPath == "" && membership.WorkspaceID == "" && membership.Alias == "" && membership.RoleName == "" && membership.JoinedAt == "" {
			continue
		}
		normalized = append(normalized, membership)
	}
	w.Memberships = normalized
}

func (w *WorktreeWorkspace) Membership(teamID string) *WorktreeMembership {
	if w == nil {
		return nil
	}
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return nil
	}
	for i := range w.Memberships {
		if strings.EqualFold(strings.TrimSpace(w.Memberships[i].TeamID), teamID) {
			return &w.Memberships[i]
		}
	}
	return nil
}

func (w *WorktreeWorkspace) ActiveMembership() *WorktreeMembership {
	if w == nil {
		return nil
	}
	return w.Membership(w.ActiveTeam)
}

func (w *WorktreeWorkspace) AvailableTeamIDs() []string {
	if w == nil || len(w.Memberships) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(w.Memberships))
	teamIDs := make([]string, 0, len(w.Memberships))
	for _, membership := range w.Memberships {
		teamID := strings.TrimSpace(membership.TeamID)
		if teamID == "" {
			continue
		}
		key := strings.ToLower(teamID)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		teamIDs = append(teamIDs, teamID)
	}
	sort.Strings(teamIDs)
	return teamIDs
}

func (w *WorktreeWorkspace) HasBinding() bool {
	if w == nil {
		return false
	}
	return strings.TrimSpace(w.AwebURL) != "" && w.ActiveMembership() != nil
}

func (w *WorktreeWorkspace) HasTeamBinding() bool {
	return w.HasBinding()
}

func (w *WorktreeWorkspace) validate() error {
	if w == nil {
		return errors.New("nil workspace state")
	}
	if strings.TrimSpace(w.AwebURL) == "" {
		return errors.New("workspace.yaml is missing aweb_url")
	}
	if len(w.Memberships) == 0 {
		return errors.New("workspace.yaml must contain at least one membership")
	}
	if strings.TrimSpace(w.ActiveTeam) == "" {
		return errors.New("workspace.yaml is missing active_team")
	}
	seen := make(map[string]struct{}, len(w.Memberships))
	for _, membership := range w.Memberships {
		if membership.TeamID == "" {
			return errors.New("workspace.yaml membership is missing team_id")
		}
		if membership.CertPath == "" {
			return fmt.Errorf("workspace.yaml membership %q is missing cert_path", membership.TeamID)
		}
		key := strings.ToLower(membership.TeamID)
		if _, ok := seen[key]; ok {
			return fmt.Errorf("workspace.yaml contains duplicate membership for %q", membership.TeamID)
		}
		seen[key] = struct{}{}
	}
	if w.ActiveMembership() == nil {
		return fmt.Errorf("workspace.yaml active_team %q is not present in memberships", w.ActiveTeam)
	}
	return nil
}

func inspectMembershipYAMLKeys(prefix string, value *yaml.Node) (removed []string, unsupported []string) {
	if value == nil || value.Kind != yaml.MappingNode {
		return nil, nil
	}
	for i := 0; i+1 < len(value.Content); i += 2 {
		key := strings.TrimSpace(value.Content[i].Value)
		if key == "" {
			continue
		}
		if _, ok := canonicalMembershipYAMLKeys[key]; ok {
			continue
		}
		label := fmt.Sprintf("%s.%s", prefix, key)
		if _, ok := removedWorkspaceYAMLKeys[key]; ok {
			removed = append(removed, label)
		} else {
			unsupported = append(unsupported, label)
		}
	}
	return removed, unsupported
}

func inspectWorkspaceYAMLKeys(value *yaml.Node) (bool, bool, bool, []string, []string) {
	if value == nil || value.Kind != yaml.MappingNode {
		return false, false, false, nil, nil
	}
	removed := make([]string, 0, 8)
	unsupported := make([]string, 0, 4)
	hasServerURL := false
	hasLegacyTeamAddress := false
	hasLegacySingleTeam := false
	for i := 0; i+1 < len(value.Content); i += 2 {
		keyNode := value.Content[i]
		valNode := value.Content[i+1]
		key := strings.TrimSpace(keyNode.Value)
		if key == "" {
			continue
		}
		if key == "memberships" {
			if valNode.Kind != yaml.SequenceNode {
				continue
			}
			for idx, item := range valNode.Content {
				entryRemoved, entryUnsupported := inspectMembershipYAMLKeys(fmt.Sprintf("memberships[%d]", idx), item)
				removed = append(removed, entryRemoved...)
				unsupported = append(unsupported, entryUnsupported...)
			}
			continue
		}
		if _, ok := canonicalWorkspaceYAMLKeys[key]; ok {
			continue
		}
		switch key {
		case "server_url":
			hasServerURL = true
		case "team_address":
			hasLegacyTeamAddress = true
		case "team_id":
			hasLegacySingleTeam = true
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
	return hasServerURL, hasLegacyTeamAddress, hasLegacySingleTeam, removed, unsupported
}

func (w *WorktreeWorkspace) UnmarshalYAML(value *yaml.Node) error {
	var raw worktreeWorkspaceYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}
	hasServerURL, hasLegacyTeamAddress, hasLegacySingleTeam, removed, unsupported := inspectWorkspaceYAMLKeys(value)
	if hasServerURL {
		return errors.New(legacyWorkspaceFormatError)
	}
	if hasLegacyTeamAddress {
		return errors.New(legacyWorkspaceTeamAddressError)
	}
	if hasLegacySingleTeam {
		return errors.New(legacyWorkspaceSingleTeamError)
	}
	if len(removed) > 0 {
		return fmt.Errorf("%s: %s. Run `aw init` to reinitialize this worktree.", legacyWorkspaceRemovedFieldsErrorPrefix, strings.Join(removed, ", "))
	}
	if len(unsupported) > 0 {
		return fmt.Errorf("%s: %s. Remove them and keep only the canonical workspace binding keys.", workspaceUnsupportedFieldsErrorPrefix, strings.Join(unsupported, ", "))
	}

	memberships := make([]WorktreeMembership, 0, len(raw.Memberships))
	for _, membership := range raw.Memberships {
		memberships = append(memberships, WorktreeMembership{
			TeamID:      membership.TeamID,
			Alias:       membership.Alias,
			RoleName:    membership.RoleName,
			WorkspaceID: membership.WorkspaceID,
			CertPath:    membership.CertPath,
			JoinedAt:    membership.JoinedAt,
		})
	}

	*w = WorktreeWorkspace{
		AwebURL:         raw.AwebURL,
		APIKey:          raw.APIKey,
		ActiveTeam:      raw.ActiveTeam,
		Memberships:     memberships,
		HumanName:       raw.HumanName,
		AgentType:       raw.AgentType,
		RepoID:          raw.RepoID,
		CanonicalOrigin: raw.CanonicalOrigin,
		Hostname:        raw.Hostname,
		WorkspacePath:   raw.WorkspacePath,
		UpdatedAt:       raw.UpdatedAt,
	}
	w.normalize()
	return w.validate()
}

func (w WorktreeWorkspace) MarshalYAML() (any, error) {
	w.normalize()
	if err := w.validate(); err != nil {
		return nil, err
	}
	memberships := make([]worktreeMembershipYAML, 0, len(w.Memberships))
	for _, membership := range w.Memberships {
		memberships = append(memberships, worktreeMembershipYAML{
			TeamID:      membership.TeamID,
			Alias:       membership.Alias,
			RoleName:    membership.RoleName,
			WorkspaceID: membership.WorkspaceID,
			CertPath:    membership.CertPath,
			JoinedAt:    membership.JoinedAt,
		})
	}
	return worktreeWorkspaceYAML{
		AwebURL:         w.AwebURL,
		APIKey:          w.APIKey,
		ActiveTeam:      w.ActiveTeam,
		Memberships:     memberships,
		HumanName:       w.HumanName,
		AgentType:       w.AgentType,
		RepoID:          w.RepoID,
		CanonicalOrigin: w.CanonicalOrigin,
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

func LoadLegacySingleTeamWorkspaceFrom(path string) (*LegacySingleTeamWorkspace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var state LegacySingleTeamWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	state.AwebURL = strings.TrimSpace(state.AwebURL)
	state.TeamID = strings.TrimSpace(state.TeamID)
	state.WorkspaceID = strings.TrimSpace(state.WorkspaceID)
	state.RepoID = strings.TrimSpace(state.RepoID)
	state.CanonicalOrigin = strings.TrimSpace(state.CanonicalOrigin)
	state.Alias = strings.TrimSpace(state.Alias)
	state.HumanName = strings.TrimSpace(state.HumanName)
	state.AgentType = strings.TrimSpace(state.AgentType)
	state.RoleName = strings.TrimSpace(state.RoleName)
	state.Hostname = strings.TrimSpace(state.Hostname)
	state.WorkspacePath = strings.TrimSpace(state.WorkspacePath)
	state.UpdatedAt = strings.TrimSpace(state.UpdatedAt)
	if state.TeamID == "" {
		return nil, errors.New("workspace.yaml is not in the legacy single-team shape")
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
	if err := state.validate(); err != nil {
		return err
	}

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

func LegacyWorkspaceSingleTeamError() string {
	return legacyWorkspaceSingleTeamError
}
