package awconfig

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeWorkspace struct {
	AwebURL         string `yaml:"aweb_url,omitempty"`
	TeamAddress     string `yaml:"team_address,omitempty"`
	WorkspaceID     string `yaml:"workspace_id"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	AgentType       string `yaml:"agent_type,omitempty"`
	RoleName        string `yaml:"role_name,omitempty"`
	Role            string `yaml:"-"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
}

type worktreeWorkspaceYAML struct {
	AwebURL         string `yaml:"aweb_url,omitempty"`
	ServerURL       string `yaml:"server_url,omitempty"`
	TeamAddress     string `yaml:"team_address,omitempty"`
	APIKey          string `yaml:"api_key,omitempty"`
	WorkspaceID     string `yaml:"workspace_id"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	AgentType       string `yaml:"agent_type,omitempty"`
	RoleName        string `yaml:"role_name,omitempty"`
	Role            string `yaml:"role,omitempty"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
	IdentityID      string `yaml:"identity_id,omitempty"`
	IdentityHandle  string `yaml:"identity_handle,omitempty"`
	NamespaceSlug   string `yaml:"namespace_slug,omitempty"`
	DID             string `yaml:"did,omitempty"`
	StableID        string `yaml:"stable_id,omitempty"`
	SigningKey      string `yaml:"signing_key,omitempty"`
	Custody         string `yaml:"custody,omitempty"`
	Lifetime        string `yaml:"lifetime,omitempty"`
	ProjectID       string `yaml:"project_id,omitempty"`
	ProjectSlug     string `yaml:"project_slug,omitempty"`
}

const legacyWorkspaceFormatError = "workspace.yaml is in the legacy format. Run `aw init` to reinitialize, or manually replace server_url with aweb_url in workspace.yaml."
const legacyWorkspaceAPIKeyError = "workspace.yaml uses removed api_key auth. Run `aw init` to reinitialize this worktree with team certificate auth."
const legacyWorkspaceRemovedFieldsErrorPrefix = "workspace.yaml uses removed legacy fields"

func (w *WorktreeWorkspace) syncRoleFields() {
	if w == nil {
		return
	}
	resolved := strings.TrimSpace(w.RoleName)
	if resolved == "" {
		resolved = strings.TrimSpace(w.Role)
	}
	w.RoleName = resolved
	w.Role = resolved
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
	w.syncRoleFields()
}

func (w *WorktreeWorkspace) HasBinding() bool {
	if w == nil {
		return false
	}
	return strings.TrimSpace(w.AwebURL) != "" && strings.TrimSpace(w.TeamAddress) != ""
}

func (w *WorktreeWorkspace) HasTeamBinding() bool {
	if w == nil {
		return false
	}
	return strings.TrimSpace(w.AwebURL) != "" && strings.TrimSpace(w.TeamAddress) != ""
}

func (raw worktreeWorkspaceYAML) removedFieldNames() []string {
	fields := make([]string, 0, 11)
	if strings.TrimSpace(raw.Role) != "" {
		fields = append(fields, "role")
	}
	if strings.TrimSpace(raw.IdentityID) != "" {
		fields = append(fields, "identity_id")
	}
	if strings.TrimSpace(raw.IdentityHandle) != "" {
		fields = append(fields, "identity_handle")
	}
	if strings.TrimSpace(raw.NamespaceSlug) != "" {
		fields = append(fields, "namespace_slug")
	}
	if strings.TrimSpace(raw.DID) != "" {
		fields = append(fields, "did")
	}
	if strings.TrimSpace(raw.StableID) != "" {
		fields = append(fields, "stable_id")
	}
	if strings.TrimSpace(raw.SigningKey) != "" {
		fields = append(fields, "signing_key")
	}
	if strings.TrimSpace(raw.Custody) != "" {
		fields = append(fields, "custody")
	}
	if strings.TrimSpace(raw.Lifetime) != "" {
		fields = append(fields, "lifetime")
	}
	if strings.TrimSpace(raw.ProjectID) != "" {
		fields = append(fields, "project_id")
	}
	if strings.TrimSpace(raw.ProjectSlug) != "" {
		fields = append(fields, "project_slug")
	}
	return fields
}

func (w *WorktreeWorkspace) UnmarshalYAML(value *yaml.Node) error {
	var raw worktreeWorkspaceYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}
	if strings.TrimSpace(raw.AwebURL) == "" && strings.TrimSpace(raw.ServerURL) != "" {
		return errors.New(legacyWorkspaceFormatError)
	}
	if strings.TrimSpace(raw.APIKey) != "" {
		return errors.New(legacyWorkspaceAPIKeyError)
	}
	if removed := raw.removedFieldNames(); len(removed) > 0 {
		return fmt.Errorf("%s: %s. Run `aw init` to reinitialize this worktree.", legacyWorkspaceRemovedFieldsErrorPrefix, strings.Join(removed, ", "))
	}

	*w = WorktreeWorkspace{
		AwebURL:         raw.AwebURL,
		TeamAddress:     raw.TeamAddress,
		WorkspaceID:     raw.WorkspaceID,
		RepoID:          raw.RepoID,
		CanonicalOrigin: raw.CanonicalOrigin,
		Alias:           raw.Alias,
		HumanName:       raw.HumanName,
		AgentType:       raw.AgentType,
		RoleName:        raw.RoleName,
		Role:            raw.Role,
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
		TeamAddress:     w.TeamAddress,
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
