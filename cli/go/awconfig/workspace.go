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
	CloudURL        string `yaml:"cloud_url,omitempty"`
	AwidURL         string `yaml:"awid_url,omitempty"`
	TeamAddress     string `yaml:"team_address,omitempty"`
	IdentityID      string `yaml:"identity_id,omitempty"`
	IdentityHandle  string `yaml:"identity_handle,omitempty"`
	NamespaceSlug   string `yaml:"namespace_slug,omitempty"`
	DID             string `yaml:"did,omitempty"`
	StableID        string `yaml:"stable_id,omitempty"`
	SigningKey      string `yaml:"signing_key,omitempty"`
	Custody         string `yaml:"custody,omitempty"`
	Lifetime        string `yaml:"lifetime,omitempty"`
	WorkspaceID     string `yaml:"workspace_id"`
	ProjectID       string `yaml:"project_id,omitempty"`
	ProjectSlug     string `yaml:"project_slug,omitempty"`
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
	CloudURL        string `yaml:"cloud_url,omitempty"`
	AwidURL         string `yaml:"awid_url,omitempty"`
	ServerURL       string `yaml:"server_url,omitempty"`
	TeamAddress     string `yaml:"team_address,omitempty"`
	APIKey          string `yaml:"api_key,omitempty"`
	IdentityID      string `yaml:"identity_id,omitempty"`
	IdentityHandle  string `yaml:"identity_handle,omitempty"`
	NamespaceSlug   string `yaml:"namespace_slug,omitempty"`
	DID             string `yaml:"did,omitempty"`
	StableID        string `yaml:"stable_id,omitempty"`
	SigningKey      string `yaml:"signing_key,omitempty"`
	Custody         string `yaml:"custody,omitempty"`
	Lifetime        string `yaml:"lifetime,omitempty"`
	WorkspaceID     string `yaml:"workspace_id"`
	ProjectID       string `yaml:"project_id,omitempty"`
	ProjectSlug     string `yaml:"project_slug,omitempty"`
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
}

const legacyWorkspaceFormatError = "workspace.yaml is in the legacy format. Run `aw init` to reinitialize, or manually add aweb_url, cloud_url, awid_url to workspace.yaml."
const legacyWorkspaceAPIKeyError = "workspace.yaml uses removed api_key auth. Run `aw init` to reinitialize this worktree with team certificate auth."

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
	w.CloudURL = strings.TrimSpace(w.CloudURL)
	w.AwidURL = strings.TrimSpace(w.AwidURL)
}

func (w *WorktreeWorkspace) syncHandleFields() {
	if w == nil {
		return
	}
	resolved := strings.TrimSpace(w.IdentityHandle)
	if resolved == "" {
		resolved = strings.TrimSpace(w.Alias)
	}
	w.IdentityHandle = resolved
	if strings.TrimSpace(w.Alias) == "" {
		w.Alias = resolved
	}
}

func (w *WorktreeWorkspace) normalize() {
	if w == nil {
		return
	}
	w.syncURLFields()
	w.syncRoleFields()
	w.syncHandleFields()
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

func (w *WorktreeWorkspace) hasIdentityFields() bool {
	if w == nil {
		return false
	}
	return strings.TrimSpace(w.DID) != "" ||
		strings.TrimSpace(w.StableID) != "" ||
		strings.TrimSpace(w.SigningKey) != "" ||
		strings.TrimSpace(w.Custody) != "" ||
		strings.TrimSpace(w.Lifetime) != ""
}

func (w *WorktreeWorkspace) clearIdentityFields() {
	if w == nil {
		return
	}
	w.DID = ""
	w.StableID = ""
	w.SigningKey = ""
	w.Custody = ""
	w.Lifetime = ""
}

func scrubWorkspaceIdentityFields(path string, state *WorktreeWorkspace, warn bool) error {
	if state == nil || !state.hasIdentityFields() {
		return nil
	}
	root := WorktreeRootFromWorkspacePath(path)
	if strings.TrimSpace(root) == "" {
		return nil
	}
	identityPath := filepath.Join(root, DefaultWorktreeIdentityRelativePath())
	if _, err := os.Stat(identityPath); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", identityPath, err)
	}
	if warn {
		fmt.Fprintf(os.Stderr, "Warning: ignoring identity fields in %s because %s is present\n", path, identityPath)
	}
	state.clearIdentityFields()
	return nil
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

	*w = WorktreeWorkspace{
		AwebURL:         raw.AwebURL,
		CloudURL:        raw.CloudURL,
		AwidURL:         raw.AwidURL,
		TeamAddress:     raw.TeamAddress,
		IdentityID:      raw.IdentityID,
		IdentityHandle:  raw.IdentityHandle,
		NamespaceSlug:   raw.NamespaceSlug,
		DID:             raw.DID,
		StableID:        raw.StableID,
		SigningKey:      raw.SigningKey,
		Custody:         raw.Custody,
		Lifetime:        raw.Lifetime,
		WorkspaceID:     raw.WorkspaceID,
		ProjectID:       raw.ProjectID,
		ProjectSlug:     raw.ProjectSlug,
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
		CloudURL:        w.CloudURL,
		AwidURL:         w.AwidURL,
		TeamAddress:     w.TeamAddress,
		IdentityID:      w.IdentityID,
		IdentityHandle:  w.IdentityHandle,
		NamespaceSlug:   w.NamespaceSlug,
		DID:             w.DID,
		StableID:        w.StableID,
		SigningKey:      w.SigningKey,
		Custody:         w.Custody,
		Lifetime:        w.Lifetime,
		WorkspaceID:     w.WorkspaceID,
		ProjectID:       w.ProjectID,
		ProjectSlug:     w.ProjectSlug,
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
	if err := scrubWorkspaceIdentityFields(path, &state, true); err != nil {
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
	if err := scrubWorkspaceIdentityFields(path, state, false); err != nil {
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
