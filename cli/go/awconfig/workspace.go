package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

type WorktreeWorkspace struct {
	WorkspaceID     string `yaml:"workspace_id"`
	ProjectID       string `yaml:"project_id,omitempty"`
	ProjectSlug     string `yaml:"project_slug,omitempty"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	RoleName        string `yaml:"role_name,omitempty"`
	Role            string `yaml:"-"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
}

type worktreeWorkspaceYAML struct {
	WorkspaceID     string `yaml:"workspace_id"`
	ProjectID       string `yaml:"project_id,omitempty"`
	ProjectSlug     string `yaml:"project_slug,omitempty"`
	RepoID          string `yaml:"repo_id,omitempty"`
	CanonicalOrigin string `yaml:"canonical_origin,omitempty"`
	Alias           string `yaml:"alias,omitempty"`
	HumanName       string `yaml:"human_name,omitempty"`
	RoleName        string `yaml:"role_name,omitempty"`
	Role            string `yaml:"role,omitempty"`
	Hostname        string `yaml:"hostname,omitempty"`
	WorkspacePath   string `yaml:"workspace_path,omitempty"`
	UpdatedAt       string `yaml:"updated_at,omitempty"`
}

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

func (w *WorktreeWorkspace) UnmarshalYAML(value *yaml.Node) error {
	var raw worktreeWorkspaceYAML
	if err := value.Decode(&raw); err != nil {
		return err
	}

	*w = WorktreeWorkspace{
		WorkspaceID:     raw.WorkspaceID,
		ProjectID:       raw.ProjectID,
		ProjectSlug:     raw.ProjectSlug,
		RepoID:          raw.RepoID,
		CanonicalOrigin: raw.CanonicalOrigin,
		Alias:           raw.Alias,
		HumanName:       raw.HumanName,
		RoleName:        raw.RoleName,
		Role:            raw.Role,
		Hostname:        raw.Hostname,
		WorkspacePath:   raw.WorkspacePath,
		UpdatedAt:       raw.UpdatedAt,
	}
	w.syncRoleFields()
	return nil
}

func (w WorktreeWorkspace) MarshalYAML() (any, error) {
	w.syncRoleFields()
	return worktreeWorkspaceYAML{
		WorkspaceID:     w.WorkspaceID,
		ProjectID:       w.ProjectID,
		ProjectSlug:     w.ProjectSlug,
		RepoID:          w.RepoID,
		CanonicalOrigin: w.CanonicalOrigin,
		Alias:           w.Alias,
		HumanName:       w.HumanName,
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
	state.syncRoleFields()

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
	clean := filepath.Clean(path)
	base := filepath.Base(clean)
	if base == "workspace.yaml" {
		return filepath.Dir(filepath.Dir(clean))
	}
	return filepath.Dir(filepath.Dir(clean))
}
