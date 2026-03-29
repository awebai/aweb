package aweb

import (
	"context"
	"fmt"
	"strings"
)

type RoleDefinition struct {
	Title      string `json:"title"`
	PlaybookMD string `json:"playbook_md"`
}

type ProjectRolesBundle struct {
	Roles    map[string]RoleDefinition `json:"roles"`
	Adapters map[string]any            `json:"adapters,omitempty"`
}

type SelectedRoleInfo struct {
	RoleName   string `json:"role_name"`
	Role       string `json:"role"`
	Title      string `json:"title"`
	PlaybookMD string `json:"playbook_md"`
}

type ActiveProjectRolesResponse struct {
	ProjectRolesID       string                    `json:"project_roles_id"`
	ActiveProjectRolesID string                    `json:"active_project_roles_id,omitempty"`
	ProjectID            string                    `json:"project_id"`
	Version              int                       `json:"version"`
	UpdatedAt            string                    `json:"updated_at"`
	Roles                map[string]RoleDefinition `json:"roles"`
	SelectedRole         *SelectedRoleInfo         `json:"selected_role,omitempty"`
	Adapters             map[string]any            `json:"adapters,omitempty"`
}

type ActiveProjectRolesParams struct {
	RoleName     string
	Role         string
	OnlySelected bool
}

type CreateProjectRolesRequest struct {
	Bundle               ProjectRolesBundle `json:"bundle"`
	BaseProjectRolesID   string             `json:"base_project_roles_id,omitempty"`
	CreatedByWorkspaceID string             `json:"created_by_workspace_id,omitempty"`
}

type CreateProjectRolesResponse struct {
	ProjectRolesID string `json:"project_roles_id"`
	ProjectID      string `json:"project_id"`
	Version        int    `json:"version"`
	Created        bool   `json:"created"`
}

type ActivateProjectRolesResponse struct {
	Activated            bool   `json:"activated"`
	ActiveProjectRolesID string `json:"active_project_roles_id"`
}

type ResetProjectRolesResponse struct {
	Reset                bool   `json:"reset"`
	ActiveProjectRolesID string `json:"active_project_roles_id"`
	Version              int    `json:"version"`
}

type DeactivateProjectRolesResponse struct {
	Deactivated          bool   `json:"deactivated"`
	ActiveProjectRolesID string `json:"active_project_roles_id"`
	Version              int    `json:"version"`
}

type ProjectRolesHistoryItem struct {
	ProjectRolesID       string  `json:"project_roles_id"`
	Version              int     `json:"version"`
	CreatedAt            string  `json:"created_at"`
	CreatedByWorkspaceID *string `json:"created_by_workspace_id"`
	IsActive             bool    `json:"is_active"`
}

type ProjectRolesHistoryResponse struct {
	ProjectRolesVersions []ProjectRolesHistoryItem `json:"project_roles_versions"`
}

func resolveRoleNameParam(roleName, legacyRole string) (string, error) {
	roleName = strings.TrimSpace(roleName)
	legacyRole = strings.TrimSpace(legacyRole)
	switch {
	case roleName != "" && legacyRole != "" && roleName != legacyRole:
		return "", fmt.Errorf("role_name and role must match when both are provided")
	case roleName != "":
		return roleName, nil
	default:
		return legacyRole, nil
	}
}

func (c *Client) ActiveProjectRoles(ctx context.Context, params ActiveProjectRolesParams) (*ActiveProjectRolesResponse, error) {
	roleName, err := resolveRoleNameParam(params.RoleName, params.Role)
	if err != nil {
		return nil, err
	}

	path := "/v1/roles/active"
	sep := "?"
	if roleName != "" {
		path += sep + "role_name=" + urlQueryEscape(roleName)
		sep = "&"
	}
	path += sep + "only_selected=" + boolString(params.OnlySelected)

	var out ActiveProjectRolesResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProjectRolesHistory(ctx context.Context, limit int) (*ProjectRolesHistoryResponse, error) {
	path := "/v1/roles/history"
	if limit > 0 {
		path += "?limit=" + itoa(limit)
	}
	var out ProjectRolesHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateProjectRoles(ctx context.Context, req *CreateProjectRolesRequest) (*CreateProjectRolesResponse, error) {
	var out CreateProjectRolesResponse
	if err := c.Post(ctx, "/v1/roles", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ActivateProjectRoles(ctx context.Context, projectRolesID string) (*ActivateProjectRolesResponse, error) {
	var out ActivateProjectRolesResponse
	if err := c.Post(ctx, "/v1/roles/"+urlPathEscape(projectRolesID)+"/activate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResetProjectRoles(ctx context.Context) (*ResetProjectRolesResponse, error) {
	var out ResetProjectRolesResponse
	if err := c.Post(ctx, "/v1/roles/reset", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeactivateProjectRoles(ctx context.Context) (*DeactivateProjectRolesResponse, error) {
	var out DeactivateProjectRolesResponse
	if err := c.Post(ctx, "/v1/roles/deactivate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
