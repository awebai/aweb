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

type TeamRolesBundle struct {
	Roles    map[string]RoleDefinition `json:"roles"`
	Adapters map[string]any            `json:"adapters,omitempty"`
}

type SelectedRoleInfo struct {
	RoleName   string `json:"role_name"`
	Role       string `json:"role"`
	Title      string `json:"title"`
	PlaybookMD string `json:"playbook_md"`
}

type ActiveTeamRolesResponse struct {
	TeamRolesID       string                    `json:"team_roles_id"`
	ActiveTeamRolesID string                    `json:"active_team_roles_id,omitempty"`
	TeamAddress       string                    `json:"team_address"`
	Version           int                       `json:"version"`
	UpdatedAt         string                    `json:"updated_at"`
	Roles             map[string]RoleDefinition `json:"roles"`
	SelectedRole      *SelectedRoleInfo         `json:"selected_role,omitempty"`
	Adapters          map[string]any            `json:"adapters,omitempty"`
}

type ActiveTeamRolesParams struct {
	RoleName     string
	Role         string
	OnlySelected bool
}

type CreateTeamRolesRequest struct {
	Bundle          TeamRolesBundle `json:"bundle"`
	BaseTeamRolesID string          `json:"base_team_roles_id,omitempty"`
	CreatedByAlias  string          `json:"created_by_alias,omitempty"`
}

type CreateTeamRolesResponse struct {
	TeamRolesID string `json:"team_roles_id"`
	TeamAddress string `json:"team_address"`
	Version     int    `json:"version"`
	Created     bool   `json:"created"`
}

type ActivateTeamRolesResponse struct {
	Activated         bool   `json:"activated"`
	ActiveTeamRolesID string `json:"active_team_roles_id"`
}

type ResetTeamRolesResponse struct {
	Reset             bool   `json:"reset"`
	ActiveTeamRolesID string `json:"active_team_roles_id"`
	Version           int    `json:"version"`
}

type DeactivateTeamRolesResponse struct {
	Deactivated       bool   `json:"deactivated"`
	ActiveTeamRolesID string `json:"active_team_roles_id"`
	Version           int    `json:"version"`
}

type TeamRolesHistoryItem struct {
	TeamRolesID    string  `json:"team_roles_id"`
	Version        int     `json:"version"`
	CreatedAt      string  `json:"created_at"`
	CreatedByAlias *string `json:"created_by_alias"`
	IsActive       bool    `json:"is_active"`
}

type TeamRolesHistoryResponse struct {
	TeamRolesVersions []TeamRolesHistoryItem `json:"team_roles_versions"`
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

func (c *Client) ActiveTeamRoles(ctx context.Context, params ActiveTeamRolesParams) (*ActiveTeamRolesResponse, error) {
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

	var out ActiveTeamRolesResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TeamRolesHistory(ctx context.Context, limit int) (*TeamRolesHistoryResponse, error) {
	path := "/v1/roles/history"
	if limit > 0 {
		path += "?limit=" + itoa(limit)
	}
	var out TeamRolesHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateTeamRoles(ctx context.Context, req *CreateTeamRolesRequest) (*CreateTeamRolesResponse, error) {
	var out CreateTeamRolesResponse
	if err := c.Post(ctx, "/v1/roles", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ActivateTeamRoles(ctx context.Context, teamRolesID string) (*ActivateTeamRolesResponse, error) {
	var out ActivateTeamRolesResponse
	if err := c.Post(ctx, "/v1/roles/"+urlPathEscape(teamRolesID)+"/activate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResetTeamRoles(ctx context.Context) (*ResetTeamRolesResponse, error) {
	var out ResetTeamRolesResponse
	if err := c.Post(ctx, "/v1/roles/reset", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeactivateTeamRoles(ctx context.Context) (*DeactivateTeamRolesResponse, error) {
	var out DeactivateTeamRolesResponse
	if err := c.Post(ctx, "/v1/roles/deactivate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
