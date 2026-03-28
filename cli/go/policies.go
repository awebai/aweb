package aweb

import (
	"context"
	"fmt"
	"strings"
)

type ProjectRolesInvariant struct {
	ID     string `json:"id"`
	Title  string `json:"title"`
	BodyMD string `json:"body_md"`
}

type RoleDefinition struct {
	Title      string `json:"title"`
	PlaybookMD string `json:"playbook_md"`
}

type SelectedRoleInfo struct {
	RoleName   string `json:"role_name"`
	Role       string `json:"role"`
	Title      string `json:"title"`
	PlaybookMD string `json:"playbook_md"`
}

type ActiveProjectRolesResponse struct {
	ProjectRolesID       string                    `json:"project_roles_id"`
	PolicyID             string                    `json:"policy_id"`
	ActiveProjectRolesID string                    `json:"active_project_roles_id,omitempty"`
	ActivePolicyID       string                    `json:"active_policy_id,omitempty"`
	ProjectID            string                    `json:"project_id"`
	Version              int                       `json:"version"`
	UpdatedAt            string                    `json:"updated_at"`
	Invariants           []ProjectRolesInvariant   `json:"invariants"`
	Roles                map[string]RoleDefinition `json:"roles"`
	SelectedRole         *SelectedRoleInfo         `json:"selected_role,omitempty"`
}

type ActiveProjectRolesParams struct {
	RoleName     string
	Role         string
	OnlySelected bool
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

type PolicyInvariant = ProjectRolesInvariant
type PolicyRolePlaybook = RoleDefinition
type PolicySelectedRole = SelectedRoleInfo
type ActivePolicyResponse = ActiveProjectRolesResponse
type ActivePolicyParams = ActiveProjectRolesParams

func (c *Client) ActivePolicy(ctx context.Context, params ActivePolicyParams) (*ActivePolicyResponse, error) {
	return c.ActiveProjectRoles(ctx, ActiveProjectRolesParams(params))
}
