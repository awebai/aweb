package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var rolesCmd = &cobra.Command{
	Use:   "roles",
	Short: "Read and manage team roles bundles and role definitions",
}

var rolesShowCmd = &cobra.Command{
	Use:   "show [role-name]",
	Short: "Show role guidance from the active team roles bundle",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runTeamRolesShow,
}

var rolesListCmd = &cobra.Command{
	Use:   "list",
	Short: "List roles defined in the active team roles bundle",
	RunE:  runRolesList,
}

var rolesHistoryCmd = &cobra.Command{
	Use:   "history",
	Short: "List team roles history",
	RunE:  runRolesHistory,
}

var rolesSetCmd = &cobra.Command{
	Use:   "set",
	Short: "Create and activate a new team roles bundle version",
	RunE:  runRolesSet,
}

var rolesAddCmd = &cobra.Command{
	Use:   "add <role-name>",
	Short: "Add or update one role in the active team roles bundle",
	Long: "Add or update one role in the active team roles bundle.\n\n" +
		"This is the novice-friendly way to build a roles bundle from resource-pack\n" +
		"role Markdown files one role at a time. It reads the active bundle, adds the\n" +
		"role, creates a new bundle version, and activates it.",
	Args: cobra.ExactArgs(1),
	RunE: runRolesAdd,
}

var rolesActivateCmd = &cobra.Command{
	Use:   "activate <team-roles-id>",
	Short: "Activate an existing team roles bundle version",
	Args:  cobra.ExactArgs(1),
	RunE:  runRolesActivate,
}

var rolesResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Reset team roles to the server default bundle",
	RunE:  runRolesReset,
}

var rolesDeactivateCmd = &cobra.Command{
	Use:   "deactivate",
	Short: "Deactivate team roles by replacing the active bundle with an empty bundle",
	RunE:  runRolesDeactivate,
}

var (
	rolesShowRoleNameFlag string
	rolesShowAllFlag      bool
	rolesHistoryLimit     int
	rolesSetBundleJSON    string
	rolesSetBundleFile    string
	rolesAddTitle         string
	rolesAddPlaybook      string
	rolesAddPlaybookFile  string
	rolesAddReplace       bool
)

type teamRolesShowOutput struct {
	RoleName     string                        `json:"role_name,omitempty"`
	Role         string                        `json:"role,omitempty"`
	OnlySelected bool                          `json:"only_selected"`
	TeamRoles    *aweb.ActiveTeamRolesResponse `json:"team_roles"`
}

type teamRolesListOutput struct {
	Roles []teamRoleItem `json:"roles"`
}

type teamRolesSetOutput struct {
	TeamRolesID string `json:"team_roles_id"`
	Version     int    `json:"version"`
	Activated   bool   `json:"activated"`
}

type teamRolesAddOutput struct {
	TeamRolesID string `json:"team_roles_id"`
	Version     int    `json:"version"`
	Activated   bool   `json:"activated"`
	RoleName    string `json:"role_name"`
	Title       string `json:"title"`
	Replaced    bool   `json:"replaced"`
}

type teamRolesActivateOutput struct {
	TeamRolesID string `json:"team_roles_id"`
	Activated   bool   `json:"activated"`
}

type teamRoleItem struct {
	Name  string `json:"name"`
	Title string `json:"title"`
}

type namedRoleDefinition struct {
	Name       string `json:"name"`
	Title      string `json:"title"`
	PlaybookMD string `json:"playbook_md"`
}

func init() {
	addRolesShowFlags(rolesShowCmd)
	rolesHistoryCmd.Flags().IntVar(&rolesHistoryLimit, "limit", 20, "Max role bundle versions")
	rolesSetCmd.Flags().StringVar(&rolesSetBundleJSON, "bundle-json", "", "Team roles bundle JSON")
	rolesSetCmd.Flags().StringVar(&rolesSetBundleFile, "bundle-file", "", "Read team roles bundle JSON from file ('-' for stdin)")
	rolesAddCmd.Flags().StringVar(&rolesAddTitle, "title", "", "Human-readable role title (defaults to role name)")
	rolesAddCmd.Flags().StringVar(&rolesAddPlaybook, "playbook", "", "Role playbook Markdown body")
	rolesAddCmd.Flags().StringVar(&rolesAddPlaybookFile, "playbook-file", "", "Read role playbook Markdown from file ('-' for stdin)")
	rolesAddCmd.Flags().BoolVar(&rolesAddReplace, "replace", false, "Replace an existing role with the same name")

	rolesCmd.AddCommand(rolesShowCmd)
	rolesCmd.AddCommand(rolesListCmd)
	rolesCmd.AddCommand(rolesHistoryCmd)
	rolesCmd.AddCommand(rolesSetCmd)
	rolesCmd.AddCommand(rolesAddCmd)
	rolesCmd.AddCommand(rolesActivateCmd)
	rolesCmd.AddCommand(rolesResetCmd)
	rolesCmd.AddCommand(rolesDeactivateCmd)
	rootCmd.AddCommand(rolesCmd)
	rolesCmd.GroupID = groupCoordination
}

func addRolesShowFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&rolesShowRoleNameFlag, "role-name", "", "Preview a specific role name")
	cmd.Flags().StringVar(&rolesShowRoleNameFlag, "role", "", "Compatibility alias for --role-name")
	cmd.Flags().BoolVar(&rolesShowAllFlag, "all-roles", false, "Include all role playbooks instead of only the selected role")
}

func runTeamRolesShow(cmd *cobra.Command, args []string) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	requestedRole := rolesShowRoleNameFlag
	if strings.TrimSpace(requestedRole) == "" && len(args) > 0 {
		requestedRole = args[0]
	}
	roleName := resolveRequestedRoleName(sel, requestedRole)
	onlySelected := !rolesShowAllFlag
	if roleName == "" {
		// No role resolvable: list the bundle instead of asking the server
		// for a specific role. only_selected=true with no role name would
		// 400 ("only_selected=true requires a role or role_name parameter").
		onlySelected = false
	}
	if rolesShowAllFlag {
		roleName = ""
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{
		RoleName:     roleName,
		OnlySelected: onlySelected,
	})
	if err != nil {
		return err
	}

	printOutput(teamRolesShowOutput{
		RoleName:     roleName,
		Role:         roleName,
		OnlySelected: onlySelected,
		TeamRoles:    resp,
	}, formatTeamRolesShow)
	return nil
}

func runRolesList(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}
	roles, err := fetchAvailableRoleItems(client)
	if err != nil {
		return err
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Name < roles[j].Name })
	printOutput(teamRolesListOutput{Roles: roles}, formatTeamRolesList)
	return nil
}

func runRolesHistory(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TeamRolesHistory(ctx, rolesHistoryLimit)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamRolesHistory)
	return nil
}

func runRolesSet(cmd *cobra.Command, args []string) error {
	bundle, err := resolveRolesBundle(cmd.InOrStdin(), rolesSetBundleJSON, rolesSetBundleFile)
	if err != nil {
		return err
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	created, err := createAndActivateTeamRolesBundle(ctx, client, bundle, "")
	if err != nil {
		return err
	}

	printOutput(teamRolesSetOutput{
		TeamRolesID: created.TeamRolesID,
		Version:     created.Version,
		Activated:   true,
	}, formatTeamRolesSet)
	return nil
}

func runRolesAdd(cmd *cobra.Command, args []string) error {
	roleName := strings.TrimSpace(args[0])
	if roleName == "" {
		return usageError("role-name is required")
	}
	playbook, err := resolveRolesAddPlaybook(cmd.InOrStdin(), rolesAddPlaybook, rolesAddPlaybookFile)
	if err != nil {
		return err
	}
	if strings.TrimSpace(playbook) == "" {
		return usageError("role playbook is empty; pass --playbook or --playbook-file")
	}
	title := strings.TrimSpace(rolesAddTitle)
	if title == "" {
		title = roleName
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	active, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{OnlySelected: false})
	if err != nil {
		return err
	}
	bundle := aweb.TeamRolesBundle{
		Roles:    map[string]aweb.RoleDefinition{},
		Adapters: active.Adapters,
	}
	for name, role := range active.Roles {
		bundle.Roles[name] = role
	}
	_, existed := bundle.Roles[roleName]
	if existed && !rolesAddReplace {
		return usageError("role %q already exists; pass --replace to update it", roleName)
	}
	bundle.Roles[roleName] = aweb.RoleDefinition{Title: title, PlaybookMD: playbook}

	created, err := createAndActivateTeamRolesBundle(ctx, client, bundle, active.TeamRolesID)
	if err != nil {
		return err
	}

	printOutput(teamRolesAddOutput{
		TeamRolesID: created.TeamRolesID,
		Version:     created.Version,
		Activated:   true,
		RoleName:    roleName,
		Title:       title,
		Replaced:    existed,
	}, formatTeamRolesAdd)
	return nil
}

func createAndActivateTeamRolesBundle(ctx context.Context, client *aweb.Client, bundle aweb.TeamRolesBundle, baseTeamRolesID string) (*aweb.CreateTeamRolesResponse, error) {
	if strings.TrimSpace(baseTeamRolesID) == "" {
		active, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{OnlySelected: false})
		if err != nil {
			return nil, err
		}
		baseTeamRolesID = active.TeamRolesID
	}
	created, err := client.CreateTeamRoles(ctx, &aweb.CreateTeamRolesRequest{
		Bundle:          bundle,
		BaseTeamRolesID: baseTeamRolesID,
	})
	if err != nil {
		return nil, err
	}

	if _, err := client.ActivateTeamRoles(ctx, created.TeamRolesID); err != nil {
		return nil, err
	}
	return created, nil
}

func runRolesActivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActivateTeamRoles(ctx, strings.TrimSpace(args[0]))
	if err != nil {
		return err
	}

	printOutput(teamRolesActivateOutput{
		TeamRolesID: resp.ActiveTeamRolesID,
		Activated:   resp.Activated,
	}, formatTeamRolesActivate)
	return nil
}

func runRolesReset(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ResetTeamRoles(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamRolesReset)
	return nil
}

func runRolesDeactivate(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.DeactivateTeamRoles(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatTeamRolesDeactivate)
	return nil
}

func fetchAvailableRoleItems(client *aweb.Client) ([]teamRoleItem, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{
		OnlySelected: false,
	})
	if err != nil {
		return nil, err
	}

	roles := make([]teamRoleItem, 0, len(resp.Roles))
	for name, info := range resp.Roles {
		title := strings.TrimSpace(info.Title)
		if title == "" {
			title = name
		}
		roles = append(roles, teamRoleItem{Name: name, Title: title})
	}
	return roles, nil
}

func resolveRequestedRoleName(sel *awconfig.Selection, explicit string) string {
	if roleName := strings.TrimSpace(explicit); roleName != "" {
		return roleName
	}
	wd, _ := os.Getwd()
	if state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(wd); err == nil {
		if membership, err := workspaceMembershipForSelection(state, sel); err == nil && membership != nil {
			if roleName := strings.TrimSpace(membership.RoleName); roleName != "" {
				return roleName
			}
		}
	}
	_ = sel
	// No role resolvable. Returning the empty string lets the caller fall
	// back to listing the bundle instead of forcing a name like "developer"
	// that may not exist in the team's bundle (new teams bootstrap empty).
	return ""
}

func resolveRolesAddPlaybook(stdin io.Reader, playbook, playbookFile string) (string, error) {
	playbook = strings.TrimSpace(playbook)
	playbookFile = strings.TrimSpace(playbookFile)
	switch {
	case playbook != "" && playbookFile != "":
		return "", usageError("use only one of --playbook or --playbook-file")
	case playbook != "":
		return playbook, nil
	case playbookFile == "":
		return "", usageError("missing required flag: --playbook or --playbook-file")
	case playbookFile == "-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return "", err
		}
		return string(data), nil
	default:
		data, err := os.ReadFile(playbookFile)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
}

func resolveRolesBundle(stdin io.Reader, bundleJSON, bundleFile string) (aweb.TeamRolesBundle, error) {
	bundleJSON = strings.TrimSpace(bundleJSON)
	bundleFile = strings.TrimSpace(bundleFile)

	var raw []byte
	switch {
	case bundleJSON != "" && bundleFile != "":
		return aweb.TeamRolesBundle{}, usageError("use only one of --bundle-json or --bundle-file")
	case bundleJSON != "":
		raw = []byte(bundleJSON)
	case bundleFile == "":
		return aweb.TeamRolesBundle{}, usageError("missing required flag: --bundle-json or --bundle-file")
	case bundleFile == "-":
		data, err := io.ReadAll(stdin)
		if err != nil {
			return aweb.TeamRolesBundle{}, err
		}
		raw = data
	default:
		data, err := os.ReadFile(bundleFile)
		if err != nil {
			return aweb.TeamRolesBundle{}, err
		}
		raw = data
	}

	return parseRolesBundle(raw)
}

func parseRolesBundle(raw []byte) (aweb.TeamRolesBundle, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return aweb.TeamRolesBundle{}, fmt.Errorf("invalid roles bundle JSON: empty input")
	}

	switch raw[0] {
	case '[':
		roles, err := parseNamedRoleDefinitions(raw)
		if err != nil {
			return aweb.TeamRolesBundle{}, err
		}
		return aweb.TeamRolesBundle{Roles: roles}, nil
	case '{':
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			return aweb.TeamRolesBundle{}, fmt.Errorf("invalid roles bundle JSON: %w", err)
		}

		roles := map[string]aweb.RoleDefinition{}
		if rolesRaw, hasRoles := fields["roles"]; hasRoles && len(bytes.TrimSpace(rolesRaw)) > 0 && string(bytes.TrimSpace(rolesRaw)) != "null" {
			parsed, err := parseRoleDefinitions(rolesRaw)
			if err != nil {
				return aweb.TeamRolesBundle{}, err
			}
			roles = parsed
		} else if _, hasRoles := fields["roles"]; !hasRoles && len(fields) > 0 {
			if _, hasAdapters := fields["adapters"]; !hasAdapters {
				return aweb.TeamRolesBundle{}, fmt.Errorf("invalid roles bundle JSON: expected either {\"roles\":{\"developer\":{...}}} or an array of role objects with a name field")
			}
		}

		adapters, err := parseRoleAdapters(fields["adapters"])
		if err != nil {
			return aweb.TeamRolesBundle{}, err
		}
		return aweb.TeamRolesBundle{
			Roles:    roles,
			Adapters: adapters,
		}, nil
	default:
		return aweb.TeamRolesBundle{}, fmt.Errorf("invalid roles bundle JSON: expected an object with a roles field or an array of role objects")
	}
}

func parseRoleAdapters(raw json.RawMessage) (map[string]any, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	if raw[0] != '{' {
		return nil, fmt.Errorf("invalid roles bundle JSON: adapters must be an object")
	}
	var adapters map[string]any
	if err := json.Unmarshal(raw, &adapters); err != nil {
		return nil, fmt.Errorf("invalid roles bundle JSON: adapters must be an object")
	}
	return adapters, nil
}

func parseRoleDefinitions(raw json.RawMessage) (map[string]aweb.RoleDefinition, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]aweb.RoleDefinition{}, nil
	}
	switch raw[0] {
	case '[':
		return parseNamedRoleDefinitions(raw)
	case '{':
		return parseRoleDefinitionMap(raw)
	default:
		return nil, fmt.Errorf("invalid roles bundle JSON: roles must be a map keyed by role name or an array of role objects with a name field")
	}
}

func parseRoleDefinitionMap(raw json.RawMessage) (map[string]aweb.RoleDefinition, error) {
	var roleMessages map[string]json.RawMessage
	if err := json.Unmarshal(raw, &roleMessages); err != nil {
		return nil, fmt.Errorf("invalid roles bundle JSON: roles must be a map keyed by role name")
	}

	roles := make(map[string]aweb.RoleDefinition, len(roleMessages))
	for rawName, rawRole := range roleMessages {
		name := strings.TrimSpace(rawName)
		if name == "" {
			return nil, fmt.Errorf("invalid roles bundle JSON: role names must not be empty")
		}
		role, err := parseRoleDefinition(rawRole, fmt.Sprintf("roles.%s", name))
		if err != nil {
			return nil, err
		}
		roles[name] = role
	}
	return roles, nil
}

func parseNamedRoleDefinitions(raw json.RawMessage) (map[string]aweb.RoleDefinition, error) {
	var roleMessages []json.RawMessage
	if err := json.Unmarshal(raw, &roleMessages); err != nil {
		return nil, fmt.Errorf("invalid roles bundle JSON: expected an array of role objects")
	}

	roles := make(map[string]aweb.RoleDefinition, len(roleMessages))
	for i, rawRole := range roleMessages {
		trimmed := bytes.TrimSpace(rawRole)
		if len(trimmed) == 0 || trimmed[0] != '{' {
			return nil, fmt.Errorf("invalid roles bundle JSON: roles[%d] must be an object with name, title, and playbook_md", i)
		}
		var role namedRoleDefinition
		if err := json.Unmarshal(trimmed, &role); err != nil {
			return nil, fmt.Errorf("invalid roles bundle JSON: roles[%d] must be an object with name, title, and playbook_md", i)
		}
		name := strings.TrimSpace(role.Name)
		if name == "" {
			return nil, fmt.Errorf("invalid roles bundle JSON: roles[%d].name is required for array-shaped bundles", i)
		}
		if _, exists := roles[name]; exists {
			return nil, fmt.Errorf("invalid roles bundle JSON: duplicate role name %q", name)
		}
		roles[name] = aweb.RoleDefinition{
			Title:      role.Title,
			PlaybookMD: role.PlaybookMD,
		}
	}
	return roles, nil
}

func parseRoleDefinition(raw json.RawMessage, label string) (aweb.RoleDefinition, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return aweb.RoleDefinition{}, fmt.Errorf("invalid roles bundle JSON: %s must be an object with title and playbook_md", label)
	}
	var role aweb.RoleDefinition
	if err := json.Unmarshal(trimmed, &role); err != nil {
		return aweb.RoleDefinition{}, fmt.Errorf("invalid roles bundle JSON: %s must be an object with title and playbook_md", label)
	}
	return role, nil
}

func formatTeamRolesShow(v any) string {
	out := v.(teamRolesShowOutput)
	if out.TeamRoles == nil {
		return "No active team roles.\n"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Team Roles v%d\n", out.TeamRoles.Version))
	if out.RoleName != "" {
		sb.WriteString(fmt.Sprintf("Role: %s\n", out.RoleName))
	}

	if out.TeamRoles.SelectedRole != nil {
		sb.WriteString(fmt.Sprintf("\n## Role: %s\n", out.TeamRoles.SelectedRole.Title))
		for _, line := range strings.Split(strings.TrimSpace(out.TeamRoles.SelectedRole.PlaybookMD), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			sb.WriteString(line + "\n")
		}
		return sb.String()
	}

	if len(out.TeamRoles.Roles) == 0 {
		sb.WriteString("\nNo roles configured for this team. Add roles with `aw roles add`.\n")
		return sb.String()
	}

	names := make([]string, 0, len(out.TeamRoles.Roles))
	for name := range out.TeamRoles.Roles {
		names = append(names, name)
	}
	sort.Strings(names)
	sb.WriteString("\n## Roles\n")
	for _, name := range names {
		role := out.TeamRoles.Roles[name]
		title := strings.TrimSpace(role.Title)
		if title == "" {
			title = name
		}
		sb.WriteString(fmt.Sprintf("\n### %s\n", title))
		playbook := strings.TrimSpace(role.PlaybookMD)
		if playbook == "" {
			sb.WriteString("(no playbook)\n")
			continue
		}
		for _, line := range strings.Split(playbook, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			sb.WriteString(line + "\n")
		}
	}

	return sb.String()
}

func formatTeamRolesList(v any) string {
	out := v.(teamRolesListOutput)
	if len(out.Roles) == 0 {
		return "No roles defined.\n"
	}
	var sb strings.Builder
	for _, role := range out.Roles {
		if role.Title != "" && role.Title != role.Name {
			sb.WriteString(fmt.Sprintf("%s\t%s\n", role.Name, role.Title))
		} else {
			sb.WriteString(role.Name + "\n")
		}
	}
	return sb.String()
}

func formatTeamRolesHistory(v any) string {
	out := v.(*aweb.TeamRolesHistoryResponse)
	if out == nil || len(out.TeamRolesVersions) == 0 {
		return "No team roles versions.\n"
	}

	var sb strings.Builder
	for _, item := range out.TeamRolesVersions {
		status := "inactive"
		if item.IsActive {
			status = "active"
		}
		sb.WriteString(fmt.Sprintf("v%d\t%s\t%s\t%s", item.Version, status, item.CreatedAt, item.TeamRolesID))
		if item.CreatedByAlias != nil && strings.TrimSpace(*item.CreatedByAlias) != "" {
			sb.WriteString("\t" + strings.TrimSpace(*item.CreatedByAlias))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func formatTeamRolesSet(v any) string {
	out := v.(teamRolesSetOutput)
	return fmt.Sprintf("Activated team roles v%d (%s)\n", out.Version, out.TeamRolesID)
}

func formatTeamRolesAdd(v any) string {
	out := v.(teamRolesAddOutput)
	action := "Added"
	if out.Replaced {
		action = "Updated"
	}
	return fmt.Sprintf("%s role %s and activated team roles v%d (%s)\n", action, out.RoleName, out.Version, out.TeamRolesID)
}

func formatTeamRolesActivate(v any) string {
	out := v.(teamRolesActivateOutput)
	return fmt.Sprintf("Activated team roles %s\n", out.TeamRolesID)
}

func formatTeamRolesReset(v any) string {
	out := v.(*aweb.ResetTeamRolesResponse)
	if out == nil {
		return "Team roles reset.\n"
	}
	return fmt.Sprintf("Reset team roles to default (v%d, %s)\n", out.Version, out.ActiveTeamRolesID)
}

func formatTeamRolesDeactivate(v any) string {
	out := v.(*aweb.DeactivateTeamRolesResponse)
	if out == nil {
		return "Team roles deactivated.\n"
	}
	return fmt.Sprintf("Deactivated team roles (v%d, %s)\n", out.Version, out.ActiveTeamRolesID)
}
