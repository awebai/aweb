package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/awebai/aw/awid"
	"net/url"
	"regexp"
	"strings"

	"github.com/spf13/cobra"
)

const cliOrganizationsPath = "/api/v1/cli/organizations"

var orgDisplayName string

var orgCmd = &cobra.Command{
	Use: "org", Short: "Manage organizations using this host's human login",
	Long: "Manage organizations using host CLI authorization, not an agent or team key.\n\n" +
		"For an existing account, propose <username>-<hostname>; for a new account,\n" +
		"propose the hostname. Distro defaults such as omarchy, archlinux and localhost\n" +
		"should go straight to an available suggestion. Confirm the proposed name before\n" +
		"creating it. The server never silently suffixes a requested organization slug.\n" +
		"Use org availability for a read-only plan; it creates no keys or resources.",
	GroupID: groupIdentity,
}

var orgCreateCmd = &cobra.Command{
	Use: "create <slug>", Short: "Create or recover an organization you own",
	Long: orgCmd.Long,
	Args: cobra.ExactArgs(1), RunE: runOrgCreate,
}

var orgListCmd = &cobra.Command{
	Use: "list", Short: "List organizations where you are an owner or admin",
	Args: cobra.NoArgs, RunE: runOrgList,
}

var orgAvailabilityCmd = &cobra.Command{
	Use: "availability <slug>", Short: "Check an organization name without creating anything",
	Args: cobra.ExactArgs(1), RunE: runOrgAvailability,
}

type cliOrganization struct {
	ID        string `json:"id"`
	Slug      string `json:"slug"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

func init() {
	orgCreateCmd.Flags().StringVar(&orgDisplayName, "name", "", "Optional organization display name")
	orgCmd.AddCommand(orgCreateCmd, orgListCmd, orgAvailabilityCmd)
	rootCmd.AddCommand(orgCmd)
	for _, cmd := range []*cobra.Command{orgCreateCmd, orgListCmd, orgAvailabilityCmd} {
		identityHomeNeutralCommandExemptions[cmd] = struct{}{}
	}
}

func requireOrgCLIAuth(ctx context.Context) (cliAuthConfig, cliAuthAccount, error) {
	// Keep host-human authority separate from workspace identities. The shared
	// loader checks audience/client, refreshes that same token and checks account.
	cfg, account, err := requireCLIAuthForScope(ctx, cliAuthScopeOrgCreate, "aw auth login")
	if err != nil {
		var audience *cliAuthAudienceError
		if errors.As(err, &audience) && audience.RequiredScope == cliAuthScopeOrgCreate {
			return cliAuthConfig{}, cliAuthAccount{}, &cliAuthHTTPStatusError{
				StatusCode: 403, ErrorCode: "cli_auth_relogin_required",
				Detail: "This CLI authorization does not include cli.org_create; run aw auth login again.",
			}
		}
		return cliAuthConfig{}, cliAuthAccount{}, err
	}
	return cfg, account, nil
}

func orgCommandError(cmd *cobra.Command, err error) error {
	code, message, suggestion := cliAuthErrorCode(err), err.Error(), ""
	var status *cliAuthHTTPStatusError
	if errors.As(err, &status) {
		suggestion = status.Suggestion
		if status.Detail != "" {
			message = status.Detail
		}
	}
	if code == "org_slug_taken" {
		message = "Organization slug is unavailable; confirm another name before creating it."
	}
	if jsonFlag {
		if code == "" {
			code = "request_failed"
		}
		out := map[string]any{"code": code, "message": message}
		if status != nil {
			out["http_status"] = status.StatusCode
		}
		if suggestion != "" {
			out["suggestion"] = suggestion
		}
		if writeErr := json.NewEncoder(cmd.OutOrStdout()).Encode(out); writeErr != nil {
			return writeErr
		}
	}
	if suggestion != "" {
		message += " Suggested slug: " + suggestion
	}
	return usageError("%s: %s", firstNonEmptyString(code, "org_request_failed"), message)
}

func runOrgCreate(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
	cfg, _, err := requireOrgCLIAuth(ctx)
	cancel()
	if err != nil {
		return orgCommandError(cmd, err)
	}
	slug := strings.ToLower(strings.TrimSpace(args[0]))
	if slug == "" {
		return usageError("organization slug is required")
	}
	for {
		request := struct {
			Slug string `json:"slug"`
			Name string `json:"name,omitempty"`
		}{slug, strings.TrimSpace(orgDisplayName)}
		var out cliOrganization
		ctx, cancel = commandAPIContext(cmd)
		err = postCLIAuthJSON(ctx, cfg.Issuer, cliOrganizationsPath, cfg.AccessToken, request, &out)
		cancel()
		if err == nil {
			if out.ID == "" || out.Slug != slug || out.Namespace == "" {
				return orgCommandError(cmd, errors.New("organization response does not match the requested slug"))
			}
			if jsonFlag {
				return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "Organization: %s\nName: %s\nNamespace: %s\n", out.Slug, out.Name, out.Namespace)
			return err
		}
		var status *cliAuthHTTPStatusError
		if !errors.As(err, &status) || status.ErrorCode != "org_slug_taken" || status.Suggestion == "" || jsonFlag || !readerIsTerminal(cmd.InOrStdin()) {
			return orgCommandError(cmd, err)
		}
		choice, promptErr := promptStringWithIO("Slug unavailable. Confirm the suggestion or type another slug", status.Suggestion, cmd.InOrStdin(), cmd.ErrOrStderr())
		if promptErr != nil {
			return promptErr
		}
		slug = strings.ToLower(strings.TrimSpace(choice))
		if slug == "" {
			return orgCommandError(cmd, err)
		}
	}
}

func runOrgList(cmd *cobra.Command, _ []string) error {
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	cfg, _, err := requireOrgCLIAuth(ctx)
	if err != nil {
		return orgCommandError(cmd, err)
	}
	var out struct {
		Organizations []cliOrganization `json:"organizations"`
	}
	if err := getCLIAuthJSON(ctx, cfg.Issuer, cliOrganizationsPath, cfg.AccessToken, &out); err != nil {
		return orgCommandError(cmd, err)
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	for _, org := range out.Organizations {
		fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\n", org.Slug, org.Name, org.Namespace)
	}
	return nil
}

func runOrgAvailability(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	cfg, _, err := requireOrgCLIAuth(ctx)
	if err != nil {
		return orgCommandError(cmd, err)
	}
	var out struct {
		Available  bool    `json:"available"`
		Suggestion *string `json:"suggestion"`
	}
	path := cliOrganizationsPath + "/availability?slug=" + url.QueryEscape(strings.TrimSpace(args[0]))
	if err := getCLIAuthJSON(ctx, cfg.Issuer, path, cfg.AccessToken, &out); err != nil {
		return orgCommandError(cmd, err)
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Available: %t\n", out.Available)
	if out.Suggestion != nil {
		fmt.Fprintf(cmd.OutOrStdout(), "Suggestion: %s\n", *out.Suggestion)
	}
	return nil
}

// The human grants organization authority; the returned invitation grants a
// separate admission. This command never enrolls or substitutes an agent key.
func runOrgTeamCreate(cmd *cobra.Command, name string) error {
	org, _ := cmd.Flags().GetString("org")
	org, name = strings.TrimSpace(org), strings.ToLower(strings.TrimSpace(name))
	if org == "" || name == "" {
		return usageError("--org and a team name are required")
	}
	for _, incompatible := range []string{"byot", "namespace", "registry", "service", "first-agent-name", "first-agent-local", "first-agent-global", "alias", "username", "home", "runtime", "library-url", "agent", "profile", "blueprint", "team"} {
		if cmd.Flags().Changed(incompatible) {
			return usageError("--%s cannot be combined with --org; chosen-org creation returns an invite without creating a local workspace", incompatible)
		}
	}
	requestID, _ := cmd.Flags().GetString("request-id")
	requestID = strings.TrimSpace(requestID)
	if cmd.Flags().Changed("request-id") {
		if !regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(requestID) {
			return usageError("--request-id must be a UUID")
		}
	} else {
		var err error
		requestID, err = awid.GenerateUUID4()
		if err != nil {
			return err
		}
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	cfg, _, err := requireOrgCLIAuth(ctx)
	if err != nil {
		return orgCommandError(cmd, err)
	}
	displayName, _ := cmd.Flags().GetString("display-name")
	request := struct {
		Org         string `json:"org"`
		Name        string `json:"name"`
		DisplayName string `json:"display_name,omitempty"`
		RequestID   string `json:"request_id"`
	}{org, name, strings.TrimSpace(displayName), requestID}
	var out hostedSiblingOutput
	if err := postCLIAuthJSON(ctx, cfg.Issuer, "/api/v1/cli/teams", cfg.AccessToken, request, &out); err != nil {
		return orgCommandError(cmd, fmt.Errorf("team create (request_id=%s; replay with the same --request-id and parameters): %w", requestID, err))
	}
	domain, returnedName, parseErr := awid.ParseTeamID(out.CanonicalTeamID)
	if parseErr != nil || returnedName != name || domain != out.Namespace || out.TeamID == "" || out.ServerURL == "" || (!out.Reused && out.Token == "") {
		return orgCommandError(cmd, errors.New("hosted team response does not match the requested team"))
	}
	out.RequestID, out.ServiceTeamID, out.TeamID = requestID, out.TeamID, out.CanonicalTeamID
	if jsonFlag {
		// The existing sibling endpoint still requires token. Only this endpoint
		// supports a consumed-invite replay, which must omit it entirely.
		data, err := json.Marshal(out)
		if err != nil {
			return err
		}
		var result map[string]any
		if err := json.Unmarshal(data, &result); err != nil {
			return err
		}
		if out.Token == "" {
			delete(result, "token")
		}
		return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Team: %s\nService: %s\nRequest ID: %s\n", out.TeamID, out.ServerURL, requestID)
	if out.Token == "" {
		fmt.Fprintln(cmd.OutOrStdout(), "Team reused; invitation already consumed; no new admission.")
		return nil
	}
	showToken, _ := cmd.Flags().GetBool("show-token")
	if showToken {
		fmt.Fprintf(cmd.OutOrStdout(), "Token: %s\n", out.Token)
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "Invite token hidden; use --json or --show-token to print it.")
	}
	fmt.Fprintln(cmd.OutOrStdout(), "Caller is not enrolled. Accept the invite into a fresh identity home.")
	return nil
}
