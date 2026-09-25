package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const teamAdmissionInvitePathTemplate = "/api/v1/teams/{team_id}/admission-invite"

var (
	teamAdmissionInviteTeamID    string
	teamAdmissionInviteRequestID string
	teamAdmissionInviteAliasHint string
)

var teamAdmissionInviteCmd = &cobra.Command{
	Use:   "admission-invite --team-id <uuid-or-canonical-team-id> --request-id <uuid>",
	Short: "Issue a shared-team admission invite token",
	Long: "Issue a shared-team admission invite token.\n\n" +
		"This uses host CLI auth with scope cli.team_admission to request an ordinary\n" +
		"single-use aw_inv_ token for a chosen recipient. It does not accept the invite,\n" +
		"install membership, or bind this workspace; use aw team join or aw id team\n" +
		"accept-invite with the returned token in the target identity root.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTeamAdmissionInvite(cmd.Context(), cmd)
	},
}

type teamAdmissionInviteRequest struct {
	AliasHint        string `json:"alias_hint,omitempty"`
	RequestID        string `json:"request_id"`
	ExpiresInSeconds int    `json:"expires_in_seconds"`
}

type teamAdmissionInviteResponse struct {
	InviteID        string `json:"invite_id"`
	Token           string `json:"token"`
	TokenPrefix     string `json:"token_prefix"`
	MaxUses         int    `json:"max_uses"`
	ExpiresAt       string `json:"expires_at"`
	TeamID          string `json:"team_id"`
	CanonicalTeamID string `json:"canonical_team_id"`
	TeamSlug        string `json:"team_slug"`
	NamespaceSlug   string `json:"namespace_slug"`
	Namespace       string `json:"namespace"`
	ServerURL       string `json:"server_url"`
}

type teamAdmissionInviteOutput struct {
	InviteID        string `json:"invite_id"`
	Token           string `json:"token"`
	TokenPrefix     string `json:"token_prefix"`
	MaxUses         int    `json:"max_uses"`
	ExpiresAt       string `json:"expires_at"`
	TeamID          string `json:"team_id"`
	CanonicalTeamID string `json:"canonical_team_id,omitempty"`
	TeamSlug        string `json:"team_slug,omitempty"`
	NamespaceSlug   string `json:"namespace_slug,omitempty"`
	Namespace       string `json:"namespace,omitempty"`
	ServerURL       string `json:"server_url,omitempty"`
	JoinCommand     string `json:"join_command"`
}

func init() {
	teamAdmissionInviteCmd.Flags().StringVar(&teamAdmissionInviteTeamID, "team-id", "", "Cloud team UUID or canonical AWID team ID to issue an admission invite for")
	teamAdmissionInviteCmd.Flags().StringVar(&teamAdmissionInviteRequestID, "request-id", "", "Client-generated UUID for retry-safe issuance")
	teamAdmissionInviteCmd.Flags().StringVar(&teamAdmissionInviteAliasHint, "alias-hint", "", "Optional suggested member alias for the recipient")
	teamAdmissionInviteCmd.GroupID = teamGroupMembership
	teamHumanCmd.AddCommand(teamAdmissionInviteCmd)
	identityHomeNeutralCommandExemptions[teamAdmissionInviteCmd] = struct{}{}
}

func runTeamAdmissionInvite(ctx context.Context, cmd *cobra.Command) error {
	loadDotenvBestEffort()
	teamID := strings.TrimSpace(teamAdmissionInviteTeamID)
	if teamID == "" {
		return usageError("--team-id is required")
	}
	requestID := strings.TrimSpace(teamAdmissionInviteRequestID)
	if requestID == "" {
		return usageError("--request-id is required")
	}
	cfg, err := requireCLIAuthForScope(ctx, cliAuthScopeTeamAdmission, "aw auth login --scope "+cliAuthScopeTeamAdmission)
	if err != nil {
		return err
	}
	path := strings.Replace(teamAdmissionInvitePathTemplate, "{team_id}", url.PathEscape(teamID), 1)
	req := teamAdmissionInviteRequest{AliasHint: strings.TrimSpace(teamAdmissionInviteAliasHint), RequestID: requestID, ExpiresInSeconds: 600}
	var resp teamAdmissionInviteResponse
	if err := postCLIAuthJSON(ctx, cfg.Issuer, path, cfg.AccessToken, req, &resp); err != nil {
		return err
	}
	if strings.TrimSpace(resp.Token) == "" {
		return fmt.Errorf("team admission-invite response missing token")
	}
	if strings.TrimSpace(resp.InviteID) == "" {
		return fmt.Errorf("team admission-invite response missing invite_id")
	}
	if got := strings.TrimSpace(resp.TeamID); got != "" && got != teamID && strings.TrimSpace(resp.CanonicalTeamID) != teamID {
		return fmt.Errorf("team admission-invite response team_id %q and canonical_team_id %q do not match requested team reference %q", got, strings.TrimSpace(resp.CanonicalTeamID), teamID)
	}
	if resp.MaxUses != 0 && resp.MaxUses != 1 {
		return fmt.Errorf("team admission-invite response max_uses=%d, want 1", resp.MaxUses)
	}
	out := teamAdmissionInviteOutput{
		InviteID:        resp.InviteID,
		Token:           resp.Token,
		TokenPrefix:     resp.TokenPrefix,
		MaxUses:         resp.MaxUses,
		ExpiresAt:       resp.ExpiresAt,
		TeamID:          firstNonEmptyString(resp.TeamID, teamID),
		CanonicalTeamID: resp.CanonicalTeamID,
		TeamSlug:        resp.TeamSlug,
		NamespaceSlug:   resp.NamespaceSlug,
		Namespace:       resp.Namespace,
		ServerURL:       resp.ServerURL,
		JoinCommand:     "aw team join " + resp.Token + " --name <name>",
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "invite_id: %s\n", out.InviteID)
	fmt.Fprintf(cmd.OutOrStdout(), "token: %s\n", out.Token)
	fmt.Fprintf(cmd.OutOrStdout(), "join_command: %s\n", out.JoinCommand)
	if out.ExpiresAt != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "expires_at: %s\n", out.ExpiresAt)
	}
	if out.CanonicalTeamID != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "canonical_team_id: %s\n", out.CanonicalTeamID)
	}
	return nil
}

func requireCLIAuthForScope(ctx context.Context, scope, remedy string) (cliAuthConfig, error) {
	cfg, ok, err := loadCLIAuthConfigForScope(scope)
	if err != nil {
		return cliAuthConfig{}, err
	}
	if !ok || strings.TrimSpace(cfg.AccessToken) == "" {
		return cliAuthConfig{}, usageError("authorization-required: run `%s` before this command", remedy)
	}
	if cfg.ClientID != cliAuthClientID || strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Resource) == "" {
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth for %s is invalid; run `%s`", scope, remedy)
	}
	if err := validateStoredCLIAuthAudience(cfg, scope); err != nil {
		return cliAuthConfig{}, err
	}
	if time.Now().UTC().After(cfg.ExpiresAt) {
		refreshed, refreshErr := refreshCLIAuthToken(ctx, cfg)
		if refreshErr != nil {
			return cliAuthConfig{}, usageError("authorization-required: stored CLI auth for %s is expired or revoked; run `%s`", scope, remedy)
		}
		cfg = refreshed
		if err := saveCLIAuthConfigForScope(scope, cfg); err != nil {
			return cliAuthConfig{}, err
		}
	}
	status, err := requestCLIAuthServerStatus(ctx, cfg)
	if err != nil {
		return cliAuthConfig{}, err
	}
	if strings.TrimSpace(status.Status) != "" && strings.TrimSpace(status.Status) != "authorized" {
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth for %s is %s; run `%s`", scope, status.Status, remedy)
	}
	return cfg, nil
}
