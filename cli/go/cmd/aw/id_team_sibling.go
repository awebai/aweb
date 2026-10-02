package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type hostedSiblingRequest struct {
	RequestID    string `json:"request_id"`
	Name         string `json:"name"`
	DisplayName  string `json:"display_name,omitempty"`
	SourceTeamID string `json:"source_team_id,omitempty"`
}

type hostedSiblingOutput struct {
	RequestID       string `json:"request_id"`
	TeamID          string `json:"team_id"`
	ServiceTeamID   string `json:"service_team_id,omitempty"`
	CanonicalTeamID string `json:"canonical_team_id"`
	Namespace       string `json:"namespace"`
	OrgHandle       string `json:"org_handle"`
	Reused          bool   `json:"reused"`
	Token           string `json:"token"`
	InviteID        string `json:"invite_id"`
	TokenPrefix     string `json:"token_prefix"`
	ExpiresAt       string `json:"expires_at"`
	MaxUses         int    `json:"max_uses"`
	ServerURL       string `json:"server_url"`
}

func runHostedTeamCreate(cmd *cobra.Command, name, domain string) error {
	if strings.TrimSpace(teamCreateRegistryURL) != "" {
		return usageError("--registry is a BYOT option; hosted creation uses the selected team's service")
	}
	requestID := strings.TrimSpace(teamCreateRequestID)
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
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if awconfig.IsGrantHome(home.Root) {
		return usageError("team_key_required: hosted sibling creation requires a native team certificate; session grants are not accepted")
	}
	sel, err := resolveSelectionForDir(wd)
	if err != nil {
		return err
	}
	if err := checkIdentityMismatchAtIdentityHome(wd, home.Root, sel); err != nil {
		return err
	}
	sourceDomain, _, err := awid.ParseTeamID(sel.TeamID)
	if err != nil {
		return err
	}
	if domain != "" && domain != sourceDomain {
		return usageError("--namespace %q does not match selected source team %q", domain, sel.TeamID)
	}
	// Use the selected service directly: discovery/fallback can replay a POST on
	// 404 and persist a different URL. Sibling creation has no automatic retries.
	baseURL, err := cleanBaseURL(sel.BaseURL)
	if err != nil {
		return err
	}
	client, err := resolveCertificateClient(sel, baseURL)
	if err != nil {
		return err
	}
	if client == nil {
		return usageError("team_key_required: selected identity has no team certificate")
	}
	if client.TeamID() != sel.TeamID {
		return usageError("source_team_mismatch: selected team and certificate do not match")
	}
	req := hostedSiblingRequest{RequestID: requestID, Name: name, DisplayName: strings.TrimSpace(teamCreateDisplayName), SourceTeamID: strings.TrimSpace(teamFlag)}
	ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
	defer cancel()
	// Show the selected service without echoing any URL userinfo.
	displayURL, _ := url.Parse(baseURL) // cleanBaseURL already validated it.
	displayURL.User = nil
	fmt.Fprintf(cmd.ErrOrStderr(), "hosted sibling via %s\n", displayURL.String())
	var out hostedSiblingOutput
	if err := client.Post(ctx, "/api/v1/teams/sibling", req, &out); err != nil {
		return fmt.Errorf("hosted team create (request_id=%s; replay with the same --request-id and parameters): %w", requestID, err)
	}
	out.RequestID = requestID
	// CLI team identifiers are canonical, as in the existing BYOT output.
	// Preserve the service-specific ID separately from the wire response.
	out.ServiceTeamID = out.TeamID
	out.TeamID = out.CanonicalTeamID
	printOutput(out, func(v any) string {
		result := v.(hostedSiblingOutput)
		status := "created"
		if result.Reused {
			status = "reused"
		}
		text := fmt.Sprintf("Status:      %s\nTeam:        %s\nService:     %s\nRequest ID:  %s\nInvite:      %s (expires %s)\n", status, result.CanonicalTeamID, result.ServerURL, result.RequestID, result.InviteID, result.ExpiresAt)
		if teamCreateShowToken {
			text += fmt.Sprintf("Token:       %s\n", result.Token)
		} else {
			text += "Invite token hidden; use --json or --show-token to print it.\n"
		}
		return text + "Caller is not enrolled. Accept the invite into a fresh identity home.\n"
	})
	return nil
}
