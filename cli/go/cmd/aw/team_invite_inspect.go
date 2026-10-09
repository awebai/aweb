package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type inviteInspection struct {
	Kind            string  `json:"kind"`
	CanonicalTeamID string  `json:"canonical_team_id"`
	IdentityScope   string  `json:"identity_scope"`
	ServerURL       string  `json:"server_url"`
	ExpiresAt       *string `json:"expires_at,omitempty"`
	Status          string  `json:"status"`
}

// Hosted expiry is explicitly nullable; controller metadata has no expiry.
func (r inviteInspection) MarshalJSON() ([]byte, error) {
	type plain inviteInspection
	if r.Kind == "hosted" {
		return json.Marshal(struct {
			plain
			ExpiresAt *string `json:"expires_at"`
		}{plain(r), r.ExpiresAt})
	}
	return json.Marshal(plain(r))
}

var teamInviteInspectCmd = &cobra.Command{
	Use:   "inspect",
	Short: "Inspect an invite from stdin without redeeming it",
	Long: "Inspect one invite token from stdin through EOF (max 65536 bytes).\n\n" +
		"Token input is always stdin; --token-stdin makes that explicit. Never pass a token\n" +
		"as an argument. Hosted envelopes make one non-redeeming Cloud preview request.\n" +
		"Controller tokens are decoded locally without network or controller-store reads:\n" +
		"scope is unknown, status is unverified, and expiry/validity are not established.\n" +
		"Inspection creates no identity, membership or workspace. External identity homes\n" +
		"remain unsupported. Cloud must support /api/v1/spawn/invite-preview.",
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) != 0 {
			return reportInviteInspectError(cmd, nil, &inviteInspectError{"malformed_token", "Pass the invite token on stdin, not as an argument.", 2})
		}
		return nil
	},
	RunE: func(cmd *cobra.Command, args []string) error {
		token, err := readInspectToken(cmd.InOrStdin())
		if err != nil {
			return reportInviteInspectError(cmd, nil, err.(*inviteInspectError))
		}
		result, inspectErr := inspectInvite(cmd.Context(), token)
		if inspectErr != nil {
			return reportInviteInspectError(cmd, result, inspectErr)
		}
		if jsonFlag {
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		}
		return formatInviteInspection(cmd, result)
	},
}

func init() {
	teamInviteInspectCmd.Flags().Bool("token-stdin", false, "Read the token from stdin (the default)")
	teamInviteInspectCmd.SetFlagErrorFunc(func(cmd *cobra.Command, _ error) error {
		return reportInviteInspectError(cmd, nil, &inviteInspectError{"malformed_token", "Invalid inspect flags; use aw team invite inspect --help.", 2})
	})
	teamHumanInviteCmd.AddCommand(teamInviteInspectCmd)
}

func reportInviteInspectError(cmd *cobra.Command, result *inviteInspection, err *inviteInspectError) error {
	if jsonFlag {
		_ = json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
			Error  *inviteInspectError `json:"error"`
			Invite *inviteInspection   `json:"invite,omitempty"`
		}{err, result})
	} else if result != nil {
		_ = formatInviteInspection(cmd, result)
	}
	return err
}

func formatInviteInspection(cmd *cobra.Command, result *inviteInspection) error {
	_, err := fmt.Fprintf(cmd.OutOrStdout(), "Kind: %s\nTeam: %s\nIdentity scope: %s\nServer: %s\nStatus: %s\n", result.Kind, result.CanonicalTeamID, result.IdentityScope, result.ServerURL, result.Status)
	if result.Kind == "controller" {
		fmt.Fprintln(cmd.OutOrStdout(), "Locally decoded metadata only; scope, expiry and validity are unknown until acceptance.")
	} else {
		fmt.Fprintln(cmd.OutOrStdout(), "Status reported by the invite's service; no invite was redeemed. The unsigned envelope does not authenticate that service.")
	}
	return err
}

var inspectTeamName = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,127}$`)
var inspectTeamDomain = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,252}$`)

func inspectCanonicalTeam(domain, team string) (string, bool) {
	id := awid.BuildTeamID(domain, team)
	domain, team, err := awid.ParseTeamID(id)
	return id, err == nil && inspectTeamName.MatchString(team) && inspectTeamDomain.MatchString(domain)
}

func inspectInvite(ctx context.Context, token string) (*inviteInspection, *inviteInspectError) {
	if strings.HasPrefix(token, "aw_inv_") {
		envelope, err := decodeInspectHostedEnvelope(token)
		if err != nil {
			return nil, err.(*inviteInspectError)
		}
		return inspectHostedInvite(ctx, token, envelope)
	}
	decoded, err := decodeInspectControllerToken(token)
	if err != nil {
		return nil, err.(*inviteInspectError)
	}
	id, valid := inspectCanonicalTeam(decoded.Domain, decoded.TeamName)
	if !valid {
		return nil, malformedInspectToken()
	}
	result := &inviteInspection{Kind: "controller", CanonicalTeamID: id, IdentityScope: "unknown", ServerURL: decoded.AwebURL, Status: "unverified"}
	if inspectResultLeaks(result, token, decoded.Secret) {
		return nil, malformedInspectToken()
	}
	return result, nil
}

func inspectResultLeaks(result *inviteInspection, secrets ...string) bool {
	// Values are validated separately; even syntactically valid service metadata
	// must not echo the submitted capability or its secret.
	values := []string{result.Kind, result.CanonicalTeamID, result.IdentityScope, result.ServerURL, result.Status}
	if result.ExpiresAt != nil {
		values = append(values, *result.ExpiresAt)
	}
	for _, secret := range secrets {
		for _, value := range values {
			if secret != "" && strings.Contains(value, secret) {
				return true
			}
		}
	}
	return false
}

func inspectUnavailable() *inviteInspectError {
	return &inviteInspectError{"server_unreachable", "Invite preview is unavailable or returned an invalid response; the service must support invite preview. No invite was redeemed.", 1}
}

func inspectHostedInvite(ctx context.Context, token string, envelope hostedJoinTokenEnvelope) (*inviteInspection, *inviteInspectError) {
	body, _ := json.Marshal(struct {
		Token string `json:"token"`
	}{envelope.InnerToken})
	base := strings.TrimSuffix(envelope.AwebURL, "/api")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/api/v1/spawn/invite-preview", bytes.NewReader(body))
	if err != nil {
		return nil, inspectUnavailable()
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	transport := awid.NewAPITransport()
	defer transport.CloseIdleConnections()
	// Do not use identity clients or generic HTTP tracing: headers, URLs and
	// malformed bodies can all reflect secrets. This fixed trace is sufficient
	// to show the sole request and its status without logging token-derived data.
	trace := traceFlag || os.Getenv("AW_TRACE") == "1"
	if trace {
		fmt.Fprintln(os.Stderr, "AW TRACE invite preview: POST /api/v1/spawn/invite-preview (credentials and response omitted)")
	}
	resp, err := awid.DoNoRedirect(&http.Client{Timeout: 15 * time.Second, Transport: transport}, req)
	if err != nil {
		return nil, inspectUnavailable()
	}
	defer resp.Body.Close()
	if trace {
		fmt.Fprintf(os.Stderr, "AW TRACE invite preview: HTTP %d\n", resp.StatusCode)
	}
	if resp.StatusCode == http.StatusNotFound {
		return nil, &inviteInspectError{"unknown_or_invalid", "Invite is unknown or invalid, or this service does not support invite preview.", 1}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, inspectUnavailable()
	}
	data, err := awid.ReadAllBounded(resp.Body, 64*1024)
	if err != nil {
		return nil, inspectUnavailable()
	}
	// Separate the wire response so a service cannot overwrite Kind.
	var wire struct {
		CanonicalTeamID string  `json:"canonical_team_id"`
		IdentityScope   string  `json:"identity_scope"`
		ServerURL       string  `json:"server_url"`
		ExpiresAt       *string `json:"expires_at"`
		Status          string  `json:"status"`
	}
	if json.Unmarshal(data, &wire) != nil {
		return nil, inspectUnavailable()
	}
	domain, team, err := awid.ParseTeamID(wire.CanonicalTeamID)
	id, valid := inspectCanonicalTeam(domain, team)
	if err != nil || !valid || id != wire.CanonicalTeamID || (wire.IdentityScope != "local" && wire.IdentityScope != "global") {
		return nil, inspectUnavailable()
	}
	server, err := inspectServiceURL(wire.ServerURL)
	if err != nil {
		return nil, inspectUnavailable()
	}
	if server != envelope.AwebURL {
		return nil, &inviteInspectError{"server_mismatch", "Invite preview service does not match the invite envelope; no second request was made.", 1}
	}
	if wire.ExpiresAt != nil {
		if _, err := time.Parse(time.RFC3339Nano, *wire.ExpiresAt); err != nil {
			return nil, inspectUnavailable()
		}
	}
	result := &inviteInspection{"hosted", id, wire.IdentityScope, server, wire.ExpiresAt, wire.Status}
	if inspectResultLeaks(result, token, envelope.InnerToken, strings.TrimPrefix(envelope.InnerToken, "aw_inv_")) {
		return nil, inspectUnavailable()
	}
	switch wire.Status {
	case "active":
		return result, nil
	case "expired", "exhausted", "revoked":
		return result, &inviteInspectError{wire.Status, "Invite is " + wire.Status + "; request a new invite. No invite was redeemed.", 1}
	default:
		return nil, inspectUnavailable()
	}
}

// Inspection retains normal identity-home admission, but must not acquire
// incidental network or state-writing side effects from command hooks.
func isTeamInviteInspectCommand(cmd *cobra.Command) bool {
	return cmd != nil && cmd.CommandPath() == "aw team invite inspect"
}
