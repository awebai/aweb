package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw id team set-server / show-server publish and read the team's
// aweb.team-server/1 record at AWID. The record binds the team to its
// coordination server and is signed by the team controller key, so naapps can
// discover the server from AWID instead of trusting configuration or a hosted
// default. Any command that rotates the team key must re-sign and publish the
// record in the same operation.

type teamServerOutput struct {
	Status      string `json:"status"`
	TeamID      string `json:"team_id"`
	ServerURL   string `json:"server_url"`
	Audience    string `json:"audience"`
	IssuedAt    string `json:"issued_at"`
	TeamDIDKey  string `json:"team_did_key"`
	RegistryURL string `json:"registry_url"`
}

type teamServerOptions struct {
	Domain      string
	Team        string
	ServerURL   string
	RegistryURL string
	Now         func() time.Time
}

var (
	teamSetServerTeam        string
	teamSetServerNamespace   string
	teamSetServerURL         string
	teamSetServerRegistryURL string
	teamShowServerTeam       string
	teamShowServerNamespace  string
	teamShowServerRegistry   string

	teamSetServerCmd = &cobra.Command{
		Use:   "set-server",
		Short: "Publish the team's coordination server at AWID, signed by the team controller key",
		Long: "Publish the team's aweb.team-server/1 record at AWID: the coordination server\n" +
			"URL that installed apps use for this team, signed by the local team controller key.\n\n" +
			"The record must be newer than the published one; republishing the same record is\n" +
			"accepted unchanged. After a team key rotation, publish again with the new key.",
		RunE: runTeamSetServer,
	}
	teamShowServerCmd = &cobra.Command{
		Use:   "show-server",
		Short: "Show and verify the team's published coordination server",
		Long: "Read the team's aweb.team-server/1 record from AWID and verify it against the\n" +
			"team's current key. A record signed by any other key is refused.",
		RunE: runTeamShowServer,
	}
)

func init() {
	teamSetServerCmd.Flags().StringVar(&teamSetServerTeam, "team", "", "Team name")
	teamSetServerCmd.Flags().StringVar(&teamSetServerNamespace, "namespace", "", "Namespace domain")
	teamSetServerCmd.Flags().StringVar(&teamSetServerURL, "url", "", "Coordination server URL (https origin with optional path prefix)")
	teamSetServerCmd.Flags().StringVar(&teamSetServerRegistryURL, "registry", "", "Registry origin override")
	teamCmd.AddCommand(teamSetServerCmd)

	teamShowServerCmd.Flags().StringVar(&teamShowServerTeam, "team", "", "Team name")
	teamShowServerCmd.Flags().StringVar(&teamShowServerNamespace, "namespace", "", "Namespace domain")
	teamShowServerCmd.Flags().StringVar(&teamShowServerRegistry, "registry", "", "Registry origin override")
	teamCmd.AddCommand(teamShowServerCmd)
}

func runTeamSetServer(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	out, err := executeTeamSetServer(ctx, teamServerOptions{
		Domain:      teamSetServerNamespace,
		Team:        teamSetServerTeam,
		ServerURL:   teamSetServerURL,
		RegistryURL: teamSetServerRegistryURL,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatTeamServer)
	return nil
}

func runTeamShowServer(cmd *cobra.Command, args []string) error {
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	out, err := executeTeamShowServer(ctx, teamServerOptions{
		Domain:      teamShowServerNamespace,
		Team:        teamShowServerTeam,
		RegistryURL: teamShowServerRegistry,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatTeamServer)
	return nil
}

func teamServerTarget(ctx context.Context, opts teamServerOptions) (*awid.RegistryClient, string, string, string, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return nil, "", "", "", err
	}
	teamName := strings.ToLower(strings.TrimSpace(opts.Team))
	if teamName == "" {
		return nil, "", "", "", usageError("--team is required")
	}
	if strings.Contains(teamName, "/") || strings.Contains(teamName, ":") {
		return nil, "", "", "", usageError("--team must be a team name, not a full team id")
	}
	registry, err := newRegistryClientWithPreferredBaseURL(opts.RegistryURL)
	if err != nil {
		return nil, "", "", "", err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return nil, "", "", "", fmt.Errorf("discover registry for %s: %w", domain, err)
	}
	return registry, registryURL, domain, teamName, nil
}

func teamServerNow(opts teamServerOptions) time.Time {
	if opts.Now != nil {
		return opts.Now().UTC()
	}
	return time.Now().UTC()
}

// teamServerRegistryDetail is AWID's string detail for a refused request, or "".
func teamServerRegistryDetail(err error) string {
	var regErr *awid.RegistryError
	if !errors.As(err, &regErr) {
		return ""
	}
	var body struct {
		Detail string `json:"detail"`
	}
	if json.Unmarshal([]byte(regErr.Detail), &body) == nil {
		return body.Detail
	}
	return strings.TrimSpace(regErr.Detail)
}

func executeTeamSetServer(ctx context.Context, opts teamServerOptions) (teamServerOutput, error) {
	registry, registryURL, domain, teamName, err := teamServerTarget(ctx, opts)
	if err != nil {
		return teamServerOutput{}, err
	}
	teamID := awid.BuildTeamID(domain, teamName)
	serverURL, _, err := awid.CanonicalTeamServerURL(strings.TrimSpace(opts.ServerURL))
	if err != nil {
		return teamServerOutput{}, usageError("--url: %v", err)
	}
	teamKey, err := awconfig.LoadTeamKey(domain, teamName)
	if err != nil {
		return teamServerOutput{}, teamKeyLoadError(teamID, domain, err)
	}
	team, err := registry.GetTeam(ctx, registryURL, domain, teamName, teamKey)
	if err != nil {
		if friendly := friendlyTeamReadError(err, teamID, true); friendly != err {
			return teamServerOutput{}, friendly
		}
		return teamServerOutput{}, fmt.Errorf("load AWID team %s: %w", teamID, err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	if strings.TrimSpace(team.TeamDIDKey) != teamDIDKey {
		return teamServerOutput{}, fmt.Errorf("local team controller key does not match AWID team controller for %s (local=%s, awid=%s)", teamID, teamDIDKey, team.TeamDIDKey)
	}

	now := teamServerNow(opts)
	record := awid.NewTeamServerRecord(teamID, teamDIDKey, serverURL, now)
	signature, err := awid.SignTeamServerRecord(teamKey, record)
	if err != nil {
		return teamServerOutput{}, err
	}
	verified, err := awid.VerifyTeamServerRecord(record, signature, teamID, teamDIDKey, now)
	if err != nil {
		return teamServerOutput{}, fmt.Errorf("team server record for %s does not verify locally: %w", teamID, err)
	}
	if _, err := registry.PublishTeamServerRecord(ctx, registryURL, domain, teamName, record, signature); err != nil {
		code, _ := registryStatusCode(err)
		switch detail := teamServerRegistryDetail(err); {
		case code == http.StatusConflict && detail == "not_newer":
			return teamServerOutput{}, fmt.Errorf("publish team server for %s: AWID already holds a record at least as new; retry after its issued_at (not_newer): %w", teamID, err)
		case code == http.StatusUnprocessableEntity && detail != "":
			return teamServerOutput{}, fmt.Errorf("publish team server for %s: AWID refused the record (%s): %w", teamID, detail, err)
		case code == http.StatusNotFound:
			return teamServerOutput{}, fmt.Errorf("publish team server for %s: AWID did not accept the record for this team's current key: %w", teamID, err)
		}
		return teamServerOutput{}, fmt.Errorf("publish team server for %s: %w", teamID, err)
	}
	return teamServerOutput{
		Status:      "published",
		TeamID:      teamID,
		ServerURL:   verified.ServerURL,
		Audience:    verified.Audience,
		IssuedAt:    record["issued_at"].(string),
		TeamDIDKey:  teamDIDKey,
		RegistryURL: registryURL,
	}, nil
}

func executeTeamShowServer(ctx context.Context, opts teamServerOptions) (teamServerOutput, error) {
	registry, registryURL, domain, teamName, err := teamServerTarget(ctx, opts)
	if err != nil {
		return teamServerOutput{}, err
	}
	teamID := awid.BuildTeamID(domain, teamName)
	stored, err := registry.GetTeamServerRecord(ctx, registryURL, domain, teamName)
	if err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
			return teamServerOutput{}, fmt.Errorf("no team server record is published for %s", teamID)
		}
		return teamServerOutput{}, fmt.Errorf("read team server for %s: %w", teamID, err)
	}
	// A private team's current key is readable with the local team key; a
	// public team's anonymously.
	var readKey ed25519.PrivateKey
	if teamKey, err := awconfig.LoadTeamKey(domain, teamName); err == nil {
		readKey = teamKey
	}
	team, err := registry.GetTeam(ctx, registryURL, domain, teamName, readKey)
	if err != nil {
		if friendly := friendlyTeamReadError(err, teamID, readKey != nil); friendly != err {
			return teamServerOutput{}, friendly
		}
		return teamServerOutput{}, fmt.Errorf("load AWID team %s: %w", teamID, err)
	}
	verified, err := awid.VerifyTeamServerRecord(stored.Record, stored.Signature, teamID, strings.TrimSpace(team.TeamDIDKey), teamServerNow(opts))
	if err != nil {
		return teamServerOutput{}, fmt.Errorf("team server record for %s does not verify: %w", teamID, err)
	}
	return teamServerOutput{
		Status:      "verified",
		TeamID:      teamID,
		ServerURL:   verified.ServerURL,
		Audience:    verified.Audience,
		IssuedAt:    verified.IssuedAt.UTC().Format("2006-01-02T15:04:05Z"),
		TeamDIDKey:  verified.TeamDIDKey,
		RegistryURL: registryURL,
	}, nil
}

func formatTeamServer(v any) string {
	out := v.(teamServerOutput)
	var b strings.Builder
	switch out.Status {
	case "published":
		fmt.Fprintf(&b, "Published team server for %s\n", out.TeamID)
	default:
		fmt.Fprintf(&b, "Team server for %s (verified)\n", out.TeamID)
	}
	fmt.Fprintf(&b, "  server:     %s\n", out.ServerURL)
	fmt.Fprintf(&b, "  audience:   %s\n", out.Audience)
	fmt.Fprintf(&b, "  issued at:  %s\n", out.IssuedAt)
	fmt.Fprintf(&b, "  team key:   %s\n", out.TeamDIDKey)
	fmt.Fprintf(&b, "  registry:   %s\n", out.RegistryURL)
	return b.String()
}
