package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var grantCmd = &cobra.Command{
	Use:   "grant",
	Short: "Scoped, expiring session grants derived from this identity",
}

var (
	grantMintScopes        []string
	grantMintBundles       []string
	grantMintAppTools      []string
	grantMintCustodySocket string
	grantMintTTL           time.Duration
	grantMintLabel         string
	grantMintOut           string
)

const (
	identityGrantMinTTL = 60 * time.Second
	identityGrantMaxTTL = 2592000 * time.Second
)

var grantScopeBundles = map[string][]string{
	"normal-agent": {
		"mail.read", "mail.send",
		"chat.read", "chat.send",
		"events.read", "coord.read", "coord.write", "presence.write",
		"contacts.read", "contacts.write",
	},
}

// errGrantHomeRootAuthority is returned when a command that needs the
// identity's root authority runs against a grant home.
var errGrantHomeRootAuthority = usageError("this is a grant home; run from the identity's own .aw home")

type grantMintOutput struct {
	GrantID           string `json:"grant_id"`
	ExpiresAt         string `json:"expires_at"`
	TeamID            string `json:"team_id"`
	Alias             string `json:"alias,omitempty"`
	Address           string `json:"address,omitempty"`
	Out               string `json:"out"`
	CustodySocketPath string `json:"custody_socket_path,omitempty"`
}

// activeGrantHome loads the grant home the current identity-home resolution
// points at, or reports false when the identity home is not a grant home.
func activeGrantHome() (*awconfig.GrantHome, bool) {
	wd, _ := os.Getwd()
	home, err := identityHomeForDir(wd)
	if err != nil || !awconfig.IsGrantHome(home.Root) {
		return nil, false
	}
	grant, err := awconfig.LoadGrantHome(home.Root)
	if err != nil {
		return nil, false
	}
	return grant, true
}

// requireGrantAuthorityHome refuses grant subcommands from a grant home: they
// all need the identity's root team-certificate authority.
func requireGrantAuthorityHome() error {
	wd, _ := os.Getwd()
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if awconfig.IsGrantHome(home.Root) {
		return errGrantHomeRootAuthority
	}
	return nil
}

// resolveGrantClientSelection builds a grant-authenticated client from a grant
// home so mail and chat commands work unchanged for the grant's subject.
func resolveGrantClientSelection(workingDir string, home awconfig.IdentityHome) (*aweb.Client, *awconfig.Selection, error) {
	grant, err := awconfig.LoadGrantHome(home.Root)
	if err != nil {
		return nil, nil, err
	}
	if requestedTeam := strings.TrimSpace(teamFlag); requestedTeam != "" && requestedTeam != strings.TrimSpace(grant.TeamID) {
		return nil, nil, usageError("grant home is bound to team %s; --team %s conflicts", strings.TrimSpace(grant.TeamID), requestedTeam)
	}
	if expires, ok := parseTimeBestEffort(grant.ExpiresAt); ok && time.Now().After(expires) {
		return nil, nil, fmt.Errorf("identity grant %s expired at %s; mint a new grant from the identity's own .aw home", grant.GrantID, grant.ExpiresAt)
	}
	sessionKeyPath := awconfig.GrantHomeSigningKeyPath(home.Root)
	sessionKey, err := awid.LoadSigningKey(sessionKeyPath)
	if err != nil {
		return nil, nil, fmt.Errorf("load grant session key: %w", err)
	}
	baseURL, err := resolveAuthenticatedBaseURL(grant.AwebURL)
	if err != nil {
		return nil, nil, err
	}

	address := strings.TrimSpace(grant.Subject.Address)
	domain := ""
	if authority, _, ok := awconfig.CutIdentityAddress(address); ok {
		domain = authority
	}
	sel := &awconfig.Selection{
		WorkingDir:           strings.TrimSpace(workingDir),
		IdentityHome:         home.Root,
		ExternalIdentityHome: home.External(),
		BaseURL:              baseURL,
		AwebURL:              strings.TrimSpace(grant.AwebURL),
		TeamID:               strings.TrimSpace(grant.TeamID),
		Alias:                strings.TrimSpace(grant.Subject.Alias),
		Address:              address,
		Domain:               domain,
		DID:                  strings.TrimSpace(grant.Subject.DIDKey),
		StableID:             strings.TrimSpace(grant.Subject.DIDAW),
		SigningKey:           sessionKeyPath,
	}

	c, err := aweb.NewWithGrant(baseURL, sessionKey, grant.GrantID)
	if err != nil {
		return nil, nil, err
	}
	c.SetGrantSubject(sel.TeamID, sel.StableID, sel.DID, sel.Address, sel.Alias)
	if socketPath := strings.TrimSpace(grant.Custody.SocketPath); socketPath != "" {
		c.SetPlainMessageSigner(&awid.UnixCustodyClient{SocketPath: socketPath})
	}
	if err := configureResolvedClient(c, sel, baseURL); err != nil {
		return nil, nil, err
	}

	lastClient = c
	return c, sel, nil
}

func parseGrantScopes(values []string) ([]string, error) {
	return parseGrantScopesWithBundles(values, nil)
}

func parseGrantScopesWithBundles(values []string, bundles []string) ([]string, error) {
	scopes := make([]string, 0, len(values)+len(bundles))
	seen := make(map[string]struct{}, len(values)+len(bundles))
	add := func(scope string) {
		scope = strings.TrimSpace(scope)
		if scope == "" {
			return
		}
		if _, ok := seen[scope]; ok {
			return
		}
		seen[scope] = struct{}{}
		scopes = append(scopes, scope)
	}
	for _, bundleValue := range bundles {
		for _, bundle := range strings.Split(bundleValue, ",") {
			bundle = strings.TrimSpace(bundle)
			if bundle == "" {
				continue
			}
			bundleScopes, ok := grantScopeBundles[bundle]
			if !ok {
				return nil, usageError("unknown grant scope bundle %q (known: normal-agent)", bundle)
			}
			for _, scope := range bundleScopes {
				add(scope)
			}
		}
	}
	for _, value := range values {
		for _, scope := range strings.Split(value, ",") {
			add(scope)
		}
	}
	if len(scopes) == 0 {
		return nil, usageError("--scope or --bundle is required (e.g. --bundle normal-agent or --scope mail.read,mail.send)")
	}
	return scopes, nil
}

// prepareGrantHomeDir validates and creates the mint output directory. A grant
// home is always created fresh: an existing non-empty directory (including any
// existing .aw home) is refused rather than overwritten.
func prepareGrantHomeDir(out string) (string, error) {
	out = strings.TrimSpace(out)
	if out == "" {
		return "", usageError("--out is required")
	}
	abs, err := filepath.Abs(out)
	if err != nil {
		return "", err
	}
	abs = filepath.Clean(abs)
	if info, statErr := os.Stat(abs); statErr == nil {
		if !info.IsDir() {
			return "", usageError("--out %s exists and is not a directory", abs)
		}
		entries, readErr := os.ReadDir(abs)
		if readErr != nil {
			return "", readErr
		}
		if len(entries) > 0 {
			return "", usageError("--out %s is not empty; grant homes must be created fresh", abs)
		}
		return abs, nil
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return "", statErr
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return "", err
	}
	return abs, nil
}

func resolveGrantMintCustodySocket(identityHome awconfig.IdentityHome) (string, error) {
	value := strings.TrimSpace(grantMintCustodySocket)
	if value == "" {
		return "", nil
	}
	var path string
	if strings.EqualFold(value, "auto") {
		if strings.TrimSpace(identityHome.Root) == "" {
			return "", usageError("--custody-socket auto requires a resident identity home")
		}
		path = awconfig.CustodySocketPath(identityHome.Root)
	} else {
		if !filepath.IsAbs(value) {
			return "", usageError("--custody-socket must be an absolute Unix socket path or auto")
		}
		path = filepath.Clean(value)
	}
	if err := validateCustodySocketPathLength(path); err != nil {
		return "", err
	}
	return path, nil
}

func runGrantMint(cmd *cobra.Command, _ []string) error {
	if err := requireGrantAuthorityHome(); err != nil {
		return err
	}
	scopes, err := parseGrantScopesWithBundles(grantMintScopes, grantMintBundles)
	if err != nil {
		return err
	}
	if grantMintTTL < identityGrantMinTTL || grantMintTTL > identityGrantMaxTTL {
		return usageError("--ttl must be between %s and %s", identityGrantMinTTL, identityGrantMaxTTL)
	}
	outDir, err := prepareGrantHomeDir(grantMintOut)
	if err != nil {
		return err
	}
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}
	residentIdentityHome, err := identityHomeForDir(mustGetwd())
	if err != nil {
		return err
	}
	custodySocketPath, err := resolveGrantMintCustodySocket(residentIdentityHome)
	if err != nil {
		return err
	}
	appSpecs, err := parseGrantAppToolSpecs(grantMintAppTools)
	if err != nil {
		return err
	}
	appSnapshots, err := buildGrantAppSnapshots(appSpecs, grantAppDeniedOrigins(sel.BaseURL, sel.RegistryURL))
	if err != nil {
		return err
	}
	residentHome := ""
	if len(appSnapshots) > 0 {
		residentHome = residentIdentityHome.Root
	}

	pub, sessionKey, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	grantDIDKey := awid.ComputeDIDKey(pub)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	view, err := client.MintIdentityGrant(ctx, &aweb.IdentityGrantMintRequest{
		GrantDIDKey: grantDIDKey,
		Scopes:      scopes,
		TTLSeconds:  int(grantMintTTL / time.Second),
		Label:       strings.TrimSpace(grantMintLabel),
	})
	if err != nil {
		return err
	}

	if len(appSnapshots) > 0 {
		snap := &grantAppToolsSnapshot{
			Version: grantAppToolsSnapshotVersion,
			GrantID: strings.TrimSpace(view.GrantID),
			TeamID:  firstNonEmpty(strings.TrimSpace(view.TeamID), strings.TrimSpace(sel.TeamID)),
			Apps:    appSnapshots,
		}
		if err := saveGrantAppToolsSnapshot(residentHome, snap); err != nil {
			revokeCtx, revokeCancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer revokeCancel()
			if revokeErr := client.RevokeIdentityGrant(revokeCtx, snap.GrantID); revokeErr != nil {
				return fmt.Errorf("record app tool policy for grant %s: %w (revoking the grant also failed: %v; revoke it manually)", snap.GrantID, err, revokeErr)
			}
			return fmt.Errorf("record app tool policy for grant %s: %w (grant revoked)", snap.GrantID, err)
		}
	}

	grantedScopes := view.Scopes
	if len(grantedScopes) == 0 {
		grantedScopes = scopes
	}
	state := &awconfig.GrantHome{
		Version: awconfig.GrantHomeSchemaVersion,
		GrantID: strings.TrimSpace(view.GrantID),
		TeamID:  firstNonEmpty(strings.TrimSpace(view.TeamID), strings.TrimSpace(sel.TeamID)),
		Subject: awconfig.GrantSubject{
			DIDAW:   firstNonEmpty(strings.TrimSpace(view.SubjectDIDAW), strings.TrimSpace(sel.StableID)),
			DIDKey:  strings.TrimSpace(sel.DID),
			Address: selectionAddress(sel),
			Alias:   firstNonEmpty(strings.TrimSpace(view.SubjectAlias), strings.TrimSpace(sel.Alias)),
		},
		Scopes:    grantedScopes,
		ExpiresAt: strings.TrimSpace(view.ExpiresAt),
		AwebURL:   sel.BaseURL,
		MintedAt:  firstNonEmpty(strings.TrimSpace(view.IssuedAt), time.Now().UTC().Format(time.RFC3339)),
	}
	if custodySocketPath != "" {
		state.Custody.SocketPath = custodySocketPath
	}
	// The session key lands first: a directory only becomes a detectable grant
	// home (grant.yaml present) once its credential is already on disk.
	if err := awid.SaveSigningKeyExclusive(awconfig.GrantHomeSigningKeyPath(outDir), sessionKey); err != nil {
		return err
	}
	if err := awconfig.SaveGrantHomeTo(awconfig.GrantHomeStatePath(outDir), state); err != nil {
		return err
	}

	out := grantMintOutput{
		GrantID:           state.GrantID,
		ExpiresAt:         state.ExpiresAt,
		TeamID:            state.TeamID,
		Alias:             state.Subject.Alias,
		Address:           state.Subject.Address,
		Out:               outDir,
		CustodySocketPath: state.Custody.SocketPath,
	}
	printOutput(out, func(any) string {
		text := fmt.Sprintf("Minted grant %s for %s (team %s), expires %s.\nGrant home: %s\n",
			out.GrantID, firstNonEmpty(out.Address, out.Alias), out.TeamID, out.ExpiresAt, out.Out)
		if out.CustodySocketPath != "" {
			text += fmt.Sprintf("Custody socket: %s\n", out.CustodySocketPath)
		}
		return text
	})
	return nil
}

func runGrantList(cmd *cobra.Command, _ []string) error {
	if err := requireGrantAuthorityHome(); err != nil {
		return err
	}
	client, err := resolveClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.ListIdentityGrants(ctx)
	if err != nil {
		return err
	}
	printOutput(resp, formatIdentityGrants)
	return nil
}

func runGrantRevoke(cmd *cobra.Command, args []string) error {
	if err := requireGrantAuthorityHome(); err != nil {
		return err
	}
	grantID := strings.TrimSpace(args[0])
	if grantID == "" {
		return usageError("grant id is required")
	}
	client, err := resolveClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := client.RevokeIdentityGrant(ctx, grantID); err != nil {
		return err
	}
	printOutput(map[string]string{"status": "revoked", "grant_id": grantID}, func(any) string {
		return fmt.Sprintf("Revoked identity grant %s.\n", grantID)
	})
	return nil
}

func runGrantShow(cmd *cobra.Command, args []string) error {
	if err := requireGrantAuthorityHome(); err != nil {
		return err
	}
	grantID := strings.TrimSpace(args[0])
	if grantID == "" {
		return usageError("grant id is required")
	}
	client, err := resolveClient()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	resp, err := client.ListIdentityGrants(ctx)
	if err != nil {
		return err
	}
	for i := range resp.Grants {
		if strings.TrimSpace(resp.Grants[i].GrantID) == grantID {
			printOutput(&resp.Grants[i], formatIdentityGrant)
			return nil
		}
	}
	return fmt.Errorf("identity grant not found: %s", grantID)
}

func formatIdentityGrant(v any) string {
	grant := v.(*aweb.IdentityGrantView)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Grant:     %s\n", grant.GrantID))
	if grant.Status != "" {
		sb.WriteString(fmt.Sprintf("Status:    %s\n", grant.Status))
	}
	if grant.Label != "" {
		sb.WriteString(fmt.Sprintf("Label:     %s\n", grant.Label))
	}
	sb.WriteString(fmt.Sprintf("Team:      %s\n", grant.TeamID))
	if grant.SubjectAlias != "" {
		sb.WriteString(fmt.Sprintf("Subject:   %s\n", grant.SubjectAlias))
	}
	if grant.SubjectDIDAW != "" {
		sb.WriteString(fmt.Sprintf("Stable ID: %s\n", grant.SubjectDIDAW))
	}
	if grant.GrantDIDKey != "" {
		sb.WriteString(fmt.Sprintf("Session:   %s\n", grant.GrantDIDKey))
	}
	sb.WriteString(fmt.Sprintf("Scopes:    %s\n", strings.Join(grant.Scopes, ", ")))
	if grant.IssuedAt != "" {
		sb.WriteString(fmt.Sprintf("Issued:    %s\n", grant.IssuedAt))
	}
	sb.WriteString(fmt.Sprintf("Expires:   %s\n", grant.ExpiresAt))
	return sb.String()
}

func formatIdentityGrants(v any) string {
	resp := v.(*aweb.IdentityGrantListResponse)
	if len(resp.Grants) == 0 {
		return "No identity grants.\n"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("GRANTS: %d\n", len(resp.Grants)))
	for _, grant := range resp.Grants {
		line := fmt.Sprintf("  %s  %s  scopes=%s  expires=%s", grant.GrantID, firstNonEmpty(grant.Status, "active"), strings.Join(grant.Scopes, ","), grant.ExpiresAt)
		if grant.Label != "" {
			line += fmt.Sprintf("  label=%s", grant.Label)
		}
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

func init() {
	mintCmd := &cobra.Command{
		Use:   "mint",
		Short: "Mint a session grant and write a self-contained grant home",
		RunE:  runGrantMint,
	}
	mintCmd.Flags().StringArrayVar(&grantMintScopes, "scope", nil, "Grant scope, repeatable or comma-separated (mail.read, mail.send, chat.read, chat.send, events.read, coord.read, coord.write, presence.write, contacts.read, contacts.write)")
	mintCmd.Flags().StringArrayVar(&grantMintBundles, "bundle", nil, "Grant scope bundle, repeatable or comma-separated (normal-agent)")
	mintCmd.Flags().StringArrayVar(&grantMintAppTools, "app-tool", nil, "Installed app tool the grant may call, as app:verb; repeatable or comma-separated. Each signed tool must be named; the definition is snapshotted at mint")
	mintCmd.Flags().StringVar(&grantMintCustodySocket, "custody-socket", "", "Resident custody Unix socket path to write into grant.yaml, or auto for the resident identity home's default custody socket")
	mintCmd.Flags().DurationVar(&grantMintTTL, "ttl", 8*time.Hour, "Grant duration before expiry (60s to 720h)")
	mintCmd.Flags().StringVar(&grantMintLabel, "label", "", "Optional label for the grant")
	mintCmd.Flags().StringVar(&grantMintOut, "out", "", "Directory to write the grant home (created fresh; a non-empty directory is refused)")
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List this identity's session grants",
		RunE:  runGrantList,
	}
	revokeCmd := &cobra.Command{
		Use:   "revoke <grant-id>",
		Short: "Revoke a session grant",
		Args:  cobra.ExactArgs(1),
		RunE:  runGrantRevoke,
	}
	showCmd := &cobra.Command{
		Use:   "show <grant-id>",
		Short: "Show one session grant",
		Args:  cobra.ExactArgs(1),
		RunE:  runGrantShow,
	}
	bindTeamSelector(grantCmd)
	grantCmd.AddCommand(mintCmd, listCmd, revokeCmd, showCmd)
	identityCmd.AddCommand(grantCmd)
}
