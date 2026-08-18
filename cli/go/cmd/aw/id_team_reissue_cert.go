package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// aw id team reissue-cert: the blob-lost remedy from the hosted-certificate-
// anchoring contract (docs/drafts/hosted-certificate-anchoring.md). A member
// whose signed certificate blob is lost (or was never registered) cannot be
// re-registered from the blob; the remedy is minting a FRESH certificate for
// the same team, same member did:key, same alias, same identity_scope - new
// certificate UUID, fresh issued_at - registering it at the AWID registry,
// and revoking the old registration first if one exists.
//
// This is deliberately NOT the replace-key machinery: replace-key exists for a
// lost or compromised member KEY and structurally changes the did:key at both
// the client and server layers. reissue-cert never touches the member key.

var (
	teamReissueCertTeam        string
	teamReissueCertNamespace   string
	teamReissueCertDID         string
	teamReissueCertHome        string
	teamReissueCertLocal       bool
	teamReissueCertGlobal      bool
	teamReissueCertDIDAW       string
	teamReissueCertAddress     string
	teamReissueCertRegistryURL string
)

type teamReissueCertOutput struct {
	Status               string `json:"status"`
	TeamID               string `json:"team_id"`
	Alias                string `json:"alias"`
	MemberDIDKey         string `json:"member_did_key"`
	IdentityScope        string `json:"identity_scope"`
	OldCertificateID     string `json:"old_certificate_id,omitempty"`
	OldCertificateAction string `json:"old_certificate_action"`
	NewCertificateID     string `json:"new_certificate_id"`
	CertificatePath      string `json:"certificate_path,omitempty"`
	TeamCertificate      string `json:"team_certificate,omitempty"`
	Placement            string `json:"placement,omitempty"`
}

// certificateNoneRegistered reports that the registry held no active
// certificate for the alias, so there was nothing to revoke and the fresh
// registration cannot conflict with the unique active-alias constraint.
const certificateNoneRegistered = "none_registered"

var teamReissueCertCmd = &cobra.Command{
	Use:   "reissue-cert <alias>",
	Short: "Protocol/admin: mint and register a fresh certificate for the same member key",
	Long: "Mint, register, and (optionally) install a fresh team certificate for an existing\n" +
		"member, keeping the member's did:key, alias, and identity scope unchanged.\n\n" +
		"This is the remedy for a lost or never-registered certificate blob: the signed\n" +
		"blob cannot be reconstructed, so the team controller signs a fresh certificate\n" +
		"(new certificate id, fresh issued_at) for the same member key. If the registry\n" +
		"holds an active certificate for the alias, it is revoked first and the fresh one\n" +
		"is registered after, so the registry's one-active-certificate-per-alias\n" +
		"constraint is never violated. If none is registered, the fresh certificate is\n" +
		"simply registered. Re-running after a partial failure is safe: a run that\n" +
		"revoked but died before registering finds no active certificate and registers;\n" +
		"a run against an already-reissued member revokes the current certificate and\n" +
		"swaps in a fresh one.\n\n" +
		"Revoking the old certificate invalidates any grants issued under it, and the\n" +
		"member's server projection refreshes at its next certificate-authenticated\n" +
		"connect, so expect the member to reconnect.\n\n" +
		"This is NOT key rotation: the member keeps its did:key, and the command refuses\n" +
		"to run when the registered member key differs from the one attested. For a lost\n" +
		"or compromised member KEY, use `aw team replace-key` instead.\n\n" +
		"Requires the locally-held team controller key (BYOT/local-controller teams).\n" +
		"Hosted aweb.ai teams keep the controller key in cloud custody; hosted\n" +
		"re-issuance runs through the hosted service or operator support.\n\n" +
		"Pass --home to verify the member's local home and install the fresh blob there;\n" +
		"without --home the command prints the blob and where the member must place it.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamReissueCert,
}

func init() {
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertTeam, "team", "", "Team name")
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertNamespace, "namespace", "", "Namespace domain")
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertDID, "did", "", "Member did:key the fresh certificate binds (required unless --home is supplied)")
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertHome, "home", "", "Member home whose signing key attests the did:key and where the fresh certificate is installed")
	teamReissueCertCmd.Flags().BoolVar(&teamReissueCertLocal, "local", false, "Assert local identity scope (default when no registered certificate states it)")
	teamReissueCertCmd.Flags().BoolVar(&teamReissueCertGlobal, "global", false, "Assert global identity scope")
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertDIDAW, "did-aw", "", "Global member did:aw when no registered certificate states it")
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertAddress, "address", "", "Global member address when no registered certificate states it; requires --did-aw")
	teamReissueCertCmd.Flags().StringVar(&teamReissueCertRegistryURL, "registry", "", "Registry origin override")
	teamCmd.AddCommand(teamReissueCertCmd)
}

func runTeamReissueCert(cmd *cobra.Command, args []string) error {
	alias := strings.TrimSpace(args[0])
	if !isValidWorkspaceAlias(alias) {
		return usageError("invalid member alias %q", alias)
	}
	team := strings.ToLower(strings.TrimSpace(teamReissueCertTeam))
	domain := awconfig.NormalizeDomain(teamReissueCertNamespace)
	if team == "" {
		return usageError("--team is required")
	}
	if domain == "" {
		return usageError("--namespace is required")
	}
	if teamReissueCertLocal && teamReissueCertGlobal {
		return usageError("--local and --global cannot be used together")
	}
	teamID := awid.BuildTeamID(domain, team)

	teamKey, err := loadReissueCertController(domain, team)
	if err != nil {
		return err
	}

	memberDID := strings.TrimSpace(teamReissueCertDID)
	if memberDID != "" {
		if _, err := awid.ExtractPublicKey(memberDID); err != nil {
			return usageError("invalid --did: %v", err)
		}
	}
	homeDir := strings.TrimSpace(teamReissueCertHome)
	if homeDir == "" && memberDID == "" {
		return usageError("--did is required when --home is not supplied")
	}
	if homeDir != "" {
		homeDir, err = filepath.Abs(homeDir)
		if err != nil {
			return err
		}
		homeDID, err := preflightReissueCertMemberHome(homeDir, teamID, alias)
		if err != nil {
			return err
		}
		if memberDID != "" && memberDID != homeDID {
			return usageError("--did %s does not match the signing key in --home (%s); reissue-cert never changes the member key. For a lost or compromised member key, use `aw team replace-key`", memberDID, homeDID)
		}
		memberDID = homeDID
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL, err := resolveReissueCertRegistryURL(registry, domain)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// The registry enforces one unrevoked certificate per (team, alias), so the
	// alias's active registration - if any - is both the row to revoke and the
	// authoritative record of the member facts the fresh certificate must keep.
	oldRef, err := resolveActiveReissueCertMember(ctx, registry, registryURL, domain, team, teamID, alias, teamKey)
	if err != nil {
		return err
	}
	memberRef := oldRef
	if memberRef == nil {
		memberRef, err = resolveLatestRevokedReissueCertMember(
			ctx, registry, registryURL, domain, team, teamID, alias, memberDID, teamKey,
		)
		if err != nil {
			return err
		}
	}

	scope := awid.IdentityModeLocal
	if teamReissueCertGlobal {
		scope = awid.IdentityModeGlobal
	}
	memberDIDAW := strings.TrimSpace(teamReissueCertDIDAW)
	memberAddress := strings.TrimSpace(teamReissueCertAddress)
	if memberRef != nil {
		oldDID := strings.TrimSpace(memberRef.MemberDIDKey)
		if oldDID != "" && oldDID != memberDID {
			return usageError(
				"the registered certificate %s for %s in %s binds member did:key %s, not %s; reissue-cert never changes the member key. For a lost or compromised member key, use `aw team replace-key`",
				strings.TrimSpace(memberRef.CertificateID), alias, teamID, oldDID, memberDID,
			)
		}
		registeredScope := awid.NormalizeIdentityScope(memberRef.IdentityScope)
		if (teamReissueCertLocal || teamReissueCertGlobal) && scope != registeredScope {
			return usageError("requested identity scope %q conflicts with the registered certificate history's scope %q; reissue-cert keeps the member's identity scope", scope, registeredScope)
		}
		scope = registeredScope
		if memberDIDAW != "" && memberDIDAW != strings.TrimSpace(memberRef.MemberDIDAW) {
			return usageError("--did-aw %s does not match the registered certificate history's did:aw %q", memberDIDAW, strings.TrimSpace(memberRef.MemberDIDAW))
		}
		if memberAddress != "" && memberAddress != strings.TrimSpace(memberRef.MemberAddress) {
			return usageError("--address %s does not match the registered certificate history's address %q", memberAddress, strings.TrimSpace(memberRef.MemberAddress))
		}
		memberDIDAW = strings.TrimSpace(memberRef.MemberDIDAW)
		memberAddress = strings.TrimSpace(memberRef.MemberAddress)
	} else {
		if scope == awid.IdentityModeLocal && (memberDIDAW != "" || memberAddress != "") {
			return usageError("--did-aw and --address require --global; local members carry neither")
		}
		if memberAddress != "" {
			if memberDIDAW == "" {
				return usageError("--did-aw is required when --address is set")
			}
			workingDir, err := os.Getwd()
			if err != nil {
				return err
			}
			lookupSigningKey, err := loadOptionalWorktreeSigningKey(workingDir)
			if err != nil {
				return err
			}
			if err := validateMemberAddressForCertificate(ctx, registry, registryURL, memberAddress, memberDIDAW, memberDID, lookupSigningKey); err != nil {
				return err
			}
		}
	}

	freshCertificate, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  memberDID,
		MemberDIDAW:   memberDIDAW,
		MemberAddress: memberAddress,
		Alias:         alias,
		IdentityScope: scope,
	})
	if err != nil {
		return fmt.Errorf("mint fresh team certificate: %w", err)
	}
	encodedCertificate, err := awid.EncodeTeamCertificateHeader(freshCertificate)
	if err != nil {
		return fmt.Errorf("encode fresh team certificate: %w", err)
	}

	// Registry ordering under the unique active-alias constraint: the old
	// registration must be revoked BEFORE the fresh one is registered, or the
	// registration 409s against the still-active alias row. When nothing is
	// registered there is nothing to revoke and no conflict by construction.
	oldAction := certificateNoneRegistered
	oldCertificateID := ""
	if oldRef != nil {
		oldCertificateID = strings.TrimSpace(oldRef.CertificateID)
		revocation, err := revokeRegistryTeamCertificate(ctx, registry, registryURL, domain, team, oldCertificateID, teamKey)
		if err != nil {
			return fmt.Errorf("reissue-cert made no registry changes: old certificate %s was not revoked and the fresh certificate was not registered: %w; re-run this command once the registry is reachable", oldCertificateID, err)
		}
		oldAction = revocation.Result
	}
	if err := registry.RegisterCertificate(ctx, registryURL, domain, team, freshCertificate, teamKey); err != nil {
		if oldRef != nil {
			return fmt.Errorf("reissue-cert partial state: old certificate %s was revoked but fresh certificate %s was not registered: %w; re-running this command is safe - it will find no active certificate for %s and register a fresh one; fresh certificate material: %s", oldCertificateID, freshCertificate.CertificateID, err, alias, encodedCertificate)
		}
		return fmt.Errorf("register fresh certificate %s: %w; no registry state was changed, so re-running this command is safe", freshCertificate.CertificateID, err)
	}

	output := teamReissueCertOutput{
		Status:               "reissued",
		TeamID:               teamID,
		Alias:                alias,
		MemberDIDKey:         memberDID,
		IdentityScope:        scope,
		OldCertificateID:     oldCertificateID,
		OldCertificateAction: oldAction,
		NewCertificateID:     freshCertificate.CertificateID,
	}
	if homeDir != "" {
		certPath, err := awconfig.SaveTeamCertificateForTeam(homeDir, teamID, freshCertificate)
		if err != nil {
			return fmt.Errorf("reissue-cert partial state: fresh certificate %s was registered but not installed in %s: %w; save this certificate material manually (base64-decode as JSON into .aw/%s and chmod 600): %s", freshCertificate.CertificateID, homeDir, err, awconfig.TeamCertificateRelativePath(teamID), encodedCertificate)
		}
		output.CertificatePath = filepath.ToSlash(filepath.Join(homeDir, ".aw", filepath.FromSlash(certPath)))
	} else {
		output.TeamCertificate = encodedCertificate
		output.Placement = fmt.Sprintf("base64-decode team_certificate as JSON into .aw/%s and chmod 600", awconfig.TeamCertificateRelativePath(teamID))
	}
	printOutput(output, formatTeamReissueCert)
	return nil
}

// loadReissueCertController follows the replace-key key-loading path: the
// operation runs where the team signing key is locally held, and hosted
// namespaces refuse rather than pretending local custody exists.
func loadReissueCertController(domain, teamName string) (ed25519.PrivateKey, error) {
	if isAwebHostedNamespace(domain) {
		return nil, usageError("team %s:%s is hosted; reissue-cert cannot use a local team controller key for hosted custody. Hosted certificate re-issuance runs through the hosted service or operator support", teamName, domain)
	}
	exists, err := awconfig.TeamKeyExists(domain, teamName)
	if err != nil {
		return nil, fmt.Errorf("check local team controller key: %w", err)
	}
	if !exists {
		return nil, usageError("no local team controller key is available for %s:%s; reissue-cert supports local-controller/BYOT teams only. Restore the local team controller key, or use hosted operator support for hosted teams", teamName, domain)
	}
	key, err := awconfig.LoadTeamKey(domain, teamName)
	if err != nil {
		return nil, fmt.Errorf("load local team controller key: %w", err)
	}
	return key, nil
}

// resolveReissueCertRegistryURL resolves the registry origin:
// explicit flag -> controller metadata for the namespace -> client default.
func resolveReissueCertRegistryURL(registry *awid.RegistryClient, domain string) (string, error) {
	registryURL := strings.TrimSpace(teamReissueCertRegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return "", fmt.Errorf("invalid --registry: %w", err)
		}
		return registryURL, nil
	}
	if meta, err := awconfig.LoadControllerMeta(domain); err == nil && meta != nil {
		if metaURL := strings.TrimSpace(meta.RegistryURL); metaURL != "" {
			if err := registry.SetFallbackRegistryURL(metaURL); err != nil {
				return "", fmt.Errorf("invalid registry URL in controller metadata for %s: %w", domain, err)
			}
			return metaURL, nil
		}
	}
	registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	if registryURL == "" {
		return "", usageError("no AWID registry URL is known for %s; pass --registry", domain)
	}
	return registryURL, nil
}

// resolveActiveReissueCertMember returns the alias's active registration, or
// nil when the registry states there is none. A 404 from the member resolve is
// only trusted as "no active certificate" after the team itself reads back,
// so a mistyped team or a team that was never registered fails loudly instead
// of silently taking the register-only path.
func resolveActiveReissueCertMember(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, team, teamID, alias string,
	teamKey ed25519.PrivateKey,
) (*awid.TeamMemberReference, error) {
	ref, err := registry.ResolveTeamMember(ctx, registryURL, domain, team, alias, teamKey)
	if err == nil {
		return ref, nil
	}
	if status, ok := awid.HTTPStatusCode(err); !ok || status != http.StatusNotFound {
		// The team key is in hand here, so a visibility refusal means it is not
		// the team's key - said plainly rather than wrapped as a failed lookup.
		if friendly := friendlyTeamReadError(err, teamID, true); friendly != err {
			return nil, friendly
		}
		return nil, fmt.Errorf("resolve active certificate for %s in %s: %w", alias, teamID, err)
	}
	if _, teamErr := registry.GetTeam(ctx, registryURL, domain, team, teamKey); teamErr != nil {
		if friendly := friendlyTeamReadError(teamErr, teamID, true); friendly != teamErr {
			return nil, friendly
		}
		return nil, fmt.Errorf("no active certificate is registered for %s in %s, and the team itself could not be read back from the registry: %w; certificate registration requires the team to be registered first", alias, teamID, teamErr)
	}
	return nil, nil
}

// resolveLatestRevokedReissueCertMember recovers the member facts needed by a
// retry after the previous run revoked the active certificate but failed to
// register its replacement. The registry history is complete and signed with
// the team controller key. Only the newest unambiguous record for the exact
// alias and member key may supply facts; a tie with different facts fails
// rather than silently changing identity scope or global identity.
func resolveLatestRevokedReissueCertMember(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, team, teamID, alias, memberDID string,
	teamKey ed25519.PrivateKey,
) (*awid.TeamMemberReference, error) {
	certificates, err := registry.ListCertificates(
		ctx, registryURL, domain, team, false, teamKey,
	)
	if err != nil {
		if friendly := friendlyTeamReadError(err, teamID, true); friendly != err {
			return nil, friendly
		}
		return nil, fmt.Errorf("read complete certificate history for %s in %s: %w", alias, teamID, err)
	}

	var selected *awid.RegistryCertificate
	var selectedIssuedAt time.Time
	for i := range certificates {
		candidate := &certificates[i]
		if strings.TrimSpace(candidate.Alias) != alias ||
			strings.TrimSpace(candidate.MemberDIDKey) != memberDID ||
			strings.TrimSpace(candidate.RevokedAt) == "" {
			continue
		}
		issuedAt, err := time.Parse(time.RFC3339Nano, strings.TrimSpace(candidate.IssuedAt))
		if err != nil {
			return nil, fmt.Errorf(
				"certificate history for %s in %s contains invalid issued_at on %s: %w",
				alias, teamID, strings.TrimSpace(candidate.CertificateID), err,
			)
		}
		if selected == nil || issuedAt.After(selectedIssuedAt) {
			selected = candidate
			selectedIssuedAt = issuedAt
			continue
		}
		if !issuedAt.Equal(selectedIssuedAt) {
			continue
		}
		if awid.NormalizeIdentityScope(candidate.IdentityScope) != awid.NormalizeIdentityScope(selected.IdentityScope) ||
			strings.TrimSpace(candidate.MemberDIDAW) != strings.TrimSpace(selected.MemberDIDAW) ||
			strings.TrimSpace(candidate.MemberAddress) != strings.TrimSpace(selected.MemberAddress) {
			return nil, fmt.Errorf(
				"certificate history for %s in %s is ambiguous at issued_at %s; pass explicit member facts only after resolving the conflicting registry records",
				alias, teamID, issuedAt.Format(time.RFC3339Nano),
			)
		}
	}
	if selected == nil {
		return nil, nil
	}
	return &awid.TeamMemberReference{
		TeamID:        strings.TrimSpace(selected.TeamID),
		CertificateID: strings.TrimSpace(selected.CertificateID),
		MemberDIDKey:  strings.TrimSpace(selected.MemberDIDKey),
		MemberDIDAW:   strings.TrimSpace(selected.MemberDIDAW),
		MemberAddress: strings.TrimSpace(selected.MemberAddress),
		Alias:         strings.TrimSpace(selected.Alias),
		IdentityScope: awid.NormalizeIdentityScope(selected.IdentityScope),
		IssuedAt:      strings.TrimSpace(selected.IssuedAt),
	}, nil
}

// preflightReissueCertMemberHome verifies the member home records this
// membership and derives the member did:key from its signing key. The lost
// artifact this command remedies is the certificate blob, not the key: a home
// without a signing key is a replace-key situation, and the error says so.
func preflightReissueCertMemberHome(homeDir, teamID, alias string) (string, error) {
	teamState, err := awconfig.LoadTeamState(homeDir)
	if err != nil {
		return "", fmt.Errorf("load member home teams.yaml: %w", err)
	}
	membership := teamState.Membership(teamID)
	if membership == nil || strings.TrimSpace(membership.Alias) != alias {
		return "", usageError("member home teams.yaml does not contain member %s in %s", alias, teamID)
	}
	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(homeDir)
	if err != nil {
		return "", fmt.Errorf("load member home workspace.yaml: %w", err)
	}
	workspaceMembership := workspace.Membership(teamID)
	if workspaceMembership == nil || strings.TrimSpace(workspaceMembership.Alias) != alias {
		return "", usageError("member home workspace.yaml does not contain member %s in %s", alias, teamID)
	}
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(homeDir))
	if err != nil {
		return "", fmt.Errorf("load member signing key from --home: %w (reissue-cert remedies a lost certificate blob for an intact key; if the member's signing key is also lost, use `aw team replace-key --generate-new-key`)", err)
	}
	return awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)), nil
}

func formatTeamReissueCert(v any) string {
	out := v.(teamReissueCertOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Reissued team certificate for %s in %s\n", out.Alias, out.TeamID)
	fmt.Fprintf(&b, "  member did:key: %s (unchanged)\n", out.MemberDIDKey)
	fmt.Fprintf(&b, "  identity scope: %s\n", out.IdentityScope)
	switch out.OldCertificateAction {
	case certificateNoneRegistered:
		b.WriteString("  no active certificate was registered for this alias; nothing was revoked\n")
	case certificateAlreadyRevoked:
		fmt.Fprintf(&b, "  old certificate %s was already revoked at the registry\n", out.OldCertificateID)
	default:
		fmt.Fprintf(&b, "  old certificate %s revoked at the registry\n", out.OldCertificateID)
	}
	if out.OldCertificateID != "" {
		b.WriteString("    Grants issued under the old certificate are no longer valid.\n")
	}
	fmt.Fprintf(&b, "  new certificate registered: %s\n", out.NewCertificateID)
	if out.CertificatePath != "" {
		fmt.Fprintf(&b, "  fresh certificate installed: %s\n", out.CertificatePath)
	} else {
		fmt.Fprintf(&b, "  fresh team certificate: %s\n  placement: %s\n", out.TeamCertificate, out.Placement)
	}
	b.WriteString("  The member's server projection refreshes at its next certificate-authenticated connect - expect the member to reconnect.\n")
	return b.String()
}
