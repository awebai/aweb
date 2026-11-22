package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	teamHumanReplaceKeyTeamID         string
	teamHumanReplaceKeyOldDID         string
	teamHumanReplaceKeyNewDID         string
	teamHumanReplaceKeyOldCertID      string
	teamHumanReplaceKeyHome           string
	teamHumanReplaceKeyGenerateNewKey bool
	teamHumanReplaceKeyAwebURL        string
	teamHumanReplaceKeyRegistryURL    string
)

// Local participants retain their literal did:key; replacement grants no
// predecessor participation (docs/identity-messaging-contract.md:96-100).
const replacementConversationNotice = "The new key will not have the old key's mail or chat conversations."

var teamHumanReplaceKeyCmd = &cobra.Command{
	Use:   "replace-key <agent-alias>",
	Short: "Replace a local agent identity key under team-controller authority",
	Long: "Replace a local team-scoped agent's did:key under locally-held team-controller authority.\n\n" +
		"This compare-and-swap operation updates the service roster, revokes the old\n" +
		"team certificate, registers a new certificate, and records the controller-authorized\n" +
		"transition. When a real local home has lost signing.key, --generate-new-key creates\n" +
		"and retains a replacement key without overwriting an existing one. Hosted teams require\n" +
		"the pending AC owner/admin integration or operator support.\n\n" + replacementConversationNotice,
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanReplaceKey,
}

type localIdentityKeyReplacementRequest = awid.LocalIdentityKeyReplacementRequest

// maxReplaceKeyResponseBytes bounds the replace-key response body so a
// compromised or MITM'd server cannot exhaust client memory. It is a var, not a
// const, only so tests can lower it without a multi-MiB fixture; production
// keeps the shared response cap.
var maxReplaceKeyResponseBytes int64 = awid.MaxResponseSize

type replacementRosterOutcomeUnknownError struct {
	err error
}

func (e *replacementRosterOutcomeUnknownError) Error() string { return e.err.Error() }
func (e *replacementRosterOutcomeUnknownError) Unwrap() error { return e.err }

type localIdentityKeyReplacementResponse = awid.LocalIdentityKeyReplacementResponse

type teamHumanReplaceKeyOutput struct {
	Status             awid.LocalIdentityKeyReplacementState `json:"status"`
	TeamID             string                                `json:"team_id"`
	Alias              string                                `json:"alias"`
	OldDIDKey          string                                `json:"old_did_key"`
	NewDIDKey          string                                `json:"new_did_key"`
	OldCertificateID   string                                `json:"old_certificate_id"`
	NewCertificateID   string                                `json:"new_certificate_id"`
	AuditID            string                                `json:"audit_id"`
	AuthorizedBy       string                                `json:"authorized_by"`
	AuthorizedAt       string                                `json:"authorized_at"`
	CertificatePath    string                                `json:"certificate_path,omitempty"`
	SigningKeyPath     string                                `json:"signing_key_path,omitempty"`
	EncryptionKeyID    string                                `json:"encryption_key_id,omitempty"`
	TeamCertificate    string                                `json:"team_certificate,omitempty"`
	Placement          string                                `json:"placement,omitempty"`
	ConversationAccess string                                `json:"conversation_access"`
}

func init() {
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyTeamID, "team-id", "", "Canonical team id (<name>:<namespace>; defaults to active team)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyOldDID, "old-did-key", "", "Expected current local member did:key (required)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyNewDID, "new-did-key", "", "Replacement local member did:key (required unless --generate-new-key is used)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyOldCertID, "old-cert-id", "", "Old team certificate id (required without --home)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyHome, "home", "", "Agent home whose new signing identity is verified and where the replacement certificate is installed")
	teamHumanReplaceKeyCmd.Flags().BoolVar(&teamHumanReplaceKeyGenerateNewKey, "generate-new-key", false, "Generate a replacement signing key in --home when signing.key is absent (cannot be combined with --new-did-key)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyAwebURL, "aweb-url", "", "Aweb service URL override")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyRegistryURL, "registry", "", "AWID registry URL override")
	registerTeamAdminCommand(teamHumanReplaceKeyCmd, teamAdminGroupOperations)
}

func localIdentityKeyReplacementAuthPayload(alias string, payload localIdentityKeyReplacementRequest, timestamp string) ([]byte, error) {
	return awid.LocalIdentityKeyReplacementPayload(awid.LocalIdentityKeyReplacementPayloadInput{Alias: alias, Request: payload, Timestamp: timestamp})
}

func runTeamHumanReplaceKey(cmd *cobra.Command, args []string) (runErr error) {
	alias := strings.TrimSpace(args[0])
	if !isValidWorkspaceAlias(alias) {
		return usageError("invalid agent alias %q", alias)
	}
	oldDIDKey := strings.TrimSpace(teamHumanReplaceKeyOldDID)
	newDIDKey := strings.TrimSpace(teamHumanReplaceKeyNewDID)
	generateNewKey := teamHumanReplaceKeyGenerateNewKey
	if oldDIDKey == "" {
		return usageError("--old-did-key is required")
	}
	if generateNewKey {
		if strings.TrimSpace(teamHumanReplaceKeyHome) == "" {
			return usageError("--home is required with --generate-new-key")
		}
		if newDIDKey != "" {
			return usageError("--generate-new-key cannot be combined with --new-did-key")
		}
	} else if newDIDKey == "" {
		return usageError("--new-did-key is required unless --generate-new-key is used")
	}
	if _, err := awid.ExtractPublicKey(oldDIDKey); err != nil {
		return usageError("invalid --old-did-key: %v", err)
	}
	if newDIDKey != "" {
		if oldDIDKey == newDIDKey {
			return usageError("--new-did-key must differ from --old-did-key")
		}
		if _, err := awid.ExtractPublicKey(newDIDKey); err != nil {
			return usageError("invalid --new-did-key: %v", err)
		}
	}

	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(teamHumanReplaceKeyTeamID)
	if teamID == "" {
		teamID, err = activeTeamIDForHumanTeamCommand()
		if err != nil {
			return err
		}
	}
	domain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return err
	}
	teamKey, err := loadLocalReplaceKeyController(domain, teamName)
	if err != nil {
		return err
	}
	controllerDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))

	// Disclose this before generating a key or changing any remote state.
	if cmd != nil {
		fmt.Fprintln(cmd.ErrOrStderr(), replacementConversationNotice)
	} else {
		fmt.Fprintln(os.Stderr, replacementConversationNotice)
	}

	homeDir := strings.TrimSpace(teamHumanReplaceKeyHome)
	oldCertificateID := strings.TrimSpace(teamHumanReplaceKeyOldCertID)
	generatedKeyPath := ""
	if homeDir != "" {
		homeDir, err = filepath.Abs(homeDir)
		if err != nil {
			return err
		}
		if generateNewKey {
			oldCertificateID, newDIDKey, generatedKeyPath, err = prepareGeneratedReplacementAgentHome(replacementAgentHome{HomeDir: homeDir, TeamID: teamID, Alias: alias, OldDIDKey: oldDIDKey, OldCertificateID: oldCertificateID})
		} else {
			oldCertificateID, err = preflightReplacementAgentHome(replacementAgentHome{HomeDir: homeDir, TeamID: teamID, Alias: alias, OldDIDKey: oldDIDKey, NewDIDKey: newDIDKey, OldCertificateID: oldCertificateID})
		}
		if err != nil {
			return err
		}
	} else if oldCertificateID == "" {
		return usageError("--old-cert-id is required when --home is not supplied")
	}
	if generatedKeyPath != "" {
		defer func() {
			if runErr != nil {
				runErr = fmt.Errorf("%w; generated replacement signing key retained at %s (new DID %s). Do not generate another key; follow the phase-specific recovery above using this same key and DID", runErr, generatedKeyPath, newDIDKey)
			}
		}()
	}
	if oldDIDKey == newDIDKey {
		return usageError("generated --new-did-key unexpectedly matches --old-did-key")
	}

	serviceURL := strings.TrimSpace(teamHumanReplaceKeyAwebURL)
	if serviceURL == "" {
		serviceURL = strings.TrimSpace(awebURLForTeamInvite(wd, teamID))
	}
	if serviceURL == "" {
		return usageError("no aweb service URL is recorded for team %s; pass --aweb-url", teamID)
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	registryURL, err := resolveRegistryAuthority(ctx, registryAuthorityRequest{
		Kind: registryTeamRoute, Override: teamHumanReplaceKeyRegistryURL, Domain: domain,
		TeamID: teamID, WorkingDir: wd, AwebURL: serviceURL,
	})
	if err != nil {
		return err
	}
	if registryURL == "" {
		return usageError("no AWID registry URL is recorded for team %s; pass --registry", teamID)
	}
	registry := newAWIDRegistryClient(nil, nil)
	if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
		return fmt.Errorf("invalid registry URL: %w", err)
	}

	issuer := teamMembershipIssuer{TeamID: teamID, Key: teamKey, Registry: registry, RegistryURL: registryURL}
	newCertificate, err := issuer.sign(awid.TeamCertificateFields{
		MemberDIDKey: newDIDKey, Alias: alias, IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		return fmt.Errorf("mint replacement team certificate: %w", err)
	}
	encodedCertificate, err := awid.EncodeTeamCertificateHeader(newCertificate)
	if err != nil {
		return fmt.Errorf("encode replacement team certificate: %w", err)
	}
	requestPayload := localIdentityKeyReplacementRequest{
		TeamID: teamID, OldDIDKey: oldDIDKey, NewDIDKey: newDIDKey,
		OldCertificateID: oldCertificateID, NewCertificateID: newCertificate.CertificateID,
	}
	rosterResult, err := postLocalIdentityKeyReplacement(ctx, awid.LocalIdentityKeyReplacementInput{ServiceURL: serviceURL, Alias: alias, Request: requestPayload, TeamKey: teamKey})
	if err != nil {
		var unknown *replacementRosterOutcomeUnknownError
		if errors.As(err, &unknown) {
			return fmt.Errorf("replace-key roster outcome is unknown after an exact replay reconciliation attempt; no certificate registry changes were attempted, but the server may have replaced the roster and written an audit for certificate_id %s: %w; retain this exact replacement certificate material for recovery: %s", newCertificate.CertificateID, err, encodedCertificate)
		}
		return fmt.Errorf("replace service roster key (no certificate changes were attempted; retain the unused replacement certificate material until the failure is reconciled): %w; replacement certificate material: %s", err, encodedCertificate)
	}

	if err := registry.RevokeCertificate(ctx, registryURL, domain, teamName, oldCertificateID, teamKey); err != nil {
		return fmt.Errorf("replace-key partial state: roster row was replaced and audit %s was written; old certificate %s was not revoked; new certificate %s was not registered or installed: %w; retain this exact audited replacement certificate material for recovery: %s", rosterResult.AuditID, oldCertificateID, newCertificate.CertificateID, err, encodedCertificate)
	}
	if err := issuer.register(ctx, newCertificate); err != nil {
		return fmt.Errorf("replace-key partial state: roster row was replaced and audit %s was written; old certificate was revoked; new certificate was not registered or installed (certificate_id %s): %w; replacement certificate material for recovery: %s", rosterResult.AuditID, newCertificate.CertificateID, err, encodedCertificate)
	}

	output := teamHumanReplaceKeyOutput{
		Status: awid.LocalIdentityKeyReplaced, TeamID: teamID, Alias: alias,
		OldDIDKey: oldDIDKey, NewDIDKey: newDIDKey,
		OldCertificateID: oldCertificateID, NewCertificateID: newCertificate.CertificateID,
		AuditID: rosterResult.AuditID, AuthorizedBy: controllerDID, AuthorizedAt: rosterResult.AuthorizedAt,
		ConversationAccess: replacementConversationNotice,
	}
	if homeDir != "" {
		certPath, err := awconfig.SaveTeamCertificateForTeam(homeDir, teamID, newCertificate)
		if err != nil {
			return fmt.Errorf("replace-key partial state: roster row was replaced, old certificate was revoked, and new certificate %s was registered but not installed in %s: %w; save this replacement certificate material manually: %s", newCertificate.CertificateID, homeDir, err, encodedCertificate)
		}
		output.CertificatePath = filepath.ToSlash(filepath.Join(homeDir, ".aw", filepath.FromSlash(certPath)))
		output.SigningKeyPath = filepath.ToSlash(generatedKeyPath)
		encryptionCtx, encryptionCancel := commandAPIContext(cmd)
		encryptionOutput, encryptionErr := setupOrRotateIdentityEncryptionKeyForDir(encryptionCtx, homeDir, false, explicitEncryptionKeyIdentityHome(awconfig.WorktreeIdentityHome(homeDir)))
		encryptionCancel()
		if encryptionErr != nil {
			return fmt.Errorf("replace-key partial state: roster row and audit were updated, old certificate was revoked, and replacement signing key/certificate %s were installed, but the E2E encryption-key assertion was not refreshed: %w; from %s run `aw id encryption-key setup`", newCertificate.CertificateID, encryptionErr, homeDir)
		}
		output.EncryptionKeyID = encryptionOutput.KeyID
	} else {
		output.TeamCertificate = encodedCertificate
		output.Placement = fmt.Sprintf("base64-decode team_certificate as JSON into .aw/%s and chmod 600", awconfig.TeamCertificateRelativePath(teamID))
	}
	printOutput(output, formatTeamHumanReplaceKey)
	return nil
}

func loadLocalReplaceKeyController(domain, teamName string) (ed25519.PrivateKey, error) {
	if isAwebHostedNamespace(domain) {
		return nil, usageError("team %s:%s is hosted; phase-1 replace-key cannot use a local team controller key for hosted custody. Hosted owner/admin replacement requires the pending AC integration or operator support", teamName, domain)
	}
	exists, err := awconfig.TeamKeyExists(domain, teamName)
	if err != nil {
		return nil, fmt.Errorf("check local team controller key: %w", err)
	}
	if !exists {
		return nil, usageError("no local team controller key is available for %s:%s; phase-1 replace-key supports local-controller/BYOT teams only. Restore the local team controller key for a BYOT team; hosted owner/admin replacement requires the pending AC integration or operator support", teamName, domain)
	}
	key, err := awconfig.LoadTeamKey(domain, teamName)
	if err != nil {
		return nil, fmt.Errorf("load local team controller key: %w", err)
	}
	return key, nil
}

type replacementAgentHome struct {
	HomeDir          string
	TeamID           string
	Alias            string
	OldDIDKey        string
	NewDIDKey        string
	OldCertificateID string
}

func preflightReplacementAgentHome(input replacementAgentHome) (string, error) {
	homeDir, teamID, alias := input.HomeDir, input.TeamID, input.Alias
	oldDIDKey, newDIDKey, explicitOldCertificateID := input.OldDIDKey, input.NewDIDKey, input.OldCertificateID

	if err := validateReplacementAgentHomeState(replacementAgentHome{HomeDir: homeDir, TeamID: teamID, Alias: alias}); err != nil {
		return "", err
	}
	oldCertificateID, _, err := loadReplacementAgentOldCertificate(replacementAgentHome{HomeDir: homeDir, TeamID: teamID, Alias: alias, OldDIDKey: oldDIDKey, NewDIDKey: newDIDKey, OldCertificateID: explicitOldCertificateID})
	if err != nil {
		return "", err
	}
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(homeDir))
	if err != nil {
		return "", fmt.Errorf("load replacement agent signing key: %w", err)
	}
	if did := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); did != newDIDKey {
		return "", usageError("replacement agent home signing key %s does not match --new-did-key %s", did, newDIDKey)
	}
	return oldCertificateID, nil
}

func prepareGeneratedReplacementAgentHome(input replacementAgentHome) (string, string, string, error) {
	homeDir, teamID, alias := input.HomeDir, input.TeamID, input.Alias
	oldDIDKey, explicitOldCertificateID := input.OldDIDKey, input.OldCertificateID
	if err := validateReplacementAgentHomeState(replacementAgentHome{HomeDir: homeDir, TeamID: teamID, Alias: alias}); err != nil {
		return "", "", "", err
	}
	oldCertificateID, oldCertificate, err := loadReplacementAgentOldCertificate(replacementAgentHome{HomeDir: homeDir, TeamID: teamID, Alias: alias, OldDIDKey: oldDIDKey, NewDIDKey: "generated key", OldCertificateID: explicitOldCertificateID})
	if err != nil {
		return "", "", "", err
	}
	if oldCertificate == nil {
		return "", "", "", usageError("cannot generate a replacement key when both signing.key and the old team certificate are absent from --home; restore the old certificate first")
	}
	keyPath := awconfig.WorktreeSigningKeyPath(homeDir)
	if _, err := os.Lstat(keyPath); err == nil {
		return "", "", "", usageError("replacement signing key already exists at %s; --generate-new-key never overwrites recoverable identity material. For a compromised-key replacement, back up and remove that key yourself, then rerun", keyPath)
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", "", "", fmt.Errorf("inspect replacement signing key path: %w", err)
	}
	publicKey, privateKey, err := awid.GenerateKeypair()
	if err != nil {
		return "", "", "", err
	}
	if err := awid.SaveSigningKeyExclusive(keyPath, privateKey); err != nil {
		return "", "", "", fmt.Errorf("persist generated replacement signing key: %w", err)
	}
	return oldCertificateID, awid.ComputeDIDKey(publicKey), keyPath, nil
}

func validateReplacementAgentHomeState(input replacementAgentHome) error {
	homeDir, teamID, alias := input.HomeDir, input.TeamID, input.Alias
	teamState, err := awconfig.LoadTeamState(homeDir)
	if err != nil {
		return fmt.Errorf("load replacement home teams.yaml: %w", err)
	}
	teamMembership := teamState.Membership(teamID)
	if teamMembership == nil || strings.TrimSpace(teamMembership.Alias) != alias {
		return usageError("replacement home teams.yaml does not contain member %s in %s", alias, teamID)
	}
	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(homeDir)
	if err != nil {
		return fmt.Errorf("load replacement home workspace.yaml: %w", err)
	}
	workspaceMembership := workspace.Membership(teamID)
	if workspaceMembership == nil || strings.TrimSpace(workspaceMembership.Alias) != alias {
		return usageError("replacement home workspace.yaml does not contain member %s in %s", alias, teamID)
	}
	return nil
}

func loadReplacementAgentOldCertificate(input replacementAgentHome) (string, *awid.TeamCertificate, error) {
	homeDir, teamID, alias := input.HomeDir, input.TeamID, input.Alias
	oldDIDKey, newDIDKey, explicitOldCertificateID := input.OldDIDKey, input.NewDIDKey, input.OldCertificateID
	oldCertificate, err := awconfig.LoadTeamCertificateForTeam(homeDir, teamID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && explicitOldCertificateID != "" {
			return explicitOldCertificateID, nil, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return "", nil, usageError("old team certificate is absent from --home; pass --old-cert-id from the team registry or operator records")
		}
		return "", nil, fmt.Errorf("load old team certificate from replacement agent home: %w", err)
	}
	if oldCertificate.Team != teamID || oldCertificate.Alias != alias || oldCertificate.MemberDIDKey != oldDIDKey || awid.NormalizeIdentityScope(oldCertificate.IdentityScope) != awid.IdentityModeLocal {
		return "", nil, usageError("old team certificate in %s does not match local member %s (%s -> %s)", homeDir, alias, oldDIDKey, newDIDKey)
	}
	if explicitOldCertificateID != "" && explicitOldCertificateID != oldCertificate.CertificateID {
		return "", nil, usageError("--old-cert-id %s does not match the certificate in --home (%s)", explicitOldCertificateID, oldCertificate.CertificateID)
	}
	return oldCertificate.CertificateID, oldCertificate, nil
}

func postLocalIdentityKeyReplacement(ctx context.Context, input awid.LocalIdentityKeyReplacementInput) (*localIdentityKeyReplacementResponse, error) {
	var firstUnknown error
	for attempt := 0; attempt < 2; attempt++ {
		out, err := postLocalIdentityKeyReplacementOnce(ctx, input)
		if err == nil {
			return out, nil
		}
		var unknown *replacementRosterOutcomeUnknownError
		if !errors.As(err, &unknown) {
			if firstUnknown != nil {
				return nil, &replacementRosterOutcomeUnknownError{err: fmt.Errorf("initial outcome was unknown (%v); exact replay returned: %w", firstUnknown, err)}
			}
			return nil, err
		}
		if firstUnknown == nil {
			firstUnknown = err
		}
		if attempt == 0 {
			timer := time.NewTimer(100 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return nil, &replacementRosterOutcomeUnknownError{err: fmt.Errorf("initial outcome was unknown (%v); reconciliation canceled: %w", firstUnknown, ctx.Err())}
			case <-timer.C:
			}
		}
	}
	return nil, &replacementRosterOutcomeUnknownError{err: fmt.Errorf("exact replay could not reconcile roster outcome: %w", firstUnknown)}
}

func postLocalIdentityKeyReplacementOnce(ctx context.Context, input awid.LocalIdentityKeyReplacementInput) (*localIdentityKeyReplacementResponse, error) {
	input.MaxResponseBytes = maxReplaceKeyResponseBytes
	result, err := awid.ReplaceLocalIdentityKey(ctx, input)
	var unknown *awid.LocalIdentityKeyReplacementUnknownError
	if errors.As(err, &unknown) {
		return nil, &replacementRosterOutcomeUnknownError{err: err}
	}
	return result, err
}

func formatTeamHumanReplaceKey(v any) string {
	out := v.(teamHumanReplaceKeyOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Replaced local identity key for %s in %s\n", out.Alias, out.TeamID)
	fmt.Fprintln(&b, replacementConversationNotice)
	fmt.Fprintf(&b, "  old did:key: %s\n  new did:key: %s\n", out.OldDIDKey, out.NewDIDKey)
	fmt.Fprintf(&b, "  audit: %s (authorized by %s at %s)\n", out.AuditID, out.AuthorizedBy, out.AuthorizedAt)
	if out.CertificatePath != "" {
		if out.SigningKeyPath != "" {
			fmt.Fprintf(&b, "  replacement signing key generated: %s\n", out.SigningKeyPath)
		}
		fmt.Fprintf(&b, "  replacement certificate installed: %s\n", out.CertificatePath)
		if out.EncryptionKeyID != "" {
			fmt.Fprintf(&b, "  E2E encryption assertion refreshed: %s\n", out.EncryptionKeyID)
		}
	} else {
		fmt.Fprintf(&b, "  replacement team certificate: %s\n  placement: %s\n", out.TeamCertificate, out.Placement)
	}
	return b.String()
}
