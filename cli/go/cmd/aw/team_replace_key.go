package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	teamHumanReplaceKeyTeamID      string
	teamHumanReplaceKeyOldDID      string
	teamHumanReplaceKeyNewDID      string
	teamHumanReplaceKeyOldCertID   string
	teamHumanReplaceKeyHome        string
	teamHumanReplaceKeyAwebURL     string
	teamHumanReplaceKeyRegistryURL string
)

var teamHumanReplaceKeyCmd = &cobra.Command{
	Use:   "replace-key <agent-alias>",
	Short: "Replace a local agent identity key under team-controller authority",
	Long: "Replace a local team-scoped agent's did:key under locally-held team-controller authority.\n\n" +
		"This compare-and-swap operation updates the service roster, revokes the old\n" +
		"team certificate, registers a new certificate, and records the controller-authorized\n" +
		"transition. Hosted teams require the pending AC owner/admin integration or operator support.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanReplaceKey,
}

type localIdentityKeyReplacementRequest struct {
	TeamID           string `json:"team_id"`
	OldDIDKey        string `json:"old_did_key"`
	NewDIDKey        string `json:"new_did_key"`
	OldCertificateID string `json:"old_certificate_id"`
	NewCertificateID string `json:"new_certificate_id"`
}

type replacementRosterOutcomeUnknownError struct {
	err error
}

func (e *replacementRosterOutcomeUnknownError) Error() string { return e.err.Error() }
func (e *replacementRosterOutcomeUnknownError) Unwrap() error { return e.err }

type localIdentityKeyReplacementResponse struct {
	Status           string `json:"status"`
	AuditID          string `json:"audit_id"`
	AgentID          string `json:"agent_id"`
	TeamID           string `json:"team_id"`
	Alias            string `json:"alias"`
	OldDIDKey        string `json:"old_did_key"`
	NewDIDKey        string `json:"new_did_key"`
	OldCertificateID string `json:"old_certificate_id"`
	NewCertificateID string `json:"new_certificate_id"`
	AuthorizedBy     string `json:"authorized_by"`
	AuthorizedAt     string `json:"authorized_at"`
}

type teamHumanReplaceKeyOutput struct {
	Status           string `json:"status"`
	TeamID           string `json:"team_id"`
	Alias            string `json:"alias"`
	OldDIDKey        string `json:"old_did_key"`
	NewDIDKey        string `json:"new_did_key"`
	OldCertificateID string `json:"old_certificate_id"`
	NewCertificateID string `json:"new_certificate_id"`
	AuditID          string `json:"audit_id"`
	AuthorizedBy     string `json:"authorized_by"`
	AuthorizedAt     string `json:"authorized_at"`
	CertificatePath  string `json:"certificate_path,omitempty"`
	TeamCertificate  string `json:"team_certificate,omitempty"`
	Placement        string `json:"placement,omitempty"`
}

func init() {
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyTeamID, "team-id", "", "Canonical team id (<name>:<namespace>; defaults to active team)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyOldDID, "old-did-key", "", "Expected current local member did:key (required)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyNewDID, "new-did-key", "", "Replacement local member did:key (required)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyOldCertID, "old-cert-id", "", "Old team certificate id (required without --home)")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyHome, "home", "", "Agent home whose new signing identity is verified and where the replacement certificate is installed")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyAwebURL, "aweb-url", "", "Aweb service URL override")
	teamHumanReplaceKeyCmd.Flags().StringVar(&teamHumanReplaceKeyRegistryURL, "registry", "", "AWID registry URL override")
	teamHumanCmd.AddCommand(teamHumanReplaceKeyCmd)
}

func localIdentityKeyReplacementAuthPayload(alias string, payload localIdentityKeyReplacementRequest, timestamp string) ([]byte, error) {
	// Field order is lexicographic to match Python canonical_json_bytes.
	return json.Marshal(struct {
		AgentAlias       string `json:"agent_alias"`
		NewCertificateID string `json:"new_certificate_id"`
		NewDIDKey        string `json:"new_did_key"`
		OldCertificateID string `json:"old_certificate_id"`
		OldDIDKey        string `json:"old_did_key"`
		Operation        string `json:"operation"`
		TeamID           string `json:"team_id"`
		Timestamp        string `json:"timestamp"`
	}{
		AgentAlias:       alias,
		NewCertificateID: payload.NewCertificateID,
		NewDIDKey:        payload.NewDIDKey,
		OldCertificateID: payload.OldCertificateID,
		OldDIDKey:        payload.OldDIDKey,
		Operation:        "replace_local_identity_key",
		TeamID:           payload.TeamID,
		Timestamp:        timestamp,
	})
}

func runTeamHumanReplaceKey(cmd *cobra.Command, args []string) error {
	alias := strings.TrimSpace(args[0])
	if !isValidWorkspaceAlias(alias) {
		return usageError("invalid agent alias %q", alias)
	}
	oldDIDKey := strings.TrimSpace(teamHumanReplaceKeyOldDID)
	newDIDKey := strings.TrimSpace(teamHumanReplaceKeyNewDID)
	if oldDIDKey == "" || newDIDKey == "" {
		return usageError("--old-did-key and --new-did-key are required")
	}
	if oldDIDKey == newDIDKey {
		return usageError("--new-did-key must differ from --old-did-key")
	}
	if _, err := awid.ExtractPublicKey(oldDIDKey); err != nil {
		return usageError("invalid --old-did-key: %v", err)
	}
	if _, err := awid.ExtractPublicKey(newDIDKey); err != nil {
		return usageError("invalid --new-did-key: %v", err)
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

	homeDir := strings.TrimSpace(teamHumanReplaceKeyHome)
	oldCertificateID := strings.TrimSpace(teamHumanReplaceKeyOldCertID)
	if homeDir != "" {
		homeDir, err = filepath.Abs(homeDir)
		if err != nil {
			return err
		}
		oldCertificateID, err = preflightReplacementAgentHome(homeDir, teamID, alias, oldDIDKey, newDIDKey, oldCertificateID)
		if err != nil {
			return err
		}
	} else if oldCertificateID == "" {
		return usageError("--old-cert-id is required when --home is not supplied")
	}

	serviceURL := strings.TrimSpace(teamHumanReplaceKeyAwebURL)
	if serviceURL == "" {
		serviceURL = strings.TrimSpace(awebURLForTeamInvite(wd, teamID))
	}
	if serviceURL == "" {
		return usageError("no aweb service URL is recorded for team %s; pass --aweb-url", teamID)
	}
	registryURL := strings.TrimSpace(teamHumanReplaceKeyRegistryURL)
	if registryURL == "" {
		registryURL = strings.TrimSpace(registryURLForTeamInvite(wd, domain, serviceURL))
	}
	if registryURL == "" {
		return usageError("no AWID registry URL is recorded for team %s; pass --registry", teamID)
	}
	registry := awid.NewAWIDRegistryClient(nil, nil)
	if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
		return fmt.Errorf("invalid registry URL: %w", err)
	}

	newCertificate, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team: teamID, MemberDIDKey: newDIDKey, Alias: alias, IdentityScope: awid.IdentityModeLocal,
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
	ctx, cancel := context.WithTimeout(context.Background(), awid.APITimeout())
	defer cancel()
	rosterResult, err := postLocalIdentityKeyReplacement(ctx, serviceURL, alias, requestPayload, teamKey)
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
	if err := registry.RegisterCertificate(ctx, registryURL, domain, teamName, newCertificate, teamKey); err != nil {
		return fmt.Errorf("replace-key partial state: roster row was replaced and audit %s was written; old certificate was revoked; new certificate was not registered or installed (certificate_id %s): %w; replacement certificate material for recovery: %s", rosterResult.AuditID, newCertificate.CertificateID, err, encodedCertificate)
	}

	output := teamHumanReplaceKeyOutput{
		Status: "replaced", TeamID: teamID, Alias: alias,
		OldDIDKey: oldDIDKey, NewDIDKey: newDIDKey,
		OldCertificateID: oldCertificateID, NewCertificateID: newCertificate.CertificateID,
		AuditID: rosterResult.AuditID, AuthorizedBy: controllerDID, AuthorizedAt: rosterResult.AuthorizedAt,
	}
	if homeDir != "" {
		certPath, err := awconfig.SaveTeamCertificateForTeam(homeDir, teamID, newCertificate)
		if err != nil {
			return fmt.Errorf("replace-key partial state: roster row was replaced, old certificate was revoked, and new certificate %s was registered but not installed in %s: %w; save this replacement certificate material manually: %s", newCertificate.CertificateID, homeDir, err, encodedCertificate)
		}
		output.CertificatePath = filepath.ToSlash(filepath.Join(homeDir, ".aw", filepath.FromSlash(certPath)))
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

func preflightReplacementAgentHome(homeDir, teamID, alias, oldDIDKey, newDIDKey, explicitOldCertificateID string) (string, error) {
	identity, _, err := awconfig.LoadWorktreeIdentityFromDir(homeDir)
	if err != nil {
		return "", fmt.Errorf("load replacement agent identity from %s: %w", homeDir, err)
	}
	identityScope := awid.NormalizeIdentityScope(firstNonEmpty(identity.IdentityScope, identity.Lifetime))
	if identityScope != awid.IdentityModeLocal {
		return "", usageError("replacement agent home identity scope is %q; --home must contain a local team-scoped identity", identityScope)
	}
	if strings.TrimSpace(identity.DID) != newDIDKey {
		return "", usageError("replacement agent home identity did %s does not match --new-did-key %s", identity.DID, newDIDKey)
	}
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(homeDir))
	if err != nil {
		return "", fmt.Errorf("load replacement agent signing key: %w", err)
	}
	if did := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); did != newDIDKey {
		return "", usageError("replacement agent home signing key %s does not match --new-did-key %s", did, newDIDKey)
	}
	oldCertificate, err := awconfig.LoadTeamCertificateForTeam(homeDir, teamID)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && explicitOldCertificateID != "" {
			return explicitOldCertificateID, nil
		}
		if errors.Is(err, os.ErrNotExist) {
			return "", usageError("old team certificate is absent from --home; pass --old-cert-id from the team registry or operator records")
		}
		return "", fmt.Errorf("load old team certificate from replacement agent home: %w", err)
	}
	if oldCertificate.Team != teamID || oldCertificate.Alias != alias || oldCertificate.MemberDIDKey != oldDIDKey || awid.NormalizeIdentityScope(firstNonEmpty(oldCertificate.IdentityScope, oldCertificate.Lifetime)) != awid.IdentityModeLocal {
		return "", usageError("old team certificate in %s does not match local member %s (%s -> %s)", homeDir, alias, oldDIDKey, newDIDKey)
	}
	if explicitOldCertificateID != "" && explicitOldCertificateID != oldCertificate.CertificateID {
		return "", usageError("--old-cert-id %s does not match the certificate in --home (%s)", explicitOldCertificateID, oldCertificate.CertificateID)
	}
	return oldCertificate.CertificateID, nil
}

func postLocalIdentityKeyReplacement(ctx context.Context, serviceURL, alias string, payload localIdentityKeyReplacementRequest, teamKey ed25519.PrivateKey) (*localIdentityKeyReplacementResponse, error) {
	var firstUnknown error
	for attempt := 0; attempt < 2; attempt++ {
		out, err := postLocalIdentityKeyReplacementOnce(ctx, serviceURL, alias, payload, teamKey)
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

func postLocalIdentityKeyReplacementOnce(ctx context.Context, serviceURL, alias string, payload localIdentityKeyReplacementRequest, teamKey ed25519.PrivateKey) (*localIdentityKeyReplacementResponse, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	path := "/v1/agents/" + url.PathEscape(alias) + "/replace-key"
	timestamp := time.Now().UTC().Format(time.RFC3339)
	canonical, err := localIdentityKeyReplacementAuthPayload(alias, payload, timestamp)
	if err != nil {
		return nil, err
	}
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, canonical))
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(serviceURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "DIDKey "+awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))+" "+signature)
	req.Header.Set("X-AWEB-Timestamp", timestamp)
	resp, err := (&http.Client{Timeout: awid.APITimeout()}).Do(req)
	if err != nil {
		return nil, &replacementRosterOutcomeUnknownError{err: err}
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, &replacementRosterOutcomeUnknownError{err: err}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		err := fmt.Errorf("aweb replace-key returned %d: %s", resp.StatusCode, strings.TrimSpace(string(responseBody)))
		if resp.StatusCode == http.StatusRequestTimeout || resp.StatusCode >= 500 {
			return nil, &replacementRosterOutcomeUnknownError{err: err}
		}
		return nil, err
	}
	var out localIdentityKeyReplacementResponse
	if err := json.Unmarshal(responseBody, &out); err != nil {
		return nil, &replacementRosterOutcomeUnknownError{err: fmt.Errorf("decode aweb replace-key response: %w", err)}
	}
	controllerDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	if out.Status != "replaced" || out.AuditID == "" || out.AgentID == "" || out.AuthorizedAt == "" || out.AuthorizedBy != controllerDID || out.TeamID != payload.TeamID || out.Alias != alias || out.OldDIDKey != payload.OldDIDKey || out.NewDIDKey != payload.NewDIDKey || out.OldCertificateID != payload.OldCertificateID || out.NewCertificateID != payload.NewCertificateID {
		return nil, &replacementRosterOutcomeUnknownError{err: errors.New("aweb replace-key response does not match the authorized transition")}
	}
	return &out, nil
}

func formatTeamHumanReplaceKey(v any) string {
	out := v.(teamHumanReplaceKeyOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Replaced local identity key for %s in %s\n", out.Alias, out.TeamID)
	fmt.Fprintf(&b, "  old did:key: %s\n  new did:key: %s\n", out.OldDIDKey, out.NewDIDKey)
	fmt.Fprintf(&b, "  audit: %s (authorized by %s at %s)\n", out.AuditID, out.AuthorizedBy, out.AuthorizedAt)
	if out.CertificatePath != "" {
		fmt.Fprintf(&b, "  replacement certificate installed: %s\n", out.CertificatePath)
	} else {
		fmt.Fprintf(&b, "  replacement team certificate: %s\n  placement: %s\n", out.TeamCertificate, out.Placement)
	}
	return b.String()
}
