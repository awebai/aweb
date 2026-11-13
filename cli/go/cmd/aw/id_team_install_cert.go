package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// installCertificateCodes are the codes install-cert refuses with. Only
// registry_unavailable is worth retrying unchanged.
var installCertificateCodes = []string{
	"certificate_invalid", "member_mismatch", "team_key_not_current", "certificate_bad_signature",
	"certificate_revoked", "certificate_unregistered", "certificate_conflict", "registry_unavailable",
}

var (
	teamInstallCertPath     string
	teamInstallCertRegistry string
)

var teamInstallCertCmd = &cobra.Command{
	Use:   "install-cert",
	Short: "Install an issued team certificate file into an identity home",
	Long: "Install a team membership certificate file, such as the one `aw id team admit`\n" +
		"wrote with --certificate-out, into the explicit --identity-home whose identity it\n" +
		"names. The certificate is checked against the registry before anything is\n" +
		"written; then `aw service init` connects the home's workspace.\n\n" +
		"Running it again with the same certificate reports already_installed and\n" +
		"completes an install that was interrupted. Refusals, with their --json codes:\n" +
		"  certificate_invalid        the file is not a team certificate, or the registry reports\n" +
		"                             a status for it that aw does not know\n" +
		"  member_mismatch            it names another key, did:aw or scope than the home's identity\n" +
		"  team_key_not_current       it is signed by a key that is not the team's current key\n" +
		"  certificate_bad_signature  its signature does not verify under that key\n" +
		"  certificate_revoked        the registry has revoked it\n" +
		"  certificate_unregistered   the registry does not hold it for this member\n" +
		"  certificate_conflict       the home holds another certificate for the team, or, for a\n" +
		"                             local identity, any membership of another team\n" +
		"  registry_unavailable       the registry could not be read; retrying may succeed",
	RunE: runTeamInstallCert,
}

func init() {
	teamInstallCertCmd.Flags().StringVar(&teamInstallCertPath, "certificate", "", "Certificate file to install")
	teamInstallCertCmd.Flags().StringVar(&teamInstallCertRegistry, "registry", "", "Registry origin the team is read from (default: the configured registry)")
	teamCmd.AddCommand(teamInstallCertCmd)
}

// teamCertificateInstall installs the certificate at CertificatePath into the
// identity home Home, checking it at RegistryURL.
type teamCertificateInstall struct {
	WorkingDir      string
	Home            string
	CertificatePath string
	RegistryURL     string
	Registry        *awid.RegistryClient
}

func installRefusal(code, format string, args ...any) error {
	return withErrorCode(code, fmt.Errorf(format, args...))
}

// commitTeamCertificate records cert in the home as one credential update.
func commitTeamCertificate(workingDir, identityHome, command string, cert *awid.TeamCertificate, registryURL string, decide func() (string, error)) (string, error) {
	home := identityHome
	if strings.TrimSpace(home) == "" {
		home = awconfig.WorktreeIdentityHome(workingDir)
	}
	encoded, err := awid.EncodeTeamCertificateFile(cert)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	op := awconfig.CredentialOperation{Command: command, Intent: awconfig.CredentialIntent(map[string]any{
		"team_id": cert.Team, "certificate_id": cert.CertificateID, "certificate_sha256": hex.EncodeToString(sum[:])})}
	var status string
	// Lock order: the home's credential lock, then the released home install
	// lock that older aw install-cert takes too, so both serialize.
	if err := awconfig.UpdateCredentials(home, op, func(begin func() error) error {
		install, err := awconfig.LockExclusive(filepath.Join(home, teamCertificateInstallLock))
		if err != nil {
			return err
		}
		defer install.Close()
		if status, err = decide(); err != nil {
			return err
		}
		return recordTeamCertificate(workingDir, identityHome, cert, registryURL, status, begin)
	}); err != nil {
		return "", credentialUpdateError(err)
	}
	intent := currentEncryptionKeyIdentityHome()
	if strings.TrimSpace(identityHome) != "" {
		intent = explicitEncryptionKeyIdentityHome(identityHome)
	}
	return status, ensureAndPublishLocalIdentityEncryptionKeyForDir(workingDir, intent)
}

// teamCertificateInstallLock serializes installs into one identity home, with
// released aw versions too.
const teamCertificateInstallLock = "team-certificate-install.lock"

// credentialUpdateError gives a refused credential update its code.
func credentialUpdateError(err error) error {
	for _, refusal := range []error{awconfig.ErrCredentialUpdateIncomplete, awconfig.ErrCredentialUpdateUnpublished} {
		if errors.Is(err, refusal) {
			return withErrorCode(refusal.Error(), err)
		}
	}
	return err
}

// membershipRecorded reports whether the home already records cert's team
// membership at registryURL, or at its own registry when registryURL is "".
func membershipRecorded(workingDir, identityHome string, cert *awid.TeamCertificate, registryURL string) bool {
	state, err := loadOptionalTeamState(workingDir, identityHome)
	if err != nil || state == nil {
		return false
	}
	membership := state.Membership(cert.Team)
	return membership != nil && membership.CertPath == awconfig.TeamCertificateRelativePath(cert.Team) &&
		(registryURL == "" || membership.RegistryURL == registryURL)
}

// installTeamCertificateFile installs c's certificate when it is a current,
// registered certificate of its team for the identity in c.Home, and refuses
// with one of installCertificateCodes before writing anything otherwise.
func installTeamCertificateFile(ctx context.Context, c teamCertificateInstall) (map[string]any, error) {
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(c.Home, "identity.yaml"))
	if err != nil {
		return nil, fmt.Errorf("load the identity in %s: %w", c.Home, err)
	}
	key, err := awid.LoadSigningKey(filepath.Join(c.Home, "signing.key"))
	if err != nil {
		return nil, fmt.Errorf("load the signing key in %s: %w", c.Home, err)
	}
	didKey := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
	cert, err := awid.LoadTeamCertificate(c.CertificatePath)
	if err != nil {
		return nil, installRefusal("certificate_invalid", "%s is not a team certificate: %v", c.CertificatePath, err)
	}
	if cert.MemberDIDKey != didKey || cert.MemberDIDAW != identity.StableID || cert.IdentityScope != identity.IdentityScope {
		return nil, installRefusal("member_mismatch", "the certificate names member %s %s (%s), not this home's identity %s %s (%s)",
			cert.MemberDIDKey, cert.MemberDIDAW, cert.IdentityScope, didKey, identity.StableID, identity.IdentityScope)
	}
	local := identity.IdentityScope == awid.IdentityModeLocal
	// Decided read-only first, so a refused home is left exactly as it was,
	// then again under the home's credential lock, so a concurrent install of
	// another certificate cannot slip in between the decision and the write,
	// which commits the home's next credential generation.
	if _, err := homeInstallStatus(c.Home, cert, local); err != nil {
		return nil, err
	}
	if err := checkCurrentTeamCertificate(ctx, c, cert); err != nil {
		return nil, err
	}
	status, err := commitTeamCertificate(c.WorkingDir, c.Home, "install-cert", cert, c.RegistryURL, func() (string, error) {
		return homeInstallStatus(c.Home, cert, local)
	})
	if err != nil {
		return nil, err
	}
	result := map[string]any{"status": status, "team_id": cert.Team, "alias": cert.Alias, "certificate_id": cert.CertificateID,
		"did_key": didKey, "identity_home": c.Home}
	if identity.StableID != "" {
		result["did_aw"] = identity.StableID
	}
	return result, nil
}

// homeInstallStatus is how home takes cert: installed when it holds none for
// cert's team, already_installed when it holds exactly cert. It refuses
// certificate_conflict when home holds another certificate for the team, or,
// for a local identity, any trace of another team.
func homeInstallStatus(home string, cert *awid.TeamCertificate, local bool) (string, error) {
	if local {
		if err := localHomeOfOtherTeam(home, cert.Team); err != nil {
			return "", err
		}
	}
	existing, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, cert.Team)
	switch {
	case os.IsNotExist(err):
		return "installed", nil
	case err != nil:
		return "", installRefusal("certificate_conflict", "%s holds a certificate for %s that cannot be read: %v", home, cert.Team, err)
	}
	same, err := sameTeamCertificate(existing, cert)
	if err != nil {
		return "", err
	}
	if !same {
		return "", installRefusal("certificate_conflict", "%s already holds certificate %s for %s", home, existing.CertificateID, cert.Team)
	}
	return "already_installed", nil
}

// localHomeOfOtherTeam refuses a local identity's home that holds any
// membership or certificate file of a team other than team: a local identity
// belongs to exactly one team (docs/identity.md).
func localHomeOfOtherTeam(home, team string) error {
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil && !os.IsNotExist(err) {
		return installRefusal("certificate_conflict", "%s holds team memberships that cannot be read: %v", home, err)
	}
	if state != nil {
		for _, membership := range state.Memberships {
			if membership.TeamID != team {
				return installRefusal("certificate_conflict", "%s is a local identity of team %s; a local identity belongs to one team", home, membership.TeamID)
			}
		}
	}
	entries, err := os.ReadDir(filepath.Join(home, "team-certs"))
	if err != nil && !os.IsNotExist(err) {
		return installRefusal("certificate_conflict", "%s holds team certificates that cannot be read: %v", home, err)
	}
	own := filepath.Base(filepath.FromSlash(awconfig.TeamCertificateRelativePath(team)))
	for _, entry := range entries {
		if entry.Name() != own {
			return installRefusal("certificate_conflict", "%s holds team certificate %s of another team; a local identity belongs to one team", home, entry.Name())
		}
	}
	return nil
}

// checkCurrentTeamCertificate refuses cert unless the registry holds it,
// unrevoked, in its team, and the team's current key signed it. It reads the
// certificate's public status, which needs no member authority: a private
// team's other reads refuse a member whose certificate is revoked, and that
// refusal must not read as an unavailable registry. The team key's signature
// binds the certificate's id to its member.
func checkCurrentTeamCertificate(ctx context.Context, c teamCertificateInstall, cert *awid.TeamCertificate) error {
	domain, name, err := awid.ParseTeamID(cert.Team)
	if err != nil {
		return installRefusal("certificate_invalid", "the certificate's team %q: %v", cert.Team, err)
	}
	status, err := c.Registry.GetTeamCertificateStatus(ctx, c.RegistryURL, domain, name, cert.CertificateID)
	if err != nil {
		var registryErr *awid.RegistryError
		if errors.As(err, &registryErr) && registryErr.StatusCode == http.StatusNotFound {
			return installRefusal("certificate_unregistered", "the registry at %s holds no certificate %s of %s", c.RegistryURL, cert.CertificateID, cert.Team)
		}
		return installRefusal("registry_unavailable", "read certificate %s of %s at %s: %v", cert.CertificateID, cert.Team, c.RegistryURL, err)
	}
	if status.TeamID != cert.Team {
		return installRefusal("certificate_unregistered", "the registry holds certificate %s for %s, not %s", cert.CertificateID, status.TeamID, cert.Team)
	}
	if cert.TeamDIDKey != status.TeamDIDKey {
		return installRefusal("team_key_not_current", "the certificate is signed by %s, not %s's current key %s", cert.TeamDIDKey, cert.Team, status.TeamDIDKey)
	}
	header, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		return installRefusal("certificate_invalid", "encode the certificate: %v", err)
	}
	if _, err := awid.CheckTeamCertificate(header, awid.TeamCertificateFacts{
		SubjectDIDKey: cert.MemberDIDKey, TeamDIDKey: status.TeamDIDKey, Registered: awid.RegistrationNotRequired(),
	}); err != nil {
		var refused *awid.TeamCertificateError
		if errors.As(err, &refused) && refused.Reason == "bad_signature" {
			return installRefusal("certificate_bad_signature", "the certificate's signature does not verify under %s", status.TeamDIDKey)
		}
		return installRefusal("certificate_invalid", "the certificate does not check: %v", err)
	}
	switch status.Status {
	case "active":
		return nil
	case "revoked":
		revokedAt := ""
		if status.RevokedAt != nil {
			revokedAt = " at " + *status.RevokedAt
		}
		return installRefusal("certificate_revoked", "certificate %s of %s was revoked%s", cert.CertificateID, cert.Team, revokedAt)
	}
	// The registry answered; a status aw does not know will not change on a
	// retry.
	return installRefusal("certificate_invalid", "the registry reports status %q for certificate %s, which aw does not know", status.Status, cert.CertificateID)
}

// sameTeamCertificate reports whether a and b are the same signed
// certificate, byte for byte.
func sameTeamCertificate(a, b *awid.TeamCertificate) (bool, error) {
	encodedA, err := awid.EncodeTeamCertificateFile(a)
	if err != nil {
		return false, err
	}
	encodedB, err := awid.EncodeTeamCertificateFile(b)
	if err != nil {
		return false, err
	}
	return bytes.Equal(encodedA, encodedB), nil
}

// recordTeamCertificate saves cert into identityHome unless status is
// already_installed and records the team membership, calling begin before its
// first credential change. Recording again completes
// an install that was interrupted; when the membership is already recorded it
// changes nothing. The encryption key is ensured after the update commits.
func recordTeamCertificate(workingDir, identityHome string, cert *awid.TeamCertificate, registryURL, status string, begin func() error) error {
	if status != "already_installed" || !membershipRecorded(workingDir, identityHome, cert, registryURL) {
		if err := begin(); err != nil {
			return err
		}
		if status != "already_installed" {
			if _, err := saveAcceptedTeamCertificate(workingDir, identityHome, cert.Team, cert); err != nil {
				return err
			}
		}
		if err := upsertAcceptedTeamMembershipState(workingDir, &teamAcceptInviteOutput{
			Status:   status,
			TeamID:   cert.Team,
			Alias:    strings.TrimSpace(cert.Alias),
			CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
		}, cert, registryURL, "", false, identityHome); err != nil {
			return err
		}
	}
	return nil
}

func runTeamInstallCert(cmd *cobra.Command, _ []string) error {
	path := strings.TrimSpace(teamInstallCertPath)
	if path == "" {
		return usageError("--certificate is required: the certificate file to install")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	if home.Source != awconfig.IdentityHomeFlag {
		return usageError("install-cert requires an explicit --identity-home: the home whose identity the certificate names")
	}
	if awconfig.IsGrantHome(home.Root) {
		return errGrantHomeRootAuthority
	}
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(teamInstallCertRegistry)
	if registryURL != "" {
		if registryURL, err = awid.CanonicalServerOrigin(registryURL); err != nil {
			return usageError("--registry: %v", err)
		}
		if err := registry.TrustRegistryOrigin(registryURL); err != nil {
			return err
		}
	} else {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	result, err := installTeamCertificateFile(ctx, teamCertificateInstall{WorkingDir: workingDir, Home: home.Root,
		CertificatePath: path, RegistryURL: registryURL, Registry: registry})
	if err != nil {
		return err
	}
	printOutput(result, func(any) string {
		return fmt.Sprintf("Certificate %s for %s as %s %s in %s\n", result["certificate_id"], result["team_id"], result["alias"], result["status"], home.Root)
	})
	return nil
}
