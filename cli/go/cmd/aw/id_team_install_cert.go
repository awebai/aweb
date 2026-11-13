package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
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
		"  certificate_invalid        the file is not a team certificate\n" +
		"  member_mismatch            it names another key, did:aw or scope than the home's identity\n" +
		"  team_key_not_current       it is signed by a key that is not the team's current key\n" +
		"  certificate_bad_signature  its signature does not verify under that key\n" +
		"  certificate_revoked        the registry has revoked it\n" +
		"  certificate_unregistered   the registry does not hold it for this member\n" +
		"  certificate_conflict       the home holds another certificate for the team\n" +
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
	if err := checkCurrentTeamCertificate(ctx, c, cert, key); err != nil {
		return nil, err
	}
	status := "installed"
	existing, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(c.Home, cert.Team)
	switch {
	case err == nil:
		same, sameErr := sameTeamCertificate(existing, cert)
		if sameErr != nil {
			return nil, sameErr
		}
		if !same {
			return nil, installRefusal("certificate_conflict", "%s already holds certificate %s for %s", c.Home, existing.CertificateID, cert.Team)
		}
		status = "already_installed"
	case !os.IsNotExist(err):
		return nil, installRefusal("certificate_conflict", "%s holds a certificate for %s that cannot be read: %v", c.Home, cert.Team, err)
	}
	if err := recordTeamCertificate(c.WorkingDir, c.Home, cert, c.RegistryURL, status); err != nil {
		return nil, err
	}
	result := map[string]any{"status": status, "team_id": cert.Team, "alias": cert.Alias, "certificate_id": cert.CertificateID,
		"did_key": didKey, "identity_home": c.Home}
	if identity.StableID != "" {
		result["did_aw"] = identity.StableID
	}
	return result, nil
}

// checkCurrentTeamCertificate refuses cert unless the registry's current key
// for its team signed it and the registry holds it, unrevoked, for its member.
func checkCurrentTeamCertificate(ctx context.Context, c teamCertificateInstall, cert *awid.TeamCertificate, key ed25519.PrivateKey) error {
	domain, name, err := awid.ParseTeamID(cert.Team)
	if err != nil {
		return installRefusal("certificate_invalid", "the certificate's team %q: %v", cert.Team, err)
	}
	unavailable := func(err error) error {
		var registryErr *awid.RegistryError
		if errors.As(err, &registryErr) && registryErr.StatusCode == http.StatusNotFound {
			return installRefusal("certificate_unregistered", "the registry at %s holds no team %s", c.RegistryURL, cert.Team)
		}
		return installRefusal("registry_unavailable", "read team %s at %s: %v", cert.Team, c.RegistryURL, err)
	}
	team, err := c.Registry.GetTeam(ctx, c.RegistryURL, domain, name, key)
	if err != nil {
		return unavailable(err)
	}
	if cert.TeamDIDKey != team.TeamDIDKey {
		return installRefusal("team_key_not_current", "the certificate is signed by %s, not %s's current key %s", cert.TeamDIDKey, cert.Team, team.TeamDIDKey)
	}
	header, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		return installRefusal("certificate_invalid", "encode the certificate: %v", err)
	}
	if _, err := awid.CheckTeamCertificate(header, awid.TeamCertificateFacts{
		SubjectDIDKey: cert.MemberDIDKey, TeamDIDKey: team.TeamDIDKey, Registered: awid.RegistrationNotRequired(),
	}); err != nil {
		var refused *awid.TeamCertificateError
		if errors.As(err, &refused) && refused.Reason == "bad_signature" {
			return installRefusal("certificate_bad_signature", "the certificate's signature does not verify under %s", team.TeamDIDKey)
		}
		return installRefusal("certificate_invalid", "the certificate does not check: %v", err)
	}
	rows, err := c.Registry.ListCertificates(ctx, c.RegistryURL, domain, name, false, key)
	if err != nil {
		return unavailable(err)
	}
	for _, row := range rows {
		if row.CertificateID != cert.CertificateID {
			continue
		}
		if row.MemberDIDKey != cert.MemberDIDKey || row.MemberDIDAW != cert.MemberDIDAW || row.Alias != cert.Alias {
			break
		}
		if strings.TrimSpace(row.RevokedAt) != "" {
			return installRefusal("certificate_revoked", "certificate %s of %s was revoked at %s", cert.CertificateID, cert.Team, row.RevokedAt)
		}
		return nil
	}
	return installRefusal("certificate_unregistered", "the registry holds no certificate %s of %s for %s", cert.CertificateID, cert.Team, cert.MemberDIDKey)
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
// already_installed, records the team membership, and ensures the identity's
// encryption key. Recording again completes an install that was interrupted.
func recordTeamCertificate(workingDir, identityHome string, cert *awid.TeamCertificate, registryURL, status string) error {
	if status != "already_installed" {
		if _, err := saveAcceptedTeamCertificate(workingDir, identityHome, cert.Team, cert); err != nil {
			return err
		}
	} else {
		registryURL = ""
	}
	if err := upsertAcceptedTeamMembershipState(workingDir, &teamAcceptInviteOutput{
		Status:   status,
		TeamID:   cert.Team,
		Alias:    strings.TrimSpace(cert.Alias),
		CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
	}, cert, registryURL, "", false, identityHome); err != nil {
		return err
	}
	intent := currentEncryptionKeyIdentityHome()
	if strings.TrimSpace(identityHome) != "" {
		intent = explicitEncryptionKeyIdentityHome(identityHome)
	}
	return ensureAndPublishLocalIdentityEncryptionKeyForDir(workingDir, intent)
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
