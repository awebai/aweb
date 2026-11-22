package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	Long: "Install an issued team membership certificate file into the explicit\n" +
		"--identity-home whose identity it names. The certificate is checked against\n" +
		"the registry before anything is written; then `aw service init` connects\n" +
		"the home's workspace.\n\n" +
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
	// Certificate, when set, is installed instead of the file at CertificatePath.
	Certificate *awid.TeamCertificate
	// Replacement names whether a verified current certificate may replace
	// material admitted under a superseded team key.
	Replacement certificateReplacementPolicy
	// WorkspacePath, when set, is the workspace binding whose membership for
	// the team is pointed at the installed certificate before anything is
	// sent with it.
	WorkspacePath string
	RegistryURL   string
	Registry      *awid.RegistryClient
}

func installRefusal(code, format string, args ...any) error {
	return withErrorCode(code, fmt.Errorf(format, args...))
}

type certificateInstallStatus string

const (
	certificateInstalled        certificateInstallStatus = "installed"
	certificateAlreadyInstalled certificateInstallStatus = "already_installed"
	certificateReplaced         certificateInstallStatus = "replaced"
)

type certificateReplacementPolicy uint8

const (
	refuseCertificateReplacement certificateReplacementPolicy = iota
	replaceSupersededCertificate
)

type certificateCommit struct {
	WorkingDir    string
	IdentityHome  string
	Command       string
	Certificate   *awid.TeamCertificate
	RegistryURL   string
	WorkspacePath string
	Decide        func() (certificateInstallStatus, error)
}

type certificateRecord struct {
	WorkingDir    string
	IdentityHome  string
	Certificate   *awid.TeamCertificate
	RegistryURL   string
	WorkspacePath string
	Status        certificateInstallStatus
	Begin         func() error
}

type homeCertificateInstall struct {
	Home        string
	Certificate *awid.TeamCertificate
	Replacement certificateReplacementPolicy
}

// commitTeamCertificate records cert in the home as one credential update,
// pointing the workspace binding at workspacePath, when set, at it, and then
// ensures the identity's encryption key, which is published with cert.
func commitTeamCertificate(input certificateCommit) (certificateInstallStatus, error) {
	workingDir, identityHome, command := input.WorkingDir, input.IdentityHome, input.Command
	cert, registryURL, workspacePath, decide := input.Certificate, input.RegistryURL, input.WorkspacePath, input.Decide

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
	var status certificateInstallStatus
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
		return recordTeamCertificate(certificateRecord{WorkingDir: workingDir, IdentityHome: identityHome, Certificate: cert, RegistryURL: registryURL, Status: status, WorkspacePath: workspacePath, Begin: begin})
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
	state, err := loadOptionalTeamState(teamMembershipLocation{WorkingDir: workingDir, IdentityHome: identityHome})
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
	cert := c.Certificate
	if cert == nil {
		cert, err = awid.LoadTeamCertificate(c.CertificatePath)
		if err != nil {
			return nil, installRefusal("certificate_invalid", "%s is not a team certificate: %v", c.CertificatePath, err)
		}
	}
	if cert.MemberDIDKey != didKey || cert.MemberDIDAW != identity.StableID || cert.IdentityScope != identity.IdentityScope {
		return nil, installRefusal("member_mismatch", "the certificate names member %s %s (%s), not this home's identity %s %s (%s)",
			cert.MemberDIDKey, cert.MemberDIDAW, cert.IdentityScope, didKey, identity.StableID, identity.IdentityScope)
	}
	// Decided read-only first, so a refused home is left exactly as it was,
	// then again under the home's credential lock, so a concurrent install of
	// another certificate cannot slip in between the decision and the write,
	// which commits the home's next credential generation.
	if _, err := homeInstallStatus(homeCertificateInstall{Home: c.Home, Certificate: cert, Replacement: c.Replacement}); err != nil {
		return nil, err
	}
	if err := checkCurrentTeamCertificate(ctx, c, cert); err != nil {
		return nil, err
	}
	status, err := commitTeamCertificate(certificateCommit{WorkingDir: c.WorkingDir, IdentityHome: c.Home, Command: "install-cert", Certificate: cert, RegistryURL: c.RegistryURL, WorkspacePath: c.WorkspacePath, Decide: func() (certificateInstallStatus, error) {
		return homeInstallStatus(homeCertificateInstall{Home: c.Home, Certificate: cert, Replacement: c.Replacement})
	}})
	if err != nil {
		return nil, err
	}
	result := map[string]any{"status": string(status), "team_id": cert.Team, "alias": cert.Alias, "certificate_id": cert.CertificateID,
		"did_key": didKey, "identity_home": c.Home}
	if identity.StableID != "" {
		result["did_aw"] = identity.StableID
	}
	return result, nil
}

// homeInstallStatus reports how the exact home takes the checked certificate.
// It installs when the home holds none for
// cert's team, already_installed when it holds exactly cert, and, with
// replacement permission, replaced when it holds one under another team key than
// cert's (checked current before the write). It refuses certificate_conflict
// when home holds another certificate for the team, or, for a local identity,
// any trace of another team.
func homeInstallStatus(input homeCertificateInstall) (certificateInstallStatus, error) {
	home, cert := input.Home, input.Certificate
	switch input.Replacement {
	case refuseCertificateReplacement, replaceSupersededCertificate:
	default:
		return "", errors.New("unknown certificate replacement policy")
	}
	if cert.IdentityScope == awid.IdentityModeLocal {
		if err := localHomeOfOtherTeam(home, cert.Team); err != nil {
			return "", err
		}
	}
	existing, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, cert.Team)
	switch {
	case os.IsNotExist(err):
		return certificateInstalled, nil
	case err != nil:
		return "", installRefusal("certificate_conflict", "%s holds a certificate for %s that cannot be read: %v", home, cert.Team, err)
	}
	same, err := sameTeamCertificate(existing, cert)
	if err != nil {
		return "", err
	}
	if !same {
		if input.Replacement == replaceSupersededCertificate && existing.TeamDIDKey != cert.TeamDIDKey && existing.MemberDIDKey == cert.MemberDIDKey && existing.Alias == cert.Alias {
			return certificateReplaced, nil
		}
		return "", installRefusal("certificate_conflict", "%s already holds certificate %s for %s", home, existing.CertificateID, cert.Team)
	}
	return certificateAlreadyInstalled, nil
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
	return c.Registry.CheckCurrentTeamCertificate(ctx, awid.CurrentTeamCertificateCheck{
		RegistryURL: c.RegistryURL, Certificate: cert,
	})
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
// first credential change. Recording again completes an install that was
// interrupted; when the membership is already recorded it changes nothing.
// With workspacePath set, it also points that workspace binding's membership
// for the team at the saved certificate.
func recordTeamCertificate(input certificateRecord) error {
	workingDir, identityHome, cert := input.WorkingDir, input.IdentityHome, input.Certificate
	registryURL, status, workspacePath, begin := input.RegistryURL, input.Status, input.WorkspacePath, input.Begin
	if status != certificateAlreadyInstalled || !membershipRecorded(workingDir, identityHome, cert, registryURL) {
		if err := begin(); err != nil {
			return err
		}
		if status != certificateAlreadyInstalled {
			if _, err := saveAcceptedTeamCertificate(workingDir, identityHome, cert.Team, cert); err != nil {
				return err
			}
		}
		if err := upsertAcceptedTeamMembershipState(teamMembershipStateUpdate{
			Location: teamMembershipLocation{WorkingDir: workingDir, IdentityHome: identityHome},
			Output: &teamAcceptInviteOutput{
				Status:   string(status),
				TeamID:   cert.Team,
				Alias:    strings.TrimSpace(cert.Alias),
				CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
			},
			Certificate: cert,
			RegistryURL: registryURL,
			AwebURL:     "",
			Activation:  membershipPreserveActive,
		}); err != nil {
			return err
		}
	}
	if strings.TrimSpace(workspacePath) == "" {
		return nil
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		return fmt.Errorf("read the workspace binding %s: %w", workspacePath, err)
	}
	installed := awconfig.TeamCertificateRelativePath(cert.Team)
	membership := workspace.Membership(cert.Team)
	if membership == nil || membership.CertPath == installed {
		return nil
	}
	if err := begin(); err != nil {
		return err
	}
	membership.CertPath = installed
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		return fmt.Errorf("certificate %s is saved, but recording it in %s failed: %w", cert.CertificateID, workspacePath, err)
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
	registryURL := firstNonEmptyString(teamInstallCertRegistry, os.Getenv("AWID_REGISTRY_URL"))
	if registryURL != "" {
		if registryURL, err = awid.CanonicalServerOrigin(registryURL); err != nil {
			return usageError("--registry: %v", err)
		}
		if err := registry.TrustRegistryOrigin(registryURL); err != nil {
			return err
		}
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
