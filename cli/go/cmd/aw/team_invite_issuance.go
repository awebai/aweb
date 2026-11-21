package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type nativeInviteRegistrationRequest struct {
	Invite      *awconfig.TeamInvite
	Certificate *awid.TeamCertificate
	TeamKey     ed25519.PrivateKey
	MemberKey   ed25519.PrivateKey
	Registry    *awid.RegistryClient
	RegistryURL string
}

// An inconclusive reconciliation must not be mistaken for a definite refusal
// of the original write (docs/cli-integration-contract.md:161-198).
type nativeInviteRegistrationUnknownError struct{ cause error }

func (e *nativeInviteRegistrationUnknownError) Error() string { return e.cause.Error() }
func (e *nativeInviteRegistrationUnknownError) Unwrap() error { return e.cause }

// A retained or uncertain issuance needs this recipient's existing credential
// for reconciliation, even through outer setup failure (docs/cli-integration-contract.md:161-198).
func (e *nativeInviteRegistrationUnknownError) RetainsIdentity() bool { return true }

// An already-registered reply succeeds only after fetching the exact signed
// effect, not merely a certificate for the same alias (docs/cli-integration-contract.md:161-198).
func registerExactNativeInviteCertificate(ctx context.Context, request nativeInviteRegistrationRequest) error {
	issuer := teamMembershipIssuer{
		TeamID: awid.BuildTeamID(request.Invite.Domain, request.Invite.TeamName), Key: request.TeamKey,
		Registry: request.Registry, RegistryURL: request.RegistryURL,
	}
	err := issuer.register(ctx, request.Certificate)
	if err == nil {
		return nil
	}
	var registered *awid.CertificateAlreadyRegisteredError
	if !errors.As(err, &registered) {
		return err
	}
	fetched, fetchErr := request.Registry.FetchTeamCertificate(ctx, request.RegistryURL, request.Invite.Domain, request.Invite.TeamName, request.Certificate.CertificateID, request.MemberKey)
	if fetchErr != nil {
		return &nativeInviteRegistrationUnknownError{cause: fmt.Errorf("verify already-registered certificate: %w", fetchErr)}
	}
	expected, encodeErr := awid.EncodeTeamCertificateHeader(request.Certificate)
	if encodeErr != nil {
		return &nativeInviteRegistrationUnknownError{cause: encodeErr}
	}
	actual, encodeErr := awid.EncodeTeamCertificateHeader(fetched)
	if encodeErr != nil {
		return &nativeInviteRegistrationUnknownError{cause: encodeErr}
	}
	if expected != actual {
		return &nativeInviteRegistrationUnknownError{cause: errors.New("registry certificate differs from the exact retained issuance")}
	}
	status, statusErr := request.Registry.GetTeamCertificateStatus(ctx, request.RegistryURL, request.Invite.Domain, request.Invite.TeamName, request.Certificate.CertificateID)
	if statusErr != nil {
		return &nativeInviteRegistrationUnknownError{cause: statusErr}
	}
	if status.TeamID != request.Certificate.Team || status.TeamDIDKey != request.Certificate.TeamDIDKey || status.Status != "active" || status.RevokedAt != nil {
		return &nativeInviteRegistrationUnknownError{cause: errors.New("retained certificate is not confirmed active in its exact team")}
	}
	return nil
}

func nativeInviteRegistrationDefinitelyRefused(err error) bool {
	var unknown *nativeInviteRegistrationUnknownError
	if errors.As(err, &unknown) {
		return false
	}
	var refusal *awid.RegistryError
	if !errors.As(err, &refusal) {
		return false
	}
	switch refusal.StatusCode {
	case http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusConflict, http.StatusUnprocessableEntity:
		return true
	default:
		return false
	}
}

func nativeInviteIssuanceRefusal(invite *awconfig.TeamInvite, cause error) error {
	check := formatShellCommand(nativeInviteCheckArgv(invite))
	if cause == nil {
		cause = awconfig.ErrInviteIssuanceUnknown
	}
	retained := &nativeInviteRegistrationUnknownError{cause: cause}
	return withErrorCode("invite_issuance_pending", fmt.Errorf("invite %s issuance is incomplete or unknown: %w; retain the recipient key and invite record, then run `%s` to check its exact certificate before cancelling or resuming", invite.InviteID, retained, check))
}

func nativeInviteRenewalRefusal(cause error) error {
	if cause == nil {
		cause = awconfig.ErrTeamInviteLifetime
	}
	return withErrorCode("invite_unknown_or_expired", &plainRefusal{text: "This invitation is unknown or expired; ask its issuer for a new invite.", err: cause})
}

func nativeInviteCheckArgv(invite *awconfig.TeamInvite) []string {
	args := []string{"aw"}
	issuance, err := awconfig.InspectTeamInviteIssuance(invite)
	if err == nil && issuance != nil {
		args = append(args, "--identity-home", issuance.Context.IdentityHome)
	}
	return append(args, "id", "team", "check-invite", "--invite-id", invite.InviteID, "--json")
}

type nativeInviteResumeRequest struct {
	WorkingDir string
	Options    teamAcceptInviteOptions
	Invite     *awconfig.TeamInvite
	Issuance   *awconfig.TeamInviteIssuance
}

// Resumption holds the invite lock and replays only the frozen effect; neither
// enrollment selection nor certificate signing runs again (docs/cli-integration-contract.md:161-198).
func resumeNativeInviteIssuance(ctx context.Context, request nativeInviteResumeRequest) (*acceptedTeamInvite, error) {
	invite, issuance := request.Invite, request.Issuance
	cert := &issuance.PreparedEffect
	key, err := validateNativeInviteResumeTarget(request)
	if err != nil {
		return nil, err
	}
	if issuance.State == awconfig.RecoveryAttempted {
		teamKey, err := awconfig.LoadTeamKey(invite.Domain, invite.TeamName)
		if err != nil {
			return nil, nativeInviteIssuanceRefusal(invite, err)
		}
		pub, err := teamInviteSigningPublicKey(teamKey)
		if err != nil {
			return nil, err
		}
		if err := awid.VerifyTeamCertificate(cert, pub); err != nil {
			return nil, nativeInviteIssuanceRefusal(invite, err)
		}
		registry, err := newConfiguredRegistryClient(nil)
		if err != nil {
			return nil, err
		}
		if err := registerExactNativeInviteCertificate(ctx, nativeInviteRegistrationRequest{Invite: invite, Certificate: cert, TeamKey: teamKey, MemberKey: key, Registry: registry, RegistryURL: issuance.Context.RegistryURL}); err != nil {
			// An earlier submission may still finish. A refusal of this replay,
			// or a later 404, cannot prove that earlier effect never happened.
			return nil, nativeInviteIssuanceRefusal(invite, err)
		}
		if err := awconfig.ConfirmTeamInviteIssuance(awconfig.TeamInviteIssuanceOutcomeInput{InviteID: invite.InviteID, CertificateID: cert.CertificateID, Now: time.Now()}); err != nil {
			return nil, nativeInviteIssuanceRefusal(invite, err)
		}
	}
	certPath, err := saveAcceptedTeamCertificate(request.WorkingDir, issuance.Context.IdentityHome, cert.Team, cert)
	if err != nil {
		return nil, issuedInvitePersistenceRefusal(issuedInvitePersistenceFailure{Cause: err, Invite: invite, Certificate: cert, RegistryURL: issuance.Context.RegistryURL})
	}
	if issuance.Context.ParentInviteID != "" {
		if err := recordConsumedTeamInvite(issuance.Context.ParentInviteID); err != nil {
			return nil, nativeInviteIssuanceRefusal(invite, err)
		}
	}
	return &acceptedTeamInvite{
		Output:      &teamAcceptInviteOutput{Status: "accepted", TeamID: cert.Team, Alias: cert.Alias, CertPath: certPath},
		Certificate: cert, RegistryURL: issuance.Context.RegistryURL, AwebURL: issuance.Context.AwebURL, Domain: invite.Domain, TeamName: invite.TeamName,
	}, nil
}

func validateNativeInviteResumeTarget(request nativeInviteResumeRequest) (ed25519.PrivateKey, error) {
	cert, frozen := &request.Issuance.PreparedEffect, request.Issuance.Context
	home, err := identityHomeForTarget(request.WorkingDir, request.Options.IdentityHome)
	if err != nil {
		return nil, err
	}
	aliasChanged := request.Options.Name != "" && strings.TrimSpace(request.Options.Name) != cert.Alias
	addressChanged := request.Options.Address != "" && strings.TrimSpace(request.Options.Address) != cert.MemberAddress
	scopeChanged := request.Options.Scope != "" && request.Options.Scope != cert.IdentityScope
	addressRemoved := request.Options.NoAddress && cert.MemberAddress != ""
	if home.Root != frozen.IdentityHome || aliasChanged || addressChanged || scopeChanged || addressRemoved {
		recovery := formatShellCommand([]string{"aw", "--identity-home", frozen.IdentityHome, "id", "team", "resume-invite", "--invite-id", request.Invite.InviteID})
		return nil, usageError("invite recovery must use its original home, member and scope; run `%s` without changing the recorded selection", recovery)
	}
	key, err := awid.LoadSigningKey(filepath.Join(home.Root, "signing.key"))
	if err != nil {
		return nil, fmt.Errorf("load original recipient key: %w; restore the exact recipient key in its recorded home before resuming", err)
	}
	pub, err := teamInviteSigningPublicKey(key)
	if err != nil {
		return nil, err
	}
	if awid.ComputeDIDKey(pub) != cert.MemberDIDKey {
		return nil, usageError("recipient key does not match the retained certificate; restore the original recipient key before resuming")
	}
	existingCertificate, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home.Root, cert.Team)
	if err == nil && existingCertificate.CertificateID != cert.CertificateID {
		return nil, usageError("recorded recipient home now holds another certificate; restore its original state before resuming this invite")
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read recipient certificate path: %w; repair its certificate path before resuming the exact invite", err)
	}
	state, err := loadOptionalTeamState(teamMembershipLocation{WorkingDir: request.WorkingDir, IdentityHome: home.Root})
	if err != nil {
		return nil, err
	}
	if state != nil {
		for _, membership := range state.Memberships {
			if membership.TeamID != cert.Team {
				return nil, usageError("recorded recipient home now holds another membership; restore its original state before resuming this invite")
			}
			path, err := awconfig.IdentityHomePath(home, membership.CertPath)
			if err != nil {
				return nil, err
			}
			existing, err := awid.LoadTeamCertificate(path)
			if err != nil {
				return nil, err
			}
			if existing.CertificateID != cert.CertificateID {
				return nil, usageError("recorded recipient home now holds another certificate; restore its original state before resuming this invite")
			}
		}
	}
	return key, nil
}

func canResumeNativeInviteIssuance(token, home string) bool {
	decoded, err := awconfig.DecodeInviteToken(token)
	if err != nil {
		return false
	}
	invite, err := awconfig.LoadTeamInvite(decoded.InviteID)
	if err != nil {
		return false
	}
	issuance, err := awconfig.InspectTeamInviteIssuance(invite)
	if err != nil || issuance == nil {
		return false
	}
	_, err = validateNativeInviteResumeTarget(nativeInviteResumeRequest{Options: teamAcceptInviteOptions{IdentityHome: home}, Invite: invite, Issuance: issuance})
	return err == nil
}
