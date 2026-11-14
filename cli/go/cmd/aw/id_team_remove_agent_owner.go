package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
	"github.com/spf13/cobra"
)

// An agent membership's owner-approved removal
// (team.agent.remove/owner_approved, docs/human-assurance-contract.md): the
// team's current owner approves, live, the revocation of one agent or
// unverified-kind membership, whoever admitted it. A registered requester
// with the binding's requester grant asks for it; its key is recorded, never
// authority. The protected service signs the registry's revoke request with
// the controller key only it holds once the owner approves; aw checks that
// what was signed is exactly that revocation under the profile's pinned key.

// ownerRemovalRequest is one owner-approved removal as the caller names it:
// the membership in the certificate file Certificate, or the certificate
// CertificateID of Team as the registry's active listing, read through List,
// holds it. RequesterKey is this home's authenticated key.
type ownerRemovalRequest struct {
	OperationID   string
	Certificate   string
	Team          string
	CertificateID string
	RequesterKey  string
	List          func(ctx context.Context, team string) ([]awid.RegistryCertificate, error)
	// Replace names an earlier unfinished removal of the same membership
	// that aw cannot continue, which the human asks to replace.
	Replace string
	// Reader gives the options to read an earlier request's receipt under
	// its own scope, and false when the profile no longer binds it. Without
	// it, only the current binding's scope is read.
	Reader func(scope map[string]any) (handoff.GovernanceOptions, bool)
}

// membershipSubject is the closed subject naming cert's exact membership.
// The membership snapshot keeps absent fields as explicit nulls.
func membershipSubject(cert *awid.TeamCertificate) map[string]any {
	nullable := func(value string) any {
		if value == "" {
			return nil
		}
		return value
	}
	memberID := cert.MemberDIDKey
	if cert.MemberDIDAW != "" {
		memberID = cert.MemberDIDAW
	}
	return map[string]any{
		"team_id": cert.Team, "member_id": memberID, "certificate_id": cert.CertificateID,
		"expected_membership": map[string]any{
			"member_did_key": cert.MemberDIDKey, "member_did_aw": nullable(cert.MemberDIDAW),
			"member_address": nullable(cert.MemberAddress), "alias": cert.Alias, "identity_scope": cert.IdentityScope,
		},
	}
}

// ownerRemovalIntent is the prepare body, without the members aw sets,
// removing cert's membership under binding.
func ownerRemovalIntent(profile *handoff.Profile, binding *handoff.ProfileBinding, cert *awid.TeamCertificate) map[string]any {
	return map[string]any{
		"operation": "team.agent.remove", "variant": "owner_approved", "approval_format": "intent_v1",
		"scope": binding.Scope, "audience": profile.RegistryOrigin, "subject": membershipSubject(cert),
	}
}

// removeMemberAsOwner runs request's owner-approved removal and returns its
// report: committed once the controller's signature over exactly the frozen
// revocation verifies, or pending while the owner has not decided. A saved
// operation for the same target is continued from its saved bytes without
// reading the listing, so a removal whose answer was lost recovers by its
// receipt after the certificate has left the listing. The saved request is
// forgotten only after a verified commit or an owned refusal.
func removeMemberAsOwner(ctx context.Context, opts handoff.GovernanceOptions, profile *handoff.Profile, request ownerRemovalRequest) (map[string]any, error) {
	team, certificateID := request.Team, request.CertificateID
	var fileCert *awid.TeamCertificate
	if request.Certificate != "" {
		cert, err := awid.LoadTeamCertificate(request.Certificate)
		if err != nil {
			return nil, withErrorCode("certificate_invalid", fmt.Errorf("%s is not a team certificate: %w", request.Certificate, err))
		}
		fileCert, team, certificateID = cert, cert.Team, cert.CertificateID
	}
	binding, err := admissionBinding(profile, team)
	if err != nil {
		return nil, err
	}
	reader := request.Reader
	if reader == nil {
		reader = func(scope map[string]any) (handoff.GovernanceOptions, bool) {
			return opts, sameCanonical(scope, binding.Scope)
		}
	}
	target := ownerRemovalIntent(profile, binding, &awid.TeamCertificate{Team: team, CertificateID: certificateID})
	settled, err := guardUnfinished(ctx, opts.Notify, profile, reader, target, sameRemovalTarget, request.Replace, keepUnverifiedRemoval)
	if err != nil || settled != nil {
		return settled, err
	}
	saved, err := savedOwnerRemovalFor(profile, binding, request.OperationID, team, certificateID, fileCert)
	if err != nil {
		return nil, err
	}

	var frozen map[string]any
	opts.Forget = nil
	requesterKey := request.RequesterKey
	opts.CheckPrepared = func(_ context.Context, prepared map[string]any) error {
		return ownerRemovalCheck(prepared, binding.AuthorityKeyDID, requesterKey, &frozen)
	}
	var presented *handoff.Prepared
	var page string
	opts.OnPresented = func(prepared *handoff.Prepared, shown string) { presented, page = prepared, shown }

	var operationID string
	var receipt *handoff.Receipt
	if saved != nil {
		operationID = saved.OperationID
		fmt.Fprintf(opts.Notify, "Continuing the same removal from before (operation %s)\n", operationID)
		receipt, err = handoff.Resume(ctx, opts, saved.Body)
	} else {
		cert := fileCert
		if cert == nil {
			if cert, err = listedCertificate(ctx, request.List, team, certificateID); err != nil {
				return nil, err
			}
		}
		if operationID = request.OperationID; operationID == "" {
			if operationID, err = awid.GenerateUUID4(); err != nil {
				return nil, err
			}
		}
		receipt, err = handoff.Approve(ctx, opts, operationID, ownerRemovalIntent(profile, binding, cert))
	}
	if receipt != nil && receipt.State == "refused" {
		forgetProtectedOperationQuietly(operationID)
	}
	if err != nil {
		if code := handoff.ErrorCode(err); code != "" {
			return nil, withErrorCode(code, fmt.Errorf("%w (operation %s)", err, operationID))
		}
		return nil, fmt.Errorf("operation %s: %w", operationID, err)
	}
	if receipt.State == "pending" {
		if presented == nil {
			return nil, fmt.Errorf("operation %s is pending, but its prepared request was never shown", operationID)
		}
		return pendingEndorsementReport(presented, page, receipt), nil
	}
	if err := issuedRevocation(receipt.Result, operationID, frozen, binding.AuthorityKeyDID); err != nil {
		return nil, fmt.Errorf("operation %s: %w", operationID, err)
	}
	forgetProtectedOperationQuietly(operationID)
	subject, _ := frozen["subject"].(map[string]any)
	membership, _ := subject["expected_membership"].(map[string]any)
	return map[string]any{
		"operation_id": operationID, "state": receipt.State, "team_id": subject["team_id"], "certificate_id": subject["certificate_id"],
		"alias": membership["alias"], "target_kind": frozen["target_kind"],
	}, nil
}

// ownerRemovalCheck accepts a verified prepared removal only when the profile's
// pinned controller signs it and it names this home's key as the requester. It
// keeps the frozen request it accepted in kept.
func ownerRemovalCheck(request map[string]any, controllerDID, requesterKey string, kept *map[string]any) error {
	template, err := handoff.IntentTemplate(request)
	if err != nil {
		return err
	}
	if template["controller_did"] != controllerDID {
		return withErrorCode("operation_mismatch", errors.New("the prepared revocation names another controller than the profile pins"))
	}
	if request["requester_key"] != requesterKey {
		return withErrorCode("operation_mismatch", errors.New("the prepared revocation names another requester key than this home's"))
	}
	// The generated verifier has already closed target_kind to the
	// classifications the service may freeze.
	*kept = request
	return nil
}

// issuedRevocation accepts a committed removal's result only as the registry
// revocation issued under the owner's approval of the frozen intent: the
// receipt's retained signed request for operationID, canonical, equal to the
// intent's template in every static field with its timestamp inside the
// frozen issuance window, and signed by the pinned controller. A result whose
// prepared operation aw never verified (its prepare answer was lost) has no
// frozen intent and is never taken. Anything else is signed_request_invalid.
func issuedRevocation(result []byte, operationID string, frozen map[string]any, controllerDID string) error {
	invalid := func(format string, args ...any) error {
		return withErrorCode("signed_request_invalid", fmt.Errorf("the signed revocation is not the one the owner approved: "+format, args...))
	}
	signing, signature, reason := retainedSignedResult(result, &handoff.Prepared{OperationID: operationID})
	if reason != "" {
		return invalid("%s", reason)
	}
	issued, ok := handoff.DecodeObject(signing)
	canonical, err := awid.StrictCanonicalJSON(issued)
	if !ok || err != nil || !bytes.Equal(canonical, signing) {
		return invalid("its signed request is not canonical")
	}
	if err := handoff.VerifyIssuedArtifact(frozen, map[string]any{"controller_did": controllerDID, "request": issued}); err != nil {
		return invalid("%v", err)
	}
	if err := awid.VerifyControllerRequestSignature(controllerDID, signature, signing); err != nil {
		return invalid("it is not signed by the pinned controller: %v", err)
	}
	return nil
}

// savedOwnerRemovalFor is the saved, unfinished owner-approved removal of team's
// certificate certificateID under binding: the one under operationID when it
// is given, else the one saved for that target. A saved operation for another
// target, binding or service under operationID, or a certificate file whose
// membership is not the saved one, is operation_conflict; nothing new is
// read or sent for it.
func savedOwnerRemovalFor(profile *handoff.Profile, binding *handoff.ProfileBinding, operationID, team, certificateID string, fileCert *awid.TeamCertificate) (*awconfig.PendingGovernanceOperation, error) {
	conflict := func(id string) error {
		return withErrorCode("operation_conflict", fmt.Errorf("operation %s was requested for another membership, binding or service; a changed removal needs a new operation id", id))
	}
	if operationID != "" {
		if err := validOperationID(operationID); err != nil {
			return nil, err
		}
		saved, err := awconfig.LoadPendingGovernanceOperation(operationID)
		if err != nil || saved == nil {
			return nil, err
		}
		if saved.Quarantine != nil {
			return nil, quarantinedOperation(operationID)
		}
		if !savedOwnerRemovalOf(profile, binding, saved, team, certificateID, fileCert) {
			return nil, conflict(operationID)
		}
		return saved, nil
	}
	all, err := awconfig.ListPendingGovernanceOperations()
	if err != nil {
		return nil, err
	}
	var matches []*awconfig.PendingGovernanceOperation
	for _, saved := range all {
		if saved.Quarantine == nil && savedOwnerRemovalOf(profile, binding, saved, team, certificateID, nil) {
			matches = append(matches, saved)
		}
	}
	switch len(matches) {
	case 0:
		return nil, nil
	case 1:
		if !savedOwnerRemovalOf(profile, binding, matches[0], team, certificateID, fileCert) {
			return nil, conflict(matches[0].OperationID)
		}
		return matches[0], nil
	}
	return nil, usageError("operations %s and %s both wait on removing certificate %s; pass --operation-id to choose one", matches[0].OperationID, matches[1].OperationID, certificateID)
}

// savedOwnerRemovalOf reports whether saved is an owner-approved removal at
// profile's service under binding of team's certificate certificateID, and,
// with fileCert, of exactly its membership.
func savedOwnerRemovalOf(profile *handoff.Profile, binding *handoff.ProfileBinding, saved *awconfig.PendingGovernanceOperation, team, certificateID string, fileCert *awid.TeamCertificate) bool {
	if saved.RequestOrigin != profile.RequestOrigin || saved.HumanOrigin != profile.HumanOrigin {
		return false
	}
	body, ok := handoff.DecodeObject(saved.Body)
	if !ok || body["operation_id"] != saved.OperationID || body["operation"] != "team.agent.remove" || body["variant"] != "owner_approved" ||
		body["audience"] != profile.RegistryOrigin || !sameCanonical(body["scope"], binding.Scope) {
		return false
	}
	subject, _ := body["subject"].(map[string]any)
	if subject["team_id"] != team || subject["certificate_id"] != certificateID {
		return false
	}
	return fileCert == nil || sameCanonical(subject, membershipSubject(fileCert))
}

// sameCanonical reports whether a and b have the same canonical JSON.
func sameCanonical(a, b any) bool {
	left, errLeft := intentCanonical(map[string]any{"v": a})
	right, errRight := intentCanonical(map[string]any{"v": b})
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

// listedCertificate is team's certificate certificateID as exactly one
// active, well-formed row of the registry's listing. A listing that cannot be
// read is returned as its own error, never as a missing certificate.
func listedCertificate(ctx context.Context, list func(context.Context, string) ([]awid.RegistryCertificate, error), team, certificateID string) (*awid.TeamCertificate, error) {
	if list == nil {
		return nil, usageError("no registry listing to select certificate %s from; pass --certificate with its file", certificateID)
	}
	rows, err := list(ctx, team)
	if err != nil {
		return nil, fmt.Errorf("the registry's certificate listing for %s could not be read: %w", team, err)
	}
	var found []awid.RegistryCertificate
	for _, row := range rows {
		if row.CertificateID == certificateID {
			found = append(found, row)
		}
	}
	switch {
	case len(found) == 0:
		return nil, withErrorCode("certificate_not_found", fmt.Errorf("team %s's active listing has no certificate %s", team, certificateID))
	case len(found) > 1:
		return nil, withErrorCode("certificate_listing_invalid", fmt.Errorf("team %s's listing holds certificate %s %d times", team, certificateID, len(found)))
	}
	row := found[0]
	if row.RevokedAt != "" {
		return nil, withErrorCode("certificate_revoked", fmt.Errorf("certificate %s of team %s is already revoked", certificateID, team))
	}
	validScope := row.IdentityScope == awid.IdentityModeLocal || (row.IdentityScope == awid.IdentityModeGlobal && row.MemberDIDAW != "")
	if row.TeamID != team || row.MemberDIDKey == "" || row.Alias == "" || !validScope {
		return nil, withErrorCode("certificate_listing_invalid", fmt.Errorf("team %s's listing of certificate %s is not a well-formed membership", team, certificateID))
	}
	return &awid.TeamCertificate{Team: row.TeamID, CertificateID: row.CertificateID, MemberDIDKey: row.MemberDIDKey,
		MemberDIDAW: row.MemberDIDAW, MemberAddress: row.MemberAddress, Alias: row.Alias, IdentityScope: row.IdentityScope}, nil
}

// memberCertificateListing reads a team's active certificate listing at the
// profile's pinned registry as a current member of exactly that team: this
// home's own certificate for the team (ownCertificate) must name this home's
// key, be issued by the team key the registry reports, and be active in the
// registry's public certificate status. Only then is the listing read,
// signed by that member key. Without that proof the selector is
// selector_unauthorized, and the membership's certificate file can still be
// named with --certificate. The listing is only a selector: the owner's
// approval of the frozen target authorizes the removal.
func memberCertificateListing(registry *awid.RegistryClient, profile *handoff.Profile, key ed25519.PrivateKey,
	ownCertificate func(team string) (*awid.TeamCertificate, error)) (func(context.Context, string) ([]awid.RegistryCertificate, error), error) {
	if key == nil {
		return nil, withErrorCode("selector_unauthorized", errors.New("this home's key is not in the home, so it cannot read the team's private certificate listing; pass --certificate with the certificate's file"))
	}
	return func(ctx context.Context, team string) ([]awid.RegistryCertificate, error) {
		domain, name, err := awid.ParseTeamID(team)
		if err != nil {
			return nil, err
		}
		unauthorized := func(why string) error {
			return withErrorCode("selector_unauthorized", fmt.Errorf("%s, so it cannot select from team %s's listing; pass --certificate with the certificate's file", why, team))
		}
		own, err := ownCertificate(team)
		if err != nil || own == nil {
			return nil, unauthorized("this home holds no membership certificate for the team")
		}
		if own.Team != team || own.MemberDIDKey != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
			return nil, unauthorized("this home's certificate for the team is not its own membership")
		}
		status, err := registry.GetTeamCertificateStatus(ctx, profile.RegistryOrigin, domain, name, own.CertificateID)
		if err != nil {
			if code, ok := awid.HTTPStatusCode(err); ok && code == http.StatusNotFound {
				return nil, unauthorized("this home's membership of the team is not registered")
			}
			return nil, fmt.Errorf("this home's membership of team %s could not be confirmed: %w", team, err)
		}
		if status.Status != "active" || status.TeamID != team {
			return nil, unauthorized("this home's membership of the team is not current")
		}
		if err := awid.CheckDecodedTeamCertificate(own, status.TeamDIDKey); err != nil {
			return nil, unauthorized("this home's certificate for the team is not issued by the team's key")
		}
		return registry.ListCertificates(ctx, profile.RegistryOrigin, domain, name, true, key)
	}, nil
}

// ownerRemovalTargetFlags checks that an owner-approved removal names its
// target exactly one way: a certificate file, or a team and a certificate id.
func ownerRemovalTargetFlags(certificate, team, certificateID string) error {
	switch {
	case certificate != "" && team == "" && certificateID == "":
		return nil
	case certificate == "" && team != "" && certificateID != "":
		return nil
	}
	return usageError("name the membership either with --certificate, or with --team and --certificate-id")
}

func runTeamRemoveAgentAsOwner(cmd *cobra.Command) error {
	request := ownerRemovalRequest{
		OperationID: strings.TrimSpace(teamRemoveAgentOperationIDFlag), Certificate: strings.TrimSpace(teamRemoveAgentCertificateFlag),
		Team: strings.TrimSpace(teamRemoveAgentTeamFlag), CertificateID: strings.TrimSpace(teamRemoveAgentCertificateIDFlag),
		Replace: strings.TrimSpace(teamRemoveAgentReplaceFlag),
	}
	if err := ownerRemovalTargetFlags(request.Certificate, request.Team, request.CertificateID); err != nil {
		return err
	}
	profile, err := loadProtectedProfile()
	if err != nil {
		return err
	}
	identity, err := resolveLocalSigningIdentity()
	if err != nil {
		return err
	}
	if identity.StableID == "" {
		return usageError("only a registered requester (with a did:aw) can request a removal")
	}
	request.RequesterKey, request.Reader = identity.DIDKey, requesterOptions(cmd, profile, identity)
	team := request.Team
	if request.Certificate != "" {
		cert, err := awid.LoadTeamCertificate(request.Certificate)
		if err != nil {
			return withErrorCode("certificate_invalid", fmt.Errorf("%s is not a team certificate: %w", request.Certificate, err))
		}
		team = cert.Team
	}
	binding, err := admissionBinding(profile, team)
	if err != nil {
		return err
	}
	if request.Certificate == "" {
		// Built here, read only for a new removal: a saved one continues
		// without the listing.
		registry, err := newConfiguredRegistryClient(nil)
		if err != nil {
			return err
		}
		if err := registry.TrustRegistryOrigin(profile.RegistryOrigin); err != nil {
			return err
		}
		request.List = func(ctx context.Context, team string) ([]awid.RegistryCertificate, error) {
			list, err := memberCertificateListing(registry, profile, identity.SigningKey, homeTeamCertificate(identity))
			if err != nil {
				return nil, err
			}
			return list(ctx, team)
		}
	}
	opts := governanceOptions(cmd, profile, binding.Scope, identity)
	if teamRemoveAgentNoBrowserFlag {
		opts.Open = nil
	}
	opts.NoWait = teamRemoveAgentNoWaitFlag
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()
	fmt.Fprintf(cmd.ErrOrStderr(), "Removing certificate %s from %s with the owner's approval, through %s\n",
		cmp.Or(request.CertificateID, request.Certificate), team, profile.ServiceID)
	report, err := removeMemberAsOwner(ctx, opts, profile, request)
	if err != nil {
		return err
	}
	if report["state"] == "pending" {
		printOutput(report, func(any) string { return pendingEndorsementText(report) })
		return nil
	}
	printOutput(report, func(any) string {
		return fmt.Sprintf("Operation %s committed; %s's membership of %s (certificate %s, %s) is removed\n",
			report["operation_id"], report["alias"], report["team_id"], report["certificate_id"], targetKindText(report["target_kind"]))
	})
	return nil
}

// targetKindText says what the service froze about the removed member's kind.
func targetKindText(kind any) string {
	if kind == "kind not verified" {
		return "kind not verified"
	}
	return "a verified agent"
}

// sameRemovalTarget compares two removal subjects by team and certificate:
// a removal's snapshot may be gone from the listing once it took effect.
func sameRemovalTarget(saved, asked any) bool {
	a, _ := saved.(map[string]any)
	b, _ := asked.(map[string]any)
	return a["team_id"] == b["team_id"] && a["certificate_id"] == b["certificate_id"]
}

// keepUnverifiedRemoval keeps an unfinished removal's committed receipt with
// the signed bytes its result carries for that operation: aw no longer holds
// the intent that request froze, so it cannot verify them.
func keepUnverifiedRemoval(saved *awconfig.PendingGovernanceOperation, _ map[string]any, result []byte) (map[string]any, *awconfig.GovernanceQuarantine) {
	facts := &awconfig.GovernanceQuarantine{State: "committed", Verification: "unverifiable"}
	if signing, signature, reason := retainedSignedResult(result, &handoff.Prepared{OperationID: saved.OperationID}); reason == "" {
		facts.Signing, facts.Signature = signing, signature
	}
	return nil, facts
}

// homeTeamCertificate loads identity's home's own membership certificate for a
// team, from the membership its team state names.
func homeTeamCertificate(identity *localSigningIdentity) func(team string) (*awid.TeamCertificate, error) {
	return func(team string) (*awid.TeamCertificate, error) {
		state, err := awconfig.LoadTeamStateFromIdentityHome(identity.IdentityHome)
		if err != nil || state == nil {
			return nil, err
		}
		membership := state.Membership(team)
		if membership == nil || strings.TrimSpace(membership.CertPath) == "" {
			return nil, nil
		}
		path, err := awconfig.IdentityHomeStoredPath(awconfig.IdentityHome{Root: identity.IdentityHome}, membership.CertPath)
		if err != nil {
			return nil, err
		}
		return awid.LoadTeamCertificate(path)
	}
}
