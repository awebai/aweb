package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/handoff"
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
}

// ownerRemovalTargetKinds are the classifications the service may freeze.
var ownerRemovalTargetKinds = map[any]bool{"agent": true, "kind not verified": true}

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
		"operation": "team.agent.remove", "variant": "owner_approved",
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
	if frozen == nil {
		return nil, withErrorCode("signed_request_invalid", fmt.Errorf("operation %s: the signed revocation is not the one aw requested: its prepared operation was never verified; run the same command again to continue it", operationID))
	}
	if err := signedFrozenRevocation(receipt.Result, frozen, binding.AuthorityKeyDID); err != nil {
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
	artifact, _ := request["artifact"].(map[string]any)
	if artifact["controller_did"] != controllerDID {
		return withErrorCode("operation_mismatch", errors.New("the prepared revocation names another controller than the profile pins"))
	}
	if request["requester_key"] != requesterKey {
		return withErrorCode("operation_mismatch", errors.New("the prepared revocation names another requester key than this home's"))
	}
	if !ownerRemovalTargetKinds[request["target_kind"]] {
		return withErrorCode("operation_mismatch", errors.New("the prepared revocation classifies its target with a kind aw does not know"))
	}
	*kept = request
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
		if savedOwnerRemovalOf(profile, binding, saved, team, certificateID, nil) {
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
