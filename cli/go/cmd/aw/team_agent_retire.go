package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
)

// Retiring an agent has to reach two stores that fail independently: the
// coordination store, which holds the workspace record and the task claims made
// under it, and the certificate store, which holds the credential. Neither
// command that existed before covered both, so a retirement could be reported
// while the agent kept its claims or kept its certificate.
//
// Every outcome below names a store and says what happened to that store. No
// single word stands for the whole retirement, because the stores can disagree.
const (
	storeCoordination = "coordination"
	storeCertificate  = "certificate"
)

// Store outcomes. Terminal outcomes are changed and unchanged: in both the store
// ends in the state retirement wants. Blocked, failed and not_attempted are not
// terminal and leave the agent partly retired.
const (
	storeChanged      = "changed"
	storeUnchanged    = "unchanged"
	storeBlocked      = "blocked"
	storeFailed       = "failed"
	storeNotAttempted = "not_attempted"
)

// Certificate store results. Each says what its evidence supports and no more.
// The defect being fixed here was one word standing for several situations and
// asserting a removal none of them established, so these are kept apart even
// though all three end the call successfully.
const (
	// certificateRevoked: this call revoked a certificate.
	certificateRevoked = "revoked"
	// certificateAlreadyRevoked: the registry stated the certificate exists and
	// was already revoked. Only the registry establishes this; it is never
	// inferred from an absence.
	certificateAlreadyRevoked = "already_revoked"
	// certificateNothingReported: the service reported it had nothing to revoke.
	// It does not follow that no certificate exists. The hosted service answers
	// from its own membership records and may never consult the registry, so a
	// member with a live certificate and no hosted record is reported this way.
	// Establishing the certificate state needs a direct read: aw team agent-status.
	certificateNothingReported = "reported_nothing_to_revoke"
)

// Overall retirement status.
//
// retired and reported_retired differ in what backs them, not in whether the
// command succeeded. Both exit zero: nothing went wrong and a retry converges.
// The distinction is kept because collapsing evidence of different strength into
// one confident word is the defect this command exists to remove.
const (
	// retirementRetired: every store established the state retirement wants.
	retirementRetired = "retired"
	// retirementReported: every store reached that state, but at least one of
	// them rests on a service reporting a no-op rather than on the state being
	// established. Confirm with aw team agent-status, which reads the registry.
	retirementReported = "reported_retired"
	// retirementIncomplete: a store did not reach that state.
	retirementIncomplete = "incomplete"
)

type retireStoreOutcome struct {
	Store  string `json:"store"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

func (o retireStoreOutcome) terminal() bool {
	return o.Result == storeChanged || o.Result == storeUnchanged
}

type teamRemoveAgentOutput struct {
	Status            string               `json:"status"`
	TeamID            string               `json:"team_id"`
	MemberAddress     string               `json:"member_address,omitempty"`
	Alias             string               `json:"alias,omitempty"`
	CertificateResult string               `json:"certificate_result,omitempty"`
	CertificateID     string               `json:"certificate_id,omitempty"`
	WorkspaceID       string               `json:"workspace_id,omitempty"`
	OperationID       string               `json:"operation_id,omitempty"`
	RecoveryPath      string               `json:"recovery_path,omitempty"`
	ClaimsReleased    *int                 `json:"claims_released"`
	Stores            []retireStoreOutcome `json:"stores"`
}

// certificateStoreResult is what a revoke attempt did to the certificate store.
type certificateStoreResult struct {
	Result        string
	CertificateID string
	MemberAddress string
	AgentID       string
	WorkspaceID   string
}

// revokeCertificateFunc revokes the member's certificate. The hosted and BYOT
// branches supply different implementations; the retirement sequence does not
// care which, only that it runs after the coordination store is clear.
type revokeCertificateFunc func(ctx context.Context) (certificateStoreResult, error)

// retireTeamAgent clears the coordination store, then the certificate store.
//
// INVARIANT: the coordination store is cleared first. Two independent reasons
// require it, and they do not expire together.
//
// The first is that the hosted remove-member endpoint soft-deletes the workspace
// record itself without releasing anything, and the delete route will not run the
// cascade for a record already deleted. So revoking first leaves every claim held
// forever. This reason has an expiry: it stops applying once the hosted removal
// releases claims of its own.
//
// The second does not expire. An agent that still holds claims can release them
// itself right up until its certificate is revoked, and not a moment after.
// Revoking first destroys the credential needed for the cheapest way out of the
// state it just created, leaving only the cascade that the same call declined to
// run. That is true of any retirement on any team, whatever the services do.
//
// So if you are here because the hosted side now releases claims and this looks
// like it can be simplified: the first reason is gone, the second is not, and the
// order stays. Reordering on the strength of the first alone reintroduces the
// unrecoverable case.
//
// For the second reason a blocked coordination store stops the sequence rather
// than proceeding to the revoke. Revoking anyway would produce exactly the
// split state this command exists to prevent.
func retireTeamAgent(
	ctx context.Context,
	client *aweb.Client,
	teamID string,
	memberAddress string,
	alias string,
	targetVerified bool,
	revoke revokeCertificateFunc,
) teamRemoveAgentOutput {
	out := teamRemoveAgentOutput{
		TeamID:        teamID,
		MemberAddress: memberAddress,
		Alias:         alias,
	}

	coordination, deleted := releaseCoordinationState(ctx, client, alias)
	if !targetVerified {
		// Say so in the result rather than implying the workspace was the one
		// named. On a hosted team no read can establish which principal an alias
		// belongs to, so this selected by alias alone.
		coordination.Detail += " (selected by alias: the typed namespace could not be verified on this team, see aweb-aaum.9)"
	}
	out.Stores = append(out.Stores, coordination)
	if deleted != nil {
		out.WorkspaceID = deleted.WorkspaceID
		out.ClaimsReleased = deleted.ClaimsReleased
	}

	if !coordination.terminal() {
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeNotAttempted,
			Detail: "not attempted: revoking now would leave the released-nothing coordination state above with no credential able to clear it; to revoke access immediately and accept that, use aw id team remove-member",
		})
		out.Status = retirementIncomplete
		return out
	}

	certificate, err := revoke(ctx)
	switch {
	case err != nil:
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeFailed,
			Detail: err.Error(),
		})
		out.Status = retirementIncomplete
		return out
	case certificate.Result == certificateRevoked:
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeChanged,
			Detail: "revoked the member certificate",
		})
	case certificate.Result == certificateAlreadyRevoked:
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeUnchanged,
			Detail: "revoked nothing: the registry states this certificate was already revoked",
		})
	case certificate.Result == certificateNothingReported:
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeUnchanged,
			Detail: "revoked nothing: the service reported it had nothing to revoke, which does not establish that no certificate exists; confirm with aw team agent-status",
		})
	default:
		// Every result constant is handled above. A new one reaching here has no
		// agreed meaning, and the strongest status is the wrong default for an
		// answer nobody has interpreted - which is the whole argument of this
		// change applied to this switch. Unreachable on purpose beats unreachable
		// by coincidence.
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeFailed,
			Detail: fmt.Sprintf("unrecognised certificate result %q; refusing to report what it means", certificate.Result),
		})
		out.Status = retirementIncomplete
		return out
	}

	out.CertificateResult = certificate.Result
	if strings.TrimSpace(certificate.CertificateID) != "" {
		out.CertificateID = certificate.CertificateID
	}
	if strings.TrimSpace(certificate.MemberAddress) != "" {
		out.MemberAddress = certificate.MemberAddress
	}
	if strings.TrimSpace(certificate.WorkspaceID) != "" && out.WorkspaceID == "" {
		out.WorkspaceID = certificate.WorkspaceID
	}
	if certificate.Result == certificateNothingReported {
		out.Status = retirementReported
	} else {
		out.Status = retirementRetired
	}
	return out
}

// retirementSucceeded reports whether the command should exit zero. Both terminal
// statuses do: nothing went wrong and a retry converges. Only a store that did
// not reach its terminal state is a failure.
func retirementSucceeded(status string) bool {
	return status == retirementRetired || status == retirementReported
}

// releaseCoordinationState deletes the retiring agent's workspace record, which
// is what releases the task claims held under it. The claim release itself lives
// in the server lifecycle cascade; this is the only caller that reaches it on a
// retirement.
func releaseCoordinationState(
	ctx context.Context,
	client *aweb.Client,
	alias string,
) (retireStoreOutcome, *aweb.DeleteWorkspaceResponse) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resp, err := client.WorkspaceList(listCtx, aweb.WorkspaceListParams{
		Alias:           alias,
		IncludePresence: false,
		Limit:           2,
	})
	cancel()
	if err != nil {
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeFailed,
			Detail: fmt.Sprintf("could not look up the workspace record for %s: %v", alias, err),
		}, nil
	}

	matches := make([]aweb.WorkspaceInfo, 0, len(resp.Workspaces))
	for _, ws := range resp.Workspaces {
		if strings.EqualFold(strings.TrimSpace(ws.Alias), alias) {
			matches = append(matches, ws)
		}
	}

	switch len(matches) {
	case 0:
		return coordinationOutcomeWithoutWorkspace(ctx, client, alias), nil
	case 1:
	default:
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeFailed,
			Detail: fmt.Sprintf("%s names %d workspace records; retire them by workspace id with aw workspace delete", alias, len(matches)),
		}, nil
	}

	deleteCtx, deleteCancel := context.WithTimeout(ctx, 10*time.Second)
	deleted, err := client.WorkspaceDelete(deleteCtx, matches[0].WorkspaceID)
	deleteCancel()
	if err != nil {
		if code, reason := workspaceDeleteProtectiveReason(err); code != "" {
			return retireStoreOutcome{
				Store:  storeCoordination,
				Result: storeBlocked,
				Detail: fmt.Sprintf("released nothing: %s", reason),
			}, nil
		}
		// The server refuses an already-deleted workspace ONLY when its identity is
		// still bound, so this establishes a BAD fact, not a neutral one. Blocked
		// rather than unchanged: unchanged is terminal, and a terminal result here
		// lets the revoke proceed and the command exit 0 while an identity nobody
		// cleaned keeps working credentials. It is also exactly the released-nothing
		// state the non-terminal branch below declines to revoke on top of.
		if errors.Is(err, aweb.ErrWorkspaceAlreadyDeleted) {
			return retireStoreOutcome{
				Store:  storeCoordination,
				Result: storeBlocked,
				Detail: fmt.Sprintf("released nothing: workspace record for %s was already deleted and its identity was NOT cleaned; clean the identity before this retirement can be reported complete", alias),
			}, nil
		}
		// Establishes nothing: not present, or not visible to this caller.
		if errors.Is(err, aweb.ErrWorkspaceNotFound) {
			return retireStoreOutcome{
				Store:  storeCoordination,
				Result: storeBlocked,
				Detail: fmt.Sprintf("could not establish coordination state: no workspace %s is visible to this caller", matches[0].WorkspaceID),
			}, nil
		}
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeFailed,
			Detail: fmt.Sprintf("could not delete workspace %s: %v", matches[0].WorkspaceID, err),
		}, nil
	}
	if deleted == nil {
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeUnchanged,
			Detail: fmt.Sprintf("released nothing: workspace record for %s was already deleted", alias),
		}, nil
	}

	if deleted.ClaimsReleased == nil {
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeChanged,
			Detail: fmt.Sprintf(
				"deleted workspace %s, which releases its task claims; this server does not report how many, so read them back with aw team agent-status",
				deleted.WorkspaceID,
			),
		}, deleted
	}
	return retireStoreOutcome{
		Store:  storeCoordination,
		Result: storeChanged,
		Detail: fmt.Sprintf("deleted workspace %s and released %d task claim(s)", deleted.WorkspaceID, *deleted.ClaimsReleased),
	}, deleted
}

// verifyRetirementTarget establishes that the alias about to be acted on names the
// member the operator typed, BEFORE anything is written.
//
// This is a read placed ahead of both mutations, not a change to the order of
// them. The invariant on retireTeamAgent orders the two WRITES; a registry
// resolve soft-deletes nothing and destroys no credential, so it moves neither.
// It is the stronger form of the same goal: the invariant preserves a recovery
// path from a bad state, and verifying first means there is no bad state.
//
// Failing closed here has a cost worth knowing. An agent whose certificate was
// already revoked - by aw id team remove-member, which this command's own blocked
// message recommends - no longer resolves, so retirement will now refuse to clean
// up its leftover coordination state. The guidance below is what makes that
// navigable, and it has to distinguish two arrivals that need different remedies.
func verifyRetirementTarget(
	ctx context.Context,
	client *aweb.Client,
	registry *awid.RegistryClient,
	registryURL, domain, team, memberAddress, alias string,
	signers []ed25519.PrivateKey,
) (*verifiedMember, error) {
	resolveCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	var memberRef *awid.TeamMemberReference
	_, err := readSignedTeamState(signers, func(key ed25519.PrivateKey) error {
		var resolveErr error
		memberRef, resolveErr = registry.ResolveTeamMember(resolveCtx, registryURL, domain, team, alias, key)
		return resolveErr
	})
	cancel()
	if err != nil {
		// A visibility refusal is not an unresolvable member: the registry
		// answered, and what it said is that this caller may not read the
		// team. Explaining the ambiguity of a 404 would point away from the
		// actual remedy, which is a credential.
		if friendly := friendlyTeamReadError(err, awid.BuildTeamID(domain, team), len(signers) > 0); friendly != err {
			return nil, friendly
		}
		return nil, unresolvedRetirementTargetError(ctx, client, memberAddress, alias, err)
	}
	if err := verifyNamedMember(memberAddress, domain, memberRef); err != nil {
		return nil, err
	}
	return &verifiedMember{
		CertificateID: strings.TrimSpace(memberRef.CertificateID),
		MemberAddress: strings.TrimSpace(memberRef.MemberAddress),
	}, nil
}

// verifiedMember is a member this command has established is the one the operator
// named, carried forward so nothing looks it up a second time.
//
// Resolving once is not only tidier. With a resolve for the verification and
// another inside the revoke, the coordination delete lands between them: if the
// certificate changes in that window - a concurrent revoke by another holder of
// the team key, which the 409 handling exists to tolerate - the second resolve
// 404s and the command ends having cleared coordination and revoked nothing.
// That is the split state the ordering exists to prevent, reachable through a
// window that does not exist while there is only one lookup. Threading the id
// through also makes the verification and the revoke agree by construction about
// which certificate they mean, rather than by assuming two lookups returned the
// same thing.
type verifiedMember struct {
	CertificateID string
	MemberAddress string
}

// unresolvedRetirementTargetError explains a refusal the operator cannot act on
// without knowing which state they are in.
//
// The workspace lookup here is read-only and is the whole point: the remedy
// differs by whether the record still exists, and the two cases are reached by
// different routes. After a customer-controlled remove-member the record is live
// and the delete cascade still works, so naming the workspace id is a real
// remedy. After a hosted removal the record is already soft-deleted, and pointing
// at aw workspace delete would send the operator at a command that reports
// success and releases nothing - that is aweb-aaum.6. There the working route is
// the status transition, which does not need the record to exist.
func unresolvedRetirementTargetError(
	ctx context.Context,
	client *aweb.Client,
	memberAddress, alias string,
	resolveErr error,
) error {
	base := fmt.Sprintf(
		"refusing to retire %s: it does not resolve to a member of this team, so which principal the name refers to cannot be established, and retiring on the bare alias is what revokes the wrong one (%v)",
		memberAddress, resolveErr,
	)

	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	resp, listErr := client.WorkspaceList(listCtx, aweb.WorkspaceListParams{Alias: alias, Limit: 2})
	cancel()
	if listErr != nil {
		return fmt.Errorf("%s", base)
	}
	for _, ws := range resp.Workspaces {
		if strings.EqualFold(strings.TrimSpace(ws.Alias), alias) {
			return fmt.Errorf(
				"%s. A workspace record for %s is still present; if you know it is the one you mean, delete it by id with aw workspace delete %s, which names a record rather than an ambiguous alias",
				base, alias, ws.WorkspaceID,
			)
		}
	}
	return fmt.Errorf(
		"%s. No workspace record remains for %s, so aw workspace delete has nothing to act on; any task claims left behind are released by moving each claimed task out of in_progress, which does not need the record to exist",
		base, alias,
	)
}

// claimsHeldByAlias lists the task refs still claimed under an alias.
//
// "No workspace record" and "no claims" are different questions, and only the
// second one is about claims. A soft-deleted workspace is invisible to the
// workspace listing - WorkspaceListParams has no include-deleted option - while
// the claims keyed to it remain, because /v1/claims selects straight from
// task_claims with no join to workspaces. Inferring one from the other is how a
// retirement reports success over an agent that still holds work.
//
// complete is false when the listing did not fit one page. A zero count from an
// incomplete listing establishes nothing and must not be read as "none".
//
// It reports how many, not which. Naming the tasks needs a task_ref field the
// claims client does not decode - see aweb-aaup, which owns that field because
// the struct is shared with the already-claimed filter in aw work ready. The
// count is what decides whether a retirement may call itself complete, so the
// correctness of this path does not wait on that.
//
// Which tasks they are is answerable today by aw work active. Its query reads
// task_claims with no join to workspaces (coordination/tasks_service.py
// list_active_work), so it lists claims whose workspace has been deleted, and it
// selects tasks with status in_progress - which is every claimed task, since a
// claim exists only while its task is in_progress. So the set it shows and the
// set counted here are the same set.
func claimsHeldByAlias(ctx context.Context, client *aweb.Client, alias string) (held int, complete bool, err error) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// The claims route caps a page at 200. There is no alias filter, so the whole
	// team's claims come back and are matched here.
	resp, err := client.ClaimsList(listCtx, "", 200)
	if err != nil {
		return 0, false, err
	}
	for _, claim := range resp.Claims {
		if strings.EqualFold(strings.TrimSpace(claim.Alias), alias) {
			held++
		}
	}
	return held, !resp.HasMore, nil
}

// coordinationOutcomeWithoutWorkspace decides what an absent workspace record
// means for the alias's claims.
//
// Absent is the ordinary case after a completed retirement, and it is also the
// case after a hosted removal that soft-deleted the record without releasing
// anything. Those look identical from the workspace listing and differ only in
// whether claims remain, so the claims are read rather than assumed.
//
// When claims remain there is nothing this command can do about them: the record
// they are keyed to is gone, so the delete cascade can no longer reach them.
// Retirement therefore cannot complete, and saying so is the only honest outcome.
func coordinationOutcomeWithoutWorkspace(ctx context.Context, client *aweb.Client, alias string) retireStoreOutcome {
	held, complete, err := claimsHeldByAlias(ctx, client, alias)
	if err != nil {
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeFailed,
			Detail: fmt.Sprintf("no workspace record for %s, and its task claims could not be read, so whether any are still held is unknown: %v", alias, err),
		}
	}
	if !complete {
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeFailed,
			Detail: fmt.Sprintf("no workspace record for %s, and the claim listing was truncated, so it cannot establish that none are held", alias),
		}
	}
	if held > 0 {
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeBlocked,
			Detail: fmt.Sprintf(
				"released nothing: %s holds no workspace record but still holds %d task claim(s). The record they are keyed to is gone, so deleting it cannot release them. Run aw work active to see which tasks they are - it lists claims by alias and does not hide ones whose workspace is deleted - then move each out of in_progress, which releases every claim on it, and retire again.",
				alias, held,
			),
		}
	}
	return retireStoreOutcome{
		Store:  storeCoordination,
		Result: storeUnchanged,
		Detail: fmt.Sprintf("released nothing: no workspace record for %s, and it holds no task claims", alias),
	}
}

func formatTeamRemoveAgent(v any) string {
	out := v.(teamRemoveAgentOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	if strings.TrimSpace(out.MemberAddress) != "" {
		sb.WriteString(fmt.Sprintf("Member:      %s\n", out.MemberAddress))
	}
	if strings.TrimSpace(out.CertificateID) != "" {
		sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertificateID))
	}
	if strings.TrimSpace(out.WorkspaceID) != "" {
		sb.WriteString(fmt.Sprintf("Workspace:   %s\n", out.WorkspaceID))
	}
	if strings.TrimSpace(out.OperationID) != "" {
		sb.WriteString(fmt.Sprintf("Operation:   %s\n", out.OperationID))
	}
	if strings.TrimSpace(out.RecoveryPath) != "" {
		sb.WriteString(fmt.Sprintf("Recovery:    %s\n", out.RecoveryPath))
	}
	sb.WriteString("Stores:\n")
	for _, store := range out.Stores {
		sb.WriteString(fmt.Sprintf("  %-13s %-13s %s\n", store.Store, store.Result, store.Detail))
	}
	return sb.String()
}
