package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
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
// The order is not interchangeable. Releasing claims means deleting the
// workspace record, and the hosted remove-member endpoint soft-deletes that same
// record itself without releasing anything, so revoking first leaves the claims
// permanently held. It is also the only order that keeps a recovery path: an
// agent that still holds claims can release them itself until its certificate is
// revoked, and not a moment after.
//
// For the same reason a blocked coordination store stops the sequence rather
// than proceeding to the revoke. Revoking anyway would produce exactly the
// split state this command exists to prevent, and would destroy the credential
// needed for the cheapest way out of it.
func retireTeamAgent(
	ctx context.Context,
	client *aweb.Client,
	teamID string,
	memberAddress string,
	alias string,
	revoke revokeCertificateFunc,
) teamRemoveAgentOutput {
	out := teamRemoveAgentOutput{
		TeamID:        teamID,
		MemberAddress: memberAddress,
		Alias:         alias,
	}

	coordination, deleted := releaseCoordinationState(ctx, client, alias)
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
	default:
		out.Stores = append(out.Stores, retireStoreOutcome{
			Store:  storeCertificate,
			Result: storeUnchanged,
			Detail: "revoked nothing: the service reported it had nothing to revoke, which does not establish that no certificate exists; confirm with aw team agent-status",
		})
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
		return retireStoreOutcome{
			Store:  storeCoordination,
			Result: storeUnchanged,
			Detail: fmt.Sprintf("released nothing: no workspace record for %s", alias),
		}, nil
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
	sb.WriteString("Stores:\n")
	for _, store := range out.Stores {
		sb.WriteString(fmt.Sprintf("  %-13s %-13s %s\n", store.Store, store.Result, store.Detail))
	}
	return sb.String()
}
