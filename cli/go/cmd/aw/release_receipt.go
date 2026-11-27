package main

import (
	"errors"
	"fmt"
	"net"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// A release receipt says which one effect a release command asked for, on
// which exact team, subject and target, and what is known of it
// (docs/cli-integration-contract.md, Release receipts).
type releaseEffect string

const releaseRevokeGrant releaseEffect = "revoke_grant"

type releaseOutcome string

const (
	releaseConfirmed releaseOutcome = "confirmed"
	releaseUnknown   releaseOutcome = "unknown"
	releaseRefused   releaseOutcome = "refused"
)

const releaseSubjectMismatch = "subject_mismatch"

// releaseSubject is the selected resident or member, from authoritative local
// evidence only; a value that cannot be read is empty.
type releaseSubject struct {
	Alias    string `json:"alias"`
	DID      string `json:"did"`
	StableID string `json:"stable_id"`
}

type releaseTarget struct {
	GrantID string `json:"grant_id,omitempty"`
}

type releaseReceipt struct {
	Effect   releaseEffect  `json:"effect"`
	TeamID   string         `json:"team_id"`
	Subject  releaseSubject `json:"subject"`
	Target   releaseTarget  `json:"target"`
	Outcome  releaseOutcome `json:"outcome"`
	Code     string         `json:"code"`
	NextStep string         `json:"next_step"`
}

// releaseFailure carries a receipt with a failed release, so the JSON error
// envelope reports it in the same document.
type releaseFailure struct {
	receipt releaseReceipt
	err     error
}

func (e *releaseFailure) Error() string { return e.err.Error() }
func (e *releaseFailure) Unwrap() error { return e.err }

// grantRevocationPrecondition is the caller's sanity check on the selected
// resident, before anything is sent. The service's exact grant id, team and
// resident scope carry the binding of the operation itself.
func grantRevocationPrecondition(subject releaseSubject, expectAlias string) error {
	expect := strings.TrimSpace(expectAlias)
	if expect == "" {
		return nil
	}
	alias := strings.TrimSpace(subject.Alias)
	if alias == "" {
		return withErrorCode(releaseSubjectMismatch, usageError("the selected identity's alias cannot be read, so --expect-subject %s cannot be proved; select the resident's identity home", expect))
	}
	if !strings.EqualFold(alias, expect) {
		return withErrorCode(releaseSubjectMismatch, usageError("the selected identity is %s, not %s; select the identity home of %s", alias, expect, expect))
	}
	return nil
}

type revocationAttemptKind int

const (
	revocationConfirmed revocationAttemptKind = iota
	revocationRefused
	revocationNotSent
	revocationAmbiguous
)

// classifyGrantRevocation says what one revoke request established. Only the
// route's exact reply confirms; a definitive refusal or a connection that was
// never made establishes that nothing was revoked; anything after dispatch
// that is not an exact reply (a server failure, a lost or unusable response)
// establishes nothing.
func classifyGrantRevocation(grantID string, reply *aweb.IdentityGrantRevocation, err error) (revocationAttemptKind, string) {
	if err == nil {
		if reply != nil && sameGrantID(reply.GrantID, grantID) && reply.Status == "revoked" && strings.TrimSpace(reply.RevokedAt) != "" {
			return revocationConfirmed, reply.RevokedAt
		}
		return revocationAmbiguous, ""
	}
	if status, isHTTP := awid.HTTPStatusCode(err); isHTTP {
		if status >= 500 {
			return revocationAmbiguous, ""
		}
		return revocationRefused, ""
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) && opErr.Op == "dial" {
		return revocationNotSent, ""
	}
	return revocationAmbiguous, ""
}

// confirmRevocationByReadBack confirms an ambiguous attempt only from the
// service's recorded revocation of that exact grant in the selected team.
// Expiry, absence or a failed read confirm nothing.
func confirmRevocationByReadBack(grantID, teamID string, grants []aweb.IdentityGrantView, err error) (string, bool) {
	if err != nil {
		return "", false
	}
	for _, grant := range grants {
		if sameGrantID(grant.GrantID, grantID) && strings.EqualFold(strings.TrimSpace(grant.TeamID), strings.TrimSpace(teamID)) && strings.TrimSpace(grant.RevokedAt) != "" {
			return grant.RevokedAt, true
		}
	}
	return "", false
}

// sameGrantID compares grant ids as the route writes them, the canonical
// hyphenated UUID, whatever case the caller typed.
func sameGrantID(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && strings.EqualFold(a, b)
}

// selectionIdentityHome is the absolute identity home a retry must select to
// act as the same principal.
func selectionIdentityHome(selection *awconfig.Selection) string {
	if home := strings.TrimSpace(selection.IdentityHome); home != "" {
		return home
	}
	return awconfig.WorktreeIdentityHome(selection.WorkingDir)
}

func grantRevokeRetry(identityHome, grantID, teamID string) string {
	return fmt.Sprintf("aw --identity-home %s id grant revoke %s --team %s --json", shellQuote(identityHome), shellQuote(grantID), shellQuote(teamID))
}
