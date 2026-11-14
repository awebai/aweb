package main

import (
	"bytes"
	"cmp"
	"context"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/handoff"
)

// Unfinished requests aw cannot continue (human-assurance-contract.md, the
// saved-old-operation migration guard): a saved request for the same act on
// the same target that is in an approval format the service no longer
// serves, or was prepared under another authority generation. Neither may be
// sent again, and neither may be silently replaced by a new request: its
// outcome may still be an effect. aw reads its receipt once, without
// executing anything, settles it when that answer is definite, and
// otherwise keeps it quarantined with what it observed, until the human
// explicitly asks for a separately approved request with --replace.

// committedReading settles a committed receipt of saved, whose body is body:
// a report when aw can verify the effect applied under the original rules
// and pinned authority, or else the observed facts to keep.
type committedReading func(saved *awconfig.PendingGovernanceOperation, body map[string]any, result []byte) (map[string]any, *awconfig.GovernanceQuarantine)

// stableScope is a protected scope without its authority generation: the
// same target under a newer generation is still the same target.
func stableScope(scope any) any {
	fields, ok := scope.(map[string]any)
	if !ok {
		return scope
	}
	stable := map[string]any{}
	for name, value := range fields {
		if name != "generation" {
			stable[name] = value
		}
	}
	return stable
}

// unfinishedFor is every saved request at profile's service for intent's act
// and target, as sameTarget compares their subjects, that aw would not
// continue as it is: quarantined, in another approval format, or under
// another authority generation. It is sorted by operation id.
func unfinishedFor(profile *handoff.Profile, intent map[string]any, sameTarget func(saved, asked any) bool) ([]*awconfig.PendingGovernanceOperation, error) {
	all, err := awconfig.ListPendingGovernanceOperations()
	if err != nil {
		return nil, err
	}
	var found []*awconfig.PendingGovernanceOperation
	for _, saved := range all {
		body, ok := handoff.DecodeObject(saved.Body)
		if !ok || saved.RequestOrigin != profile.RequestOrigin || saved.HumanOrigin != profile.HumanOrigin ||
			body["operation"] != intent["operation"] || body["variant"] != intent["variant"] || body["audience"] != intent["audience"] ||
			!sameTarget(body["subject"], intent["subject"]) || !sameCanonical(stableScope(body["scope"]), stableScope(intent["scope"])) {
			continue
		}
		if saved.Quarantine != nil || body["approval_format"] != intent["approval_format"] || !sameCanonical(body["scope"], intent["scope"]) {
			found = append(found, saved)
		}
	}
	slices.SortFunc(found, func(a, b *awconfig.PendingGovernanceOperation) int {
		return strings.Compare(a.OperationID, b.OperationID)
	})
	return found, nil
}

// guardUnfinished runs before a command sends intent. For each unfinished
// request for the same act and target (sameTarget compares subjects), it reads the receipt once through the
// request's own binding (reader, false when the profile no longer has it).
// A definite refusal retires that request, and a verified applied effect
// settles it; either ends this run, settled carrying the applied report.
// Anything else keeps the request quarantined with what was observed, and
// stops the run unless replace names it: then the human has chosen a new,
// separately approved request, and guardUnfinished returns nil, nil.
func guardUnfinished(ctx context.Context, notify io.Writer, profile *handoff.Profile, reader func(scope map[string]any) (handoff.GovernanceOptions, bool),
	intent map[string]any, sameTarget func(saved, asked any) bool, replace string, committed committedReading) (settled map[string]any, err error) {
	unfinished, err := unfinishedFor(profile, intent, sameTarget)
	if err != nil {
		return nil, err
	}
	var kept []*awconfig.PendingGovernanceOperation
	for _, saved := range unfinished {
		report, refused, err := reconcileUnfinished(ctx, reader, saved, committed)
		switch {
		case err != nil:
			return nil, err
		case refused:
			return nil, withErrorCode("earlier_operation_refused", fmt.Errorf(
				"the earlier request %s for this same act was refused, so it took no effect; run the command again to start a new one", saved.OperationID))
		case report != nil:
			return report, nil
		}
		kept = append(kept, saved)
	}
	if replace == "" {
		if len(kept) == 0 {
			return nil, nil
		}
		return nil, withErrorCode("operation_reconciliation_required", fmt.Errorf(
			"an earlier request for this same act is unfinished and may still have taken effect: %s; check the current state, and to ask for a separately approved act run again with --replace %s",
			unfinishedText(kept), kept[0].OperationID))
	}
	if len(kept) != 1 || kept[0].OperationID != replace {
		return nil, usageError("--replace must name the one unfinished earlier request for this same act (found: %s)", cmp.Or(unfinishedText(kept), "none"))
	}
	fmt.Fprintf(notify, "Replacing the earlier request %s, which is kept: %s. It may still have taken effect; the new request needs its own approval.\n",
		replace, unfinishedState(kept[0].Quarantine))
	return nil, nil
}

// reconcileUnfinished reads saved's receipt once and records what it says: it
// returns refused for a definite refusal (saved is forgotten), the report of
// a verified applied effect (saved is forgotten), or neither (saved is kept
// quarantined, with facts observed earlier kept when this read says less).
func reconcileUnfinished(ctx context.Context, reader func(scope map[string]any) (handoff.GovernanceOptions, bool),
	saved *awconfig.PendingGovernanceOperation, committed committedReading) (report map[string]any, refused bool, err error) {
	body, _ := handoff.DecodeObject(saved.Body)
	scope, _ := body["scope"].(map[string]any)
	facts := &awconfig.GovernanceQuarantine{State: "unread", Verification: "binding_unavailable"}
	if opts, ok := reader(scope); ok {
		readCtx, cancel := context.WithTimeout(ctx, cmp.Or(opts.RetryWithin, handoff.DefaultRetryWithin))
		receipt, readErr := handoff.ReadReceipt(readCtx, opts, saved.OperationID)
		cancel()
		switch {
		case readErr != nil:
			facts = &awconfig.GovernanceQuarantine{State: "unread", Code: cmp.Or(handoff.ErrorCode(readErr), "receipt_unavailable"), Verification: "unread"}
		case receipt.State == "refused":
			return nil, true, awconfig.RemovePendingGovernanceOperation(saved.OperationID)
		case receipt.State == "committed":
			report, read := committed(saved, body, receipt.Result)
			if report != nil {
				return report, false, awconfig.RemovePendingGovernanceOperation(saved.OperationID)
			}
			facts = read
		default:
			facts = &awconfig.GovernanceQuarantine{State: receipt.State, Code: receipt.Code, Verification: "unsettled"}
		}
	}
	facts = mergedFacts(saved.Quarantine, facts)
	facts.ObservedAt = time.Now().UTC().Format(time.RFC3339)
	saved.Quarantine = facts
	return nil, false, awconfig.SavePendingGovernanceOperation(saved)
}

// mergedFacts is what aw knows of a quarantined request after a later read.
// Signed bytes once observed are never dropped: a later read of the same
// bytes only raises how far they are verified, and other signed bytes are
// added, each once, to the conflicts kept beside the original. Without
// signed bytes, the read that says more is kept: a committed answer over any
// other, any answer over none.
func mergedFacts(earlier, later *awconfig.GovernanceQuarantine) *awconfig.GovernanceQuarantine {
	if earlier == nil {
		return later
	}
	if len(earlier.Signing) == 0 {
		if len(later.Signing) > 0 || stateRank(later.State) >= stateRank(earlier.State) {
			return later
		}
		return earlier
	}
	kept := *earlier
	kept.Conflicts = append([]awconfig.GovernanceSignedResult(nil), earlier.Conflicts...)
	switch {
	case len(later.Signing) == 0:
	case bytes.Equal(later.Signing, earlier.Signing) && bytes.Equal(later.Signature, earlier.Signature):
		if verificationRank(later.Verification) > verificationRank(earlier.Verification) {
			kept.Verification = later.Verification
		}
	case !slices.ContainsFunc(kept.Conflicts, func(c awconfig.GovernanceSignedResult) bool {
		return bytes.Equal(c.Signing, later.Signing) && bytes.Equal(c.Signature, later.Signature)
	}):
		kept.Conflicts = append(kept.Conflicts, awconfig.GovernanceSignedResult{Signing: later.Signing, Signature: later.Signature})
	}
	return &kept
}

// stateRank orders what a read said: nothing, an unsettled state, committed.
func stateRank(state string) int {
	switch state {
	case "unread":
		return 0
	case "committed":
		return 2
	}
	return 1
}

// verificationRank orders how far observed signed bytes were verified.
func verificationRank(verification string) int {
	switch verification {
	case "signature_verified":
		return 1
	case "expired":
		return 2
	}
	return 0
}

func unfinishedText(kept []*awconfig.PendingGovernanceOperation) string {
	parts := make([]string, len(kept))
	for i, saved := range kept {
		parts[i] = saved.OperationID + " (" + unfinishedState(saved.Quarantine) + ")"
	}
	return strings.Join(parts, ", ")
}

// unfinishedState says, for people, what aw knows of a kept request.
func unfinishedState(q *awconfig.GovernanceQuarantine) string {
	if q == nil {
		return "not read"
	}
	switch {
	case q.Verification == "expired":
		return "signed; application unconfirmed; the act has expired and will not be sent"
	case q.State == "committed":
		return "signed; application unconfirmed; it will not be sent by this aw"
	case q.State == "unread":
		return "its receipt could not be read (" + cmp.Or(q.Code, q.Verification) + ")"
	}
	return "its receipt says " + q.State
}

// quarantinedOperation refuses to continue a quarantined request named by its
// id: it is only read for reconciliation, and a new request for the same act
// needs --replace.
func quarantinedOperation(operationID string) error {
	return withErrorCode("operation_reconciliation_required", fmt.Errorf(
		"operation %s is quarantined for reconciliation and is not continued; to ask for a separately approved act, run without --operation-id %s and with --replace %s", operationID, operationID, operationID))
}
