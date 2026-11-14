package handoff

import (
	"fmt"
	"time"
)

// Facts are what a refusal's sentence may name. A zero member is not known
// and is left out of the sentence.
type Facts struct {
	OperationID string
	// Operation is the definition selector ("operation|variant"); a refusal
	// its definition names reads as that definition's own sentence.
	Operation string
	Team      string
	ExpiresAt time.Time
	// RetryAt is when the service said the same request may succeed.
	RetryAt   time.Time
	Admission *AdmissionCounts
}

// AdmissionCounts are a root's admissions to one team against its policy's
// bounds, as the signer reported them.
type AdmissionCounts struct {
	Active, MaxActive      int
	InWindow, MaxPerWindow int
	WindowSeconds          int
	NextAt                 time.Time
}

const again = "Run the command again to send a new request."

// sentences tell each stable code in words. A code missing here is still
// told, with the code named (Sentence).
var sentences = map[string]func(Facts) string{
	"upgrade_aw_required": func(Facts) string {
		return "Upgrade aw to use this protected approval format."
	},
	"operation_not_served": func(Facts) string {
		return "This protected service does not serve the requested operation; upgrade the service to a version that supports it."
	},
	"awaiting_human":     func(Facts) string { return "Waiting for the approver to decide." },
	"awaiting_execute":   func(Facts) string { return "Approved; waiting for the signer to carry it out." },
	"effect_in_progress": func(Facts) string { return "The signer is carrying this out now." },

	"human_refused": func(Facts) string { return "The approver denied this request." },
	"operation_expired": func(f Facts) string {
		return "Nobody decided this request before it expired" + at(f.ExpiresAt, clock) + ". " + again
	},
	"approval_expired": func(f Facts) string {
		return "The approval came too late to be used" + at(f.ExpiresAt, clock) + ". " + again
	},
	"proof_invalid": func(Facts) string {
		return "The passkey answer could not be verified, so nothing was approved. " + again
	},
	"approval_spent": func(Facts) string {
		return "This approval was already used once and cannot be used again. " + again
	},
	"operation_mismatch": func(Facts) string {
		return "The signer's copy of this request differs from the one approved, so it was refused. " + again + " If it happens again, tell the operator."
	},
	"authority_changed": func(Facts) string {
		return "The team's signing key or approvers changed after this was requested. " + again + " If it happens again, tell the operator."
	},
	"policy_changed": func(Facts) string {
		return "The team's admission policy changed after this was requested. " + again
	},
	"scope_refused": func(f Facts) string {
		return "The signer does not accept this request from this identity" + forTeam(f.Team) + ". The operator decides which identities the protected profile accepts."
	},
	"stale_binding": func(Facts) string {
		return "The approver's passkeys or access changed while this was waiting. " + again
	},
	"no_notice_contact": func(Facts) string {
		return "The approver has no notice address on record, so passkey changes are refused until the operator sets one."
	},
	"cap_reached": func(Facts) string {
		return "The approver already has the most passkeys allowed. Replace one instead of adding another."
	},
	"cap_unavailable": func(Facts) string {
		return "The approver's passkey limit could not be read, so nothing was changed. Tell the operator."
	},
	"last_authorizer_protected": func(Facts) string {
		return "This would leave nobody able to approve, so it was refused."
	},
	"last_owner_protected": func(Facts) string {
		return "This would leave no owner, so it was refused."
	},
	"issuer_kind_forbidden": func(Facts) string {
		return "The approving identity is not allowed to issue this kind of identity, so it was refused."
	},
	"subject_ineligible": func(Facts) string {
		return "The identity this request names cannot receive it: it must be a current registered identity with no conflicting or revoked history."
	},
	"provenance_refused": func(Facts) string {
		return "This identity was not first issued through this signer, so it cannot be signed again here."
	},
	"admission_policy_missing": func(f Facts) string {
		return "The team" + named(f.Team) + " has no admission policy on this signer. The operator provisions one."
	},
	"admission_limit_reached": admissionLimit,
	"protected_admission_required": func(Facts) string {
		return "This team is protected: agents join through its root with aw id team admit, not by invite."
	},
	"live_approval_required": func(Facts) string {
		return "This needs a person's live approval and cannot run unattended."
	},
	"operation_refused": func(Facts) string { return "The signer refused this operation." },

	"receipt_unavailable": func(f Facts) string {
		return "The signer could not say whether this took effect" + operation(f.OperationID) + ". Run the same command again to check; do not start a new request."
	},
	"external_effect_unresolved": func(f Facts) string {
		return "It is not known whether this reached its destination" + operation(f.OperationID) + ". Run the same command again to check; do not start a new request."
	},

	"request_invalid":      func(Facts) string { return "The signer could not read this request. Check the command's inputs." },
	"redirect_uri_refused": func(Facts) string { return "The signer refused aw's local callback address." },
	"requester_invalid": func(Facts) string {
		return "The signer could not verify this identity's signature. Check that this identity's key is the current one in the registry."
	},
	"operation_conflict": func(Facts) string {
		return "That operation id was already used for a different request. Leave out --operation-id to start a new one."
	},
	"operation_not_found": func(Facts) string {
		return "The signer has no record of this operation for this identity."
	},
	"login_rate_limited":   func(Facts) string { return "Too many sign-in attempts." },
	"handoff_rate_limited": func(Facts) string { return "Too many requests to the signer." },
}

// Sentence tells code in words, with what f knows. A retry time, when the
// service gave one, ends it.
func Sentence(code string, f Facts) string {
	tell, ok := sentences[code]
	text := fmt.Sprintf("The signer refused this request (%s).", code)
	if own, defined := displayRefusal(f.Operation, code); defined {
		text = own
	} else if ok {
		text = tell(f)
	}
	if !f.RetryAt.IsZero() {
		text += " Try again after " + ReaderTime(f.RetryAt, "15:04:05") + "."
	}
	return text
}

// admissionLimit names the limit the root reached and what can be done now:
// a full count frees up by removing an agent, a full window only by waiting.
func admissionLimit(f Facts) string {
	a := f.Admission
	switch {
	case a != nil && a.MaxActive > 0 && a.Active >= a.MaxActive:
		return fmt.Sprintf("The root already has %d of %d agents%s, the most its admission policy allows. Remove one it no longer needs with aw id team remove-agent.",
			a.Active, a.MaxActive, inTeam(f.Team))
	case a != nil && a.MaxPerWindow > 0 && a.InWindow >= a.MaxPerWindow:
		return fmt.Sprintf("The root has added %d agents%s in the last %s, the most its admission policy allows.%s",
			a.InWindow, inTeam(f.Team), window(a.WindowSeconds), nextAt(a.NextAt))
	}
	return "The root has reached its admission limit" + forTeam(f.Team) + ". See the limits and current counts with aw id team admission-policy."
}

func window(seconds int) string {
	switch {
	case seconds == 3600:
		return "hour"
	case seconds == 86400:
		return "day"
	case seconds%3600 == 0:
		return fmt.Sprintf("%d hours", seconds/3600)
	case seconds%60 == 0:
		return fmt.Sprintf("%d minutes", seconds/60)
	}
	return fmt.Sprintf("%d seconds", seconds)
}

func nextAt(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return " The next one is possible at " + ReaderTime(t, clock) + "."
}

const clock = "15:04"

// ReaderTime is t in the reader's own zone, the zone named, as the approval
// page and the mail show times.
func ReaderTime(t time.Time, layout string) string {
	return t.Local().Format(layout + " MST")
}

func at(t time.Time, layout string) string {
	if t.IsZero() {
		return ""
	}
	return " at " + ReaderTime(t, layout)
}

func forTeam(team string) string {
	if team == "" {
		return ""
	}
	return " for " + team
}

func inTeam(team string) string {
	if team == "" {
		return ""
	}
	return " in " + team
}

func named(team string) string {
	if team == "" {
		return ""
	}
	return " " + team
}

func operation(id string) string {
	if id == "" {
		return ""
	}
	return " (operation " + id + ")"
}
