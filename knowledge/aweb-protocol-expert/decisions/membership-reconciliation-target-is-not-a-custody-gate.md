---
type: Decision
title: Membership reconciliation has a visible target, never a custody gate
description: The 60-second portable-membership reconciliation is a completion target that starts at the registry transition, and a miss is made visible per consumer and epoch; it is not a guarantee and never refuses already accepted ordinary traffic, while fresh or changed admission still needs current authority and immediate cutoff uses revocation or removal. Coordinator design direction, not approved for code.
tags: [decision, membership, registry, reconciliation, revocation, availability]
timestamp: 2026-11-14
---

Ruled by the OSS coordinator on 2026-11-14, adopting an independent
reviewer's recommendation on a portable-membership design draft. This is a
coordinator ruling, not an operator decision: the acceptance is
**source-reported** (coordinator ruling relayed to the source), and the
harvester could not read the record. Message identifiers are omitted.

**Status:** design direction only. It is not a source, runtime or release
approval. The design author still owes a revised design and its approval
before any code. The repository's contract prose has not yet been revised to
match, so it may still state the earlier hard reconciliation bound; that prose
does not show this direction or its rationale.

# Decision

- When a team's membership changes at the registry, consumers reconcile their
  membership entries with a **completion target** of 60 seconds. The target is
  measured from the registry transition's authoritative time. A cache hit or a
  consumer restart never moves that start time.
- The target is not a guarantee. A miss is made explicit: in a registry-URL
  log, a health field, team status, and per-consumer completed-epoch evidence.
  One consumer's completion is not evidence that the whole fleet completed.
- A miss never becomes a refusal of traffic that was already accepted. Accepted
  ordinary traffic keeps every baseline check (credentials, local retirement,
  grants, scope and revocation), with no added custody-evidence refusal.
- Fresh admission, and any changed certificate, still requires positive
  current authority.
- Documentation for this entry must not promise a deadline. It tells owners
  that when they need immediate cutoff, they revoke or remove the member.
- A health diagnostic is never permission to stop otherwise valid traffic, and
  never relaxes fresh governance checks.

# Why

Without the current roster, a consumer cannot tell a legitimate accepted
member from one that the new roster excludes. So two promises cannot both
hold: keep serving all accepted traffic, and guarantee that reconciliation
has completed by a deadline. The coordinator chose availability with a
visible missed target over a new custody-evidence outage. Revocation and
removal remain the immediate-cutoff path, so the trade gives up no control
that an owner needs to act at once.

# Rejected

- **A hard reconciliation bound enforced by refusal:** refusing accepted
  ordinary traffic until reconciliation evidence is complete. This turns a
  slow or failed reconciliation into an outage of valid traffic.
- **A hard bound without any gate:** promising unconditional completion by a
  deadline while still serving all accepted traffic. The conjunction cannot
  be met, so it would be a silent false guarantee.

The earlier hard-bound reasoning is superseded only for this
membership-entry convergence promise. It does not change the separate
ordinary-messaging registry outage policy.

Related: [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md),
[credential lifetime is optional team policy](/aweb-protocol-expert/decisions/credential-lifetime-is-optional-team-policy.md),
which keeps live revocation as the primary control.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes, 2026-11-14; notes/portable-membership-completion-target.md.
The ruling rests on a source-derived independent review of the design draft.
No runtime or implementation result backs it. The source's search of aweb
main at ae3a47aa6 found no equivalent concept.
