---
type: Decision
title: A holding's membership evidence has two stores; a session login refreshes only the console's
description: A human-role holding's member certificate is kept in two stores that refresh separately. The canonical retained certificate is written by designate and replace, refreshed when the app accepts a credential start the holder signs, and read by a start the holder's direct child signs. The console's browser-admission evidence is refreshed only by a successful session login and read by browser logins. A session login does not write the canonical record, because doing so would reintroduce a share-to-write lock upgrade that review ruled out. Reviewed on design and implementation branches, not yet on main.
tags: [decision, human-roles, membership, handoff, naapp, locking]
timestamp: 2026-11-11
---

**Status (verified 2026-11-11):** specified in
`docs/design/human-confirmation-from-aw.md` (G2) at a6a71951 on a design
branch. Implemented at 14c5ee526 on an owner-acts implementation branch,
where `check_holding_member` in
`naapp-lib/src/aweb_naapp/console/handoff_sessions.py` reads
`console_holding_certificates`. Neither commit is on main at 7f4be32fa. The
source reports that it is queued to land after the current release train.
Agent reviewers approved the design. No human acceptance is recorded.

# Decision

A human-role holding keeps its membership evidence (the holder's member
certificate) in two stores, and each store is refreshed separately.

- **Canonical retained certificate.** It is stored with the holding by
  designate and replace. It is refreshed only when the app accepts a
  `credential` start that the holder signs. A start that the holder's direct
  child signs reads it.
- **Console browser-admission evidence.** It is refreshed only by a
  successful `session` login. Browser logins read it.

Both stores follow the same rules:

- A refresh replaces the stored certificate only when the presented
  certificate's team and principal equal the holding's.
- A failed assertion or verification changes nothing.
- A start that the holder's direct child signs refreshes neither store.

Consequence: after a membership is renewed, the holder's direct-child starts
refuse `principal_not_member` until the holder runs a `credential` start.
The source reports that `aw` names this remedy.

# Why a session login does not write the canonical record

The login transaction holds the holding only for reading (`FOR SHARE`)
through hold and prepare. Writing the canonical row in that transaction
would upgrade a share lock to a write lock. Security review required that
pattern removed.

# Rejected

- **Saying "a login refreshes the holding's certificate".** The seat's
  first G2 text said this, at 9c26082e5. Both the implementer and an
  independent reviewer rejected it, and it was rewritten at a6a71951. A
  contract that names an unspecified "holding evidence" hides which store a
  reading path depends on.
- **Making login take the holding at write strength from the start, so that
  it refreshes both stores.** This looks simpler. But it needs a separately
  reviewed code change to the handoff packages, and it buys a recovery that
  the `credential` start already provides. It would also quietly bring back
  the lock pattern that was ruled out.

# How to apply

Before you write or review contract text saying that an operation "refreshes
the holding's evidence" or "refreshes its certificate":

- name which store the operation writes;
- check which store each reading path uses: direct-child starts, browser
  logins and the per-use member check.

Related: [admission is not the effect transaction](/aweb-protocol-expert/lessons/admission-is-not-the-effect-transaction.md)
and [evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-11; notes/holding-evidence-two-stores.md.
The harvester checked the design text at a6a71951 and the code's read of
`console_holding_certificates` at 14c5ee526. Three things are source-reported:
the lock-pattern ruling, the reviews, and the rejected write-strength option.
