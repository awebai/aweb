---
type: Decision
title: A holding read returns the stored fact
description: An app's read of a human-role holding, keyed by installation, role and principal, is app-local SQL in the caller's transaction that re-checks neither membership nor kind; the per-use human-member check (H2) runs once, in the caller that holds the fresh proof, so a departed holder still reads as a holding revoke can reach, and a replace's cooling-off reads as a holding with no loginable credential, not as no holding. Specified on a design branch, not yet on main.
tags: [decision, authority, human-roles, membership, revocation, owner-acts]
timestamp: 2026-11-09
---

**Status (verified 2026-11-09):** specified in
`docs/design/human-role-holders.md` "Reading a holding" at ad919b6a0, on a
design branch and not yet on main. The source reports that the secrets
coordinator confirmed it and withdrew its earlier wording, "the read
re-checks". That is an agent review, not a human acceptance.

# Decision

- An app's read of a role holding, keyed by (installation, role,
  principal), runs SQL reads only, in the caller's transaction. It makes no
  registry or network call and takes no lock.
- It does not re-check the principal's team membership or subject kind.
- The per-use H2 check, that the principal is still a current human member,
  is the runtime's shared exact-principal check
  (`aweb_naapp.runtime.human_member.check_human_member`). The caller runs it
  once per use, before its effect transaction, and keeps that proof fresh
  around each read.
- A holding whose principal has left the team still reads as a holding.
  Revoke can then target it, and the shared check refuses its use.
- During a replace's cooling-off, the read returns the holding with no
  loginable credential (`subject` is `None`), not "no holding". The two
  states lead to different refusals: the source reports 401
  `console_session_required` for the first and 403 `role_not_held` for the
  second.

The general rule: an authority read keyed by a principal returns the stored
fact. Whoever holds the fresh proof checks the principal's liveness, once per
use. Apply it when specifying any app's role read, such as secrets or logs.

# Rejected

Putting the membership and kind check inside the read was the first ruling
and the usual first instinct. It was reversed for three reasons:

- The consumer interface passes only a public scope, so the read has no
  certificate to check against.
- The shared handoff already holds a fresh human-member proof around every
  hold and check. A second check would be a copy of it and a second registry
  dependency.
- A read that filters on membership hides exactly the holdings of departed
  members, so revoke would fail when it matters most. Revoke needs only its
  own authority, never the holder's current membership (see
  [local stop is not new binding authority](/aweb-protocol-expert/lessons/local-stop-is-not-new-binding-authority.md)).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/holding-read-excludes-per-use-human-check.md.
The design text was checked at ad919b6a0. The interface detail and the
refusal codes come from the source note.
