---
type: Decision
title: A credential-cap change records policy.changed
description: An owner's human-credential.cap-set emits the existing policy.changed act, always widening whichever way the cap moves, with owner_act authority, owner_act_sha256 and role only; it is role policy, not a credential.* act, and a protected-key cap goes only to the protected signer's local audit. Frozen in a contract on a review branch, not yet on main.
tags: [decision, audit, hook-events, owner-acts, human-assurance, credentials]
timestamp: 2026-11-11
---

**Status (verified 2026-11-11):** the rule "Cap-set emits `policy.changed`, a
widening act whichever way the cap moves" is in `docs/owner-act-delivery.md`
at 584d76c9c, the frozen human-assurance contract head on a review branch,
not on aweb main. Settled by agent review (contract owner and security
reviewer), not by a separate human ruling.

# Decision

- `human-credential.cap-set` on an app holding emits `post-governance-hook`
  with the existing act `policy.changed`, direction `widening`, authority
  `owner_act` with `owner_act_sha256`, and the `role`. Nothing else is added
  to the event.
- The cap value is not a hook field. It is committed by the signed act that
  `owner_act_sha256` names. In the same transaction the recorder checks that
  the stored cap row was written in this transaction, that its act reference
  equals the act digest, and that its cap equals the act's.
- A cap on a protected-key (non-app) holding is recorded only in the
  protected signer's local audit.

# Why

- **The catalog fixes each act's direction and consumers refuse a mismatch**
  (`docs/hook-events.md`, `post-governance-hook`). Choosing the direction by
  whether the cap went up or down needs new acts and fields, which means
  re-freezing the v1 catalog for no security gain.
- **Fixed widening is the stricter gate.** Lowering a cap evicts no
  credential, so it has no containment urgency that could justify skipping
  the audit availability a widening act requires.
- **`credential.*` means key lifecycle.** Consumers read those acts as a key
  being enrolled, recovered or revoked. A cap is role policy.

# Rejected

- **A `credential.cap_set` act with old and new cap and direction by
  movement.** Proposed in review and withdrawn by its proposer for the reasons
  above.
- An optional cap field on `policy.changed` remains possible later, only if a
  reader needs the value without the retained act.

# How to apply

When a new governance effect needs an audit event, first look for an existing
act whose fixed direction is the stricter correct one. A new act, or a
direction that depends on the effect's values, is a catalog change that needs
its own justification.

Related: [a holding with no notice contact refuses self-service credential changes](/aweb-protocol-expert/decisions/no-notice-contact-refuses-self-credential-change.md),
from the same credential work.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-11; notes/cap-change-is-policy-changed.md.
The emission rule was checked in `docs/owner-act-delivery.md` at 584d76c9c
and the fixed-direction rule in `docs/hook-events.md` on main at 7f4be32fa.
The rejected alternative and the recorder checks come from the source note.
