---
type: Decision
title: aw delivers a protected act only after verifying it, and settles a replay only on applied_earlier
description: aw verifies a protected operation's signed act against its own saved intent and the profile's pinned controller key before it posts the act to the app's owner-act route; it keeps the saved request until the app applies the act, and treats a replay as settled only on the receiver's exact-act 409 applied_earlier, never on a generic refusal.
tags: [decision, aw, protected-operations, owner-acts, idempotency, testing]
timestamp: 2026-11-12
---

How aw hands a protected operation's committed receipt to the app that
applies it. The first cut (6205b6e2c) was NACKed in review (R 65acff22). The
fix is 58734cb22. The replay wire was agreed with the receiver's owner
(6c332739).

# Decision

- **Verify before delivering.** aw checks the receipt's act with
  `awid.VerifyOwnerAct` against its own saved intent and the profile's pinned
  controller key. Only then does it post the act to the app's existing
  owner-act route.
- **The saved request lives until the app applies the act.** The handoff
  client does not forget on a committed receipt. The command forgets after
  delivery. Otherwise a failed delivery would lose the only copy of the
  signed act.
- **A replay is settled only by the receiver's exact-act acknowledgement:**
  409 `{"detail":"applied_earlier"}`. The receiver matches it on the stored
  `act_sha256` of the signing bytes, after fresh authority, installation and
  fence checks, and applies no effect. aw treats only that code as success.
- **Any other refusal keeps the saved request.** A Resume resends the
  identical signed bytes. aw never re-signs or refreshes the act.

# Discoveries behind it

- **The signer's real encoding differs from the contract's.** The protected
  signer writes the receipt signature padded (`base64.b64encode`, 88
  characters). The owner-act contract spells it unpadded (86). Tests that sign
  with `SignOwnerAct` never see the padded form, so they hid the mismatch, and
  it cost a review round.
- **A generic refusal cannot mean "applied earlier".** The receiver prepares
  the effect before it consumes the nonce. A replay of an applied revoke
  therefore hits "holding absent" first, and the receiver maps every
  `hooks.Refused` to the generic `owner_required`. Neither `nonce_reused` nor
  `owner_required` tells aw the act was applied. That is why the explicit
  `applied_earlier` code was agreed.

# Rejected

- **Forgetting the request on a "final" 4xx from the app.** The app's owners
  want `owner_required` to keep the request, so that a repeated Resume can
  show that nothing was re-signed.
- **Treating `owner_required` or `nonce_reused` as success on replay.** That
  turns a generic refusal into a false success.

# How to apply

- Test a consumer against the producer's real output: a receipt from the real
  signer, or its exact bytes, not one re-signed with the consumer's own
  helper.
- In this area, a refusal is success only when the receiver says so with a
  code that means exactly that.

**Status (verified by the harvester 2026-11-12):** 58734cb22 and 6205b6e2c are
on the branch `agents/aweb-expert-owner-acts-roundtrip`, not on main at
88fbf7b4f. As the source reported, delivery is not yet composed or proven on
the journey, because it waits for the receiver and the reviews.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-12;
notes/protected-act-delivery.md. The review verdicts and the agreement on the
replay wire are the source's report.
