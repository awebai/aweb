---
type: Lesson
title: Prove one owner-act effect from the receiver's durable anchors
description: To prove an owner act took exactly one effect at a naapp receiver, pick the durable anchor by the act's direction (narrowing-authority row for a revoke, credential_authorizations row for a designate, one owner_act_nonces row for both), never rely on outbox payloads, bind the retained signed document to the intended act, and read every anchor in one repeatable-read transaction.
tags: [lesson, testing, e2e, owner-acts, naapp, receivers]
timestamp: 2026-11-13
---

The receiver's schema is in the repository. Which rows prove one effect for
which direction of act is not written anywhere. Picking the wrong ones either
finds no row or races delivery. Establishing this took several round-trips
with the Secrets owner.

# Choose the anchor by direction

- **Narrowing acts (revoke)** leave one `credential_narrowing_authority` row,
  joined to its outbox event. Only narrowing acts write this table.
- **Widening acts (designate)** leave one `credential_authorizations` row
  keyed by the B3 subject. It holds authority `owner_act`, the commitment,
  the retained signing bytes and the notice-contact hash. For human holders
  `contact_sha256` is NULL, so use `notice_contact_sha256`.
- **Both directions** leave exactly one `owner_act_nonces` row whose
  `act_sha256` is H, the SHA-256 of the exact prefixed signing bytes. A
  refused duplicate consumes no nonce.
- **Outbox payloads are not anchors.** The payload is set to NULL once every
  delivery of the event has ended. It can be optional context, and an
  assertion that reads it must accept NULL. Do not assert mutable outbox
  transport columns either.

# Bind the check to the act you meant

Digest self-consistency (commitment = sha256(signing) = the nonce row's
`act_sha256`) also passes for the wrong act. Check the retained signed
document against the intended act: its kind, team, audience, app,
installation, role, principal, credential digest and contact digest. The
source reports that mutation tests against the Secrets receiver showed the
act binding and the nonce-row check each catch failures that the digests
alone miss.

# Read in one place

Read every anchor in one repeatable-read, read-only transaction. Scope it by
app, team, installation, generation, role and principal. A query scoped only
by principal can pick another installation's B3 subject.

# How this was learned

The source first proposed "one nonce row and one authority row" for a
designate as an option to the coordinator, before checking the receiver's
writer. The coordinator adopted that wording, and the source then found that
no narrowing-authority row exists for widening acts. The decision had to be
amended. Check a receiver anchor's writer in source before you propose it,
as the [evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md)
requires of every claim.

Where these assertions apply is set by
[an owner act's exact replay is tested only on the protected path](/aweb-expert/decisions/owner-act-replay-is-tested-only-on-the-protected-path.md).

# Status

Source fact at aweb main f268e6596: `credential_narrowing_authority` is
inserted only in `naapp-lib/src/aweb_naapp/runtime/credential_audit/narrowing.py`;
`credential_authorizations` is inserted in `recorder.py` there with
`authority`, `commitment`, `signing` and `notice_contact_sha256`;
`owner_act_nonces` is inserted in `naapp-lib/src/aweb_naapp/hooks/owner_act_nonces.py`;
and `outbox/migrations/001_outbox.sql` documents the payload as NULL once
every delivery has ended. These are source-confirmed contracts. As of
2026-11-13 no native lane run has observed them.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/receiver-anchors-for-one-effect.md;
notes/designate-anchors-are-credential-authorizations.md.
