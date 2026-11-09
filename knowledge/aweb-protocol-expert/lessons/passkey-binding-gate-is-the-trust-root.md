---
type: Lesson
title: The gate on passkey binding is the trust root of passkey approvals
description: The naapp passkey verifier registers with user verification and one pinned origin but no attestation, so an assertion proves a fresh human gesture only as far as the gate on binding holds; an aw human key alone must not authorize a binding, a notice after binding detects but never prevents, and per-naapp registration is the safe RP ID shape.
tags: [lesson, passkeys, webauthn, authority, naapp, human-identity]
timestamp: 2026-11-08
---

The aweb_naapp passkey verifier registers a credential with user verification
required at one pinned origin and RP ID, and it does not check authenticator
attestation. Whoever passes the binding gate can therefore enrol a software
authenticator and produce user-verified assertions at will. "A passkey
assertion is a fresh human gesture" holds only as far as the gate on binding
that passkey holds.

The proposal to replace naapp-local enrolment with one shared, verified human
identity will recur. Its tempting form is "bind the passkey with the human's aw
key and keep email only for notices". That form silently loses the guarantee
that a key custodian cannot approve, and the flaw shows only when you ask who
authorizes the binding.

# How to apply

- **An aw human key alone must not authorize a passkey binding.** A custodian
  of that key, or malware holding a self-custodial one, could then enrol its own
  authenticator. A human-key signature is not evidence of a fresh gesture;
  `docs/id-certificates.md` says so for ID certificates.
- **Gate the first binding per (naapp, human) with something the key holder
  does not control.** Today that gate is the enrolment link sent only to the
  contact that the designating owner act commits to by hash, trust on first
  use. Once a subject has enrolled, it gets no new enrolment link outside
  recovery. A further binding must be gated by an existing passkey.
- **A notice sent after a binding is detection, not prevention.** It can reveal
  a substituted authenticator, but it never stops one. Never describe a notice
  channel as the gate.
- **Register per naapp.** The verifier pins one origin per naapp and re-checks
  origin and RP ID on each assertion, so an assertion collected on another
  origin is refused. Sharing one credential across naapps would need one of
  two shapes, and both are worse:
  - related origins, where the verifier accepts a set of origins and the
    cross-app confused-deputy attack reopens;
  - one common domain, which excludes self-hosted and BYOT naapps.

A weaker binding gate would also break in practice the kept approval guarantee
in [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md).
Such a change needs the same explicit ruling. Owner binding applies the same
rule of independent authorities in
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md).

**Status:** this records the mechanism, verified on aweb main at e7ae65cd7. The
operator has not ruled on the shared-identity assessment that prompted it. The
lesson holds whatever that ruling is.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/passkey-binding-gate-is-the-trust-root.md.
The assessment was NACKed in security review and then ACKed on 2026-11-08.
Checked against aweb main e7ae65cd7:

- `naapp-lib/src/aweb_naapp/runtime/passkeys/webauthn.py`: registration
  without attestation, with a pinned origin and RP ID.
- `naapp-lib/src/aweb_naapp/runtime/passkeys/service.py`:
  - the module docstring: an enrolment link goes only to the committed
    contact;
  - `reissue_enrolment`: refused once the subject has enrolled;
  - the assertion path: re-checks origin and RP ID.
- `docs/id-certificates.md`: a signature does not prove a fresh human gesture.
