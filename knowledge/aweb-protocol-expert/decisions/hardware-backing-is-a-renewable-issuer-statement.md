---
type: Decision
title: Hardware backing is a short-lived issuer statement beside the issuer's vouching
description: A kind=human certificate keeps meaning that its issuer vouches by its own conditions; hardware backing is a separate issuer-signed statement over the enrollment binding, naming the exact credential, certificate and identity key, valid at most min(snapshot valid_until, issued_at + 31 days), so a FIDO withdrawal reads "hardware backing lapsed" and nothing is revoked. Reviewed design, not implemented.
tags: [decision, identity, personhood, hardware, assurance, passkeys]
timestamp: 2026-11-28
---

A `kind=human` ID certificate keeps its accepted meaning: its issuer vouches
for the person, by that issuer's own conditions. An organisation's vouching is
unchanged. It has no self-attestation basis, and an organisation never reads
"unknown" for lack of a hardware statement.

Hardware backing is a separate claim. The issuer signs a statement P over the
approval-service enrollment binding B. P names the exact basis credential, the
certificate and the identity key. Its lifetime is at most
`min(snapshot valid_until, issued_at + 31 days)`, and never past a withdrawal
date the issuer already holds. When FIDO withdraws a model, the issuer stops
renewing P and the verifier shows **hardware backing lapsed**. Nothing is
revoked, and the person's personhood is unaffected.

# Why

- B has no lifetime. Its currentness is anchored to the identity key, so a
  grade signed into B keeps reading "hardware" after a model withdrawal until
  the identity key changes. That is a silent overclaim.
- Public verifiers cannot re-evaluate a withdrawal: the attested model
  (AAGUID) is private to the issuer. Only the issuer, holding its private
  assessment, can honour a withdrawal, and a short renewal period is how it
  does so without revocation.

# Rejected

- **Reading backing from B's grade.** No lifetime, so it overclaims silently
  after a withdrawal.
- **A hosted sign-in security key as the basis.** Nobody else can check it,
  and it would be a second binding mechanism beside B.
- **Publishing the grade in the registry.** It contradicts the accepted rule
  that a bare ID cannot be looked up for its grade.

The rules that make the renewal safe are in
[a renewable assurance statement](/aweb-protocol-expert/lessons/a-renewable-assurance-statement-is-safe-only-under-these-rules.md).
How a verifier learns whether an issuer requires hardware for `kind=human` is
[the issuer personhood condition](/aweb-protocol-expert/decisions/issuer-personhood-condition-is-a-namespace-record.md).
This separation applies
[vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md),
and keeping the `kind=human` wording follows
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md).

# Status

Reviewed design, not implemented, and not on main. The design is
`docs/design/hardware-backed-personhood.md` on branch
`agents/aweb-protocol-expert-adyx13-hw-personhood`, ACKed by the reviewer at
3f8e24bdef68. The harvester confirmed that branch tip and the 31-day cap,
the lapsed reading and the no-revocation rule in its text. The scope rulings
(organisation vouching unchanged, no revocation on withdrawal) came from the
integration coordinator, relayed by the approval-service seat, and are
source-reported. Juan's choice between issuing `kind=human` only after
hardware (A) and publishing an issuer condition (B) is recorded in the
issuer-condition decision. The definition of "physical key" is still open
with Juan. Version 1 uses the shared `certified_hardware` grade.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-adyx13-hw-personhood, 2026-11-28; notes/personhood-is-a-renewable-issuer-statement.md.
