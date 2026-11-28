---
type: Lesson
title: An issuer condition needs a carrier the holder cannot suppress
description: An issuer-specific condition on what a certificate means cannot travel in holder-presented evidence, because the holder can omit it and the reading falls back to the stronger meaning; either tie the condition to issuance itself, or publish it as an authenticated issuer record that a missing or unavailable answer never upgrades.
tags: [lesson, design, review, certificates, assurance, fail-open]
timestamp: 2026-11-28
---

"Each issuer vouches by its own conditions" is coherent only if a verifier
can learn the conditions. A closed certificate body has no field for them.
If the condition is carried only in evidence the holder presents, the holder
can leave it out, and the default reading is the stronger one: the check
fails open.

# How to apply

- **Option A: tie the condition to issuance.** The issuer issues the kind
  only when the condition holds, so the certificate's meaning needs no extra
  input.
- **Option B: publish an authenticated issuer condition.** The holder cannot
  suppress it. For a covered issuer, a missing or unavailable condition never
  yields the stronger reading, and a hosting provider's origin never selects
  the issuer.
- **Do not put per-issuer condition tables in verifiers.** That lets one
  operator govern the contract.
- In review, take each optional piece of evidence and ask what the reading
  becomes when the holder omits it. If it is the stronger reading, the
  evidence is in the wrong carrier.

The aweb.ai personhood case chose B:
[the issuer personhood condition is a namespace record](/aweb-protocol-expert/decisions/issuer-personhood-condition-is-a-namespace-record.md).
The general rule that an undetermined read never takes the permissive answer
is the same family.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-adyx13-hw-personhood, 2026-11-28; notes/issuer-conditions-need-a-carrier.md. The closed certificate body is in `docs/id-certificates.md` §2 on main.
