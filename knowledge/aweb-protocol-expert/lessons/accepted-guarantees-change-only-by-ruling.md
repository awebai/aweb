---
type: Lesson
title: Accepted guarantees change only by ruling
description: When an implementation cannot meet a promise in an accepted design, do not align the text down to the implementation; quote the promise and get a ruling. A service-held verification summary or a keyed digest whose key is later destroyed cannot give independent later verification.
tags: [lesson, design, contracts, audit, passkeys]
timestamp: 2026-10-21
---

The accepted secrets design promised that a reviewer holding an approver's
public key could check an approval later without trusting the service. The
approval primitive as built stored a smaller verification summary. The designer
first proposed aligning the design sentence down to that summary; the
coordinator required an explicit ruling on whether the promise was
contractual, and the operator kept it on 2026-10-21: "KEEP THE PROOF. secrets.md
§10.4 stays as written: a reviewer holding the approver's public key can check
an approval later, without trusting our service."

# How to apply

- An implementation's smaller shape does not silently downgrade an accepted
  guarantee. Quote the promised sentence and get a ruling from whoever owns it;
  then either the implementation grows or the promise is explicitly superseded.
- Independent later verification needs the retained signed bytes, the exact
  challenge preimage and context, and the public key compared against the
  reviewer's trusted key. A stored success record only asserts what the service
  checked. A summary HMAC whose key is destroyed cannot supply the check after
  rotation; the public commitment must be unkeyed.

The settled wire contract is in `docs/hook-events.md`; this records why the
weaker form was rejected.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-secrets-design` (note
`proof-commitments-must-outlive-service-keys.md`; coordinator b268fa69, ruling
relay 93e680c4); the seat confirmed the account of its own proposal in
3c6a2c98.
