---
type: Decision
title: New-product admission requires a creator-signed chain
description: In the new product every newly created agent carries a creator-signed ID chain and every agent admission verifies it at the membership grantor with the shared verifier unchanged; chainless agents are replaced, not certified, and the current service and frozen deployments keep their current acceptance.
tags: [decision, identity, id-chain, admission, teams]
timestamp: 2026-11-27
---

Decided on 2026-11-27 for the new product (the pilot and freshly set-up
organisations). Accepted by the operator, **source-reported**: the aweb
coordinator relayed the acceptance in mail 2a27a706, itself relaying the OATS
integration coordinator's e6b1b334. The precise form comes from the aweb
protocol reviewer's verdicts 528075b6 and 1db42419 on task aweb-adyy. None of
these records could be read by the harvester.

# Decision

- Every newly created agent in the new product has a creator-signed ID chain.
- Every agent admission verifies that chain at the membership grantor. It is a
  required check, not a team or organisation opt-in.
- The check: the chain's leaf binds the joining key, ordinary eligibility holds,
  `identity_valid` is true, and the kind is a verified agent. A verified
  `no_human` chain passes; `for_human` is a separate, stricter per-invite
  condition.
- The shared verifier is reused unchanged. The generic `request_disposition` in
  the Python, Go and TypeScript copies, and every frozen service, keep their
  current behaviour, in which `legacy_no_chain` continues.
- A verified existing agent joins with its own chain and needs no new parent. A
  missing inviter child link refuses only a fresh child that has no other valid
  chain.
- Chainless agents are replaced on entry. No retroactive certification path is
  built for them.
- A chainless request to a new organisation refuses from any client, so the
  compatible client floor needs a test.

# Rejected

- **An optional per-team or per-organisation policy.** The guarantee is the
  product's, not a setting a team can leave off.
- **A blanket change to every verifier copy.** That would narrow the released
  disposition, in which `legacy_no_chain` continues, for every existing
  deployment.
- **Certifying an existing chainless root in place.** Chainless agents are
  replaced instead.

# Why this does not break released clients

[Released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
binds contracts that released clients already use. A fresh product that gates
its own admission narrows no released contract, because the current service and
frozen deployments keep their acceptance. The gate lives in the new product's
grantor, not in the shared disposition.

Agents get a first chain only through the explicit exchange, not through
automatic provisioning: see
[only the explicit exchange starts an ID chain](/aweb-protocol-expert/lessons/only-the-explicit-exchange-starts-an-id-chain.md).
Hosted Cloud creation behaviour is outside this open-source base and is not
part of this concept.

Checked by the harvester at aweb main f7a5b9ccb: the released disposition
continues on `legacy_no_chain` (`awid/src/awid/id_certificates.py`
`request_disposition`; `docs/id-certificates.md`, "Request disposition"). The
new-product gate itself is a ruling and is not described in
`docs/id-certificates.md` at that commit.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-oss-classify, 2026-11-27; notes/new-product-agent-admission-ruling.md.
