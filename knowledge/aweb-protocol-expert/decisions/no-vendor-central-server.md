---
type: Decision
title: Nothing requires a vendor-central server; start from BYOT
description: Every aweb flow must work without a mandatory vendor-operated service, with hosted services optional; the starting point is the existing BYOT model, and authority checks such as registry status stay, made against the customer's own registry rather than removed.
tags: [decision, direction, decentralization, byot, awid, revocation, naapp]
timestamp: 2026-11-08
---

Direction from the operator on 2026-11-08, relayed to protocol seats through
aweb by the coordinator. The acceptance is **source-reported**: the relay is
aweb mail the harvester could not read. It is direction, not approval of any
mechanism. The open decisions in the no-central-server assessment that
followed it were not ruled when this was recorded.

# Decision

- Every flow must work without a mandatory vendor-central server. Hosted
  services stay optional.
- The starting point is the existing Bring Your Own Team (BYOT) model, not a
  new customer-key authority. BYOT already holds the customer's authority:
  its controllers, a registry selected through the customer's DNS, and a
  coordination server whose authority the team key signs.
- The direction also asks for authority proofs agents carry and that others
  can inspect; for a human who may hold several identities across
  organizations; and for short-lived credentials where possible. No default
  lifetime may be inferred for resident grants. These name no mechanism, and
  they do not by themselves change
  [credential lifetime is optional team policy](/aweb-protocol-expert/decisions/credential-lifetime-is-optional-team-policy.md).

# Two tests, not one

"Decentralized" is read as two separate tests:

- **A, no vendor-operated service.** Passes when a customer can run every
  required service itself. BYOT plus the naapp-side fixes meets it.
  Customer-run registries and servers pass it; calling them "central" is a
  misreading.
- **B, no common authority lookup at all.** Meeting it would replace live
  registry status checks with something weaker, which changes the revocation
  guarantee. That is the operator's decision, never a side effect of a
  design. Moving revocation to bounded staleness is one of the assessment's
  open decisions.

So registry status checks are kept against the customer's own DNS-selected
registry. They are never removed silently to "decentralize"; see
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md).

# Gaps found against test A

The assessment found the gaps on the naapp side, not in BYOT:

- a naapp verifies every team against one configured registry
  ([a naapp trusts exactly one AWID registry](/aweb-protocol-expert/lessons/a-naapp-trusts-one-registry.md));
- naapp installation authority comes from rows on the coordination host;
- the first passkey binding is gated by email.

# Rejected

- **Removing registry status checks to pass test B.** It weakens revocation
  without a ruling.
- **Hosted-only issuance as the complete answer.** It is a vendor service by
  definition.
- **Reading OIDC workload federation as proof of no dependency.** OIDC
  workload federation (aweb-aclk) is a separate credential family. It still
  depends on the issuer being publicly reachable, on its JWKS, and on the
  provider's STS.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/no-vendor-central-server-direction.md.
The direction was relayed in coordinator mail b1311df9 and 78ee044e. The
assessment (revision 2) was acknowledged by independent review after an
earlier refusal. The A/B reading is from oats 461fc0dc.
