---
type: Decision
title: Registry signer rotation is independent of domain issuer selection
description: A namespace controller delegates to a stable issuer identity at an exact registry origin, and the issuer's own registry authority owns the issuer-wide operational key set, so a key rotation or emergency withdrawal is one registry-wide update that leaves every subscriber domain's association and organisation head untouched; a verifier establishes both authorities independently and anchors the current key-set digest in authenticated discovery, never in the registry's response. Per-domain signer lists were rejected. Approved design, not on main or implemented.
tags: [decision, awid, standing, issuer, registry, key-rotation, discovery, organisation]
timestamp: 2026-11-28
---

**Status:** approved design for pilot D2, merged to the `one-organisation`
branch at 53a8abbb7 (`docs/design/standing-organisation-records.md`,
sections 1 and 2). The design records the operator's approval of the
identity-path work on 2026-11-28. The rejection of per-domain signer lists
(design review 22e64e75) and the issuer-trust and custody review ACKs
(fa7db244, f3125a64) are **source-reported**: the harvester cannot read
those records. Not on main; implementation and operating evidence are
pending.

# Decision

- **Two authorities, two facts.** A domain's namespace controller signs an
  issuer association: which exact registry origin and which stable issuer
  identity it uses. The issuer's registry domain controller signs one
  issuer-wide key set: which operational keys currently sign standing
  statements, request evidence, feed points and namespace reads.
- **The issuer identity is stable.** It is the registry authority's DNS
  name and does not change when an operational key does. A domain re-signs
  its association only when it changes registry, or after its own
  controller rotates.
- **A key change touches one record.** Rotating or withdrawing an
  operational key updates the issuer's key set and its discovery
  commitment. Subscriber domains keep their existing issuer association and
  organisation head.
- **The verifier checks both, independently.** It resolves the domain's
  discovery (controller, registry, standing issuer) and, separately, the
  issuer's own discovery, which carries the key set's digest. It trusts the
  key set only if issuer and origin match both, the issuer's controller
  verifies the signature, and the digest equals the discovery commitment.
- **The current version is anchored outside the registry response.** A
  missing or mismatched commitment, or a failed authority read, leaves the
  issuer unavailable. The verifier never switches origin or accepts a
  replacement digest supplied by the registry.

# Why

- **Per-domain signer lists make withdrawal a coordinated update.** If each
  namespace signed its issuer's operational keys, withdrawing a compromised
  key would need a new signature from every served domain controller,
  including independent self-custodial tenants who cannot be made to act on
  the registry's schedule. Emergency response would stall on the slowest
  tenant.
- **The facts belong to different authorities.** Choosing a service is the
  tenant's decision; the service's key lifecycle is the service's. Keeping
  them apart lets the registry replace a key once while every tenant's
  choice and organisation definition stay intact.
- **An old signature does not prove currency.** A key set validly signed in
  the past says nothing about whether it is still the current one. Only an
  independently authenticated current commitment does, which is why the
  digest lives in discovery rather than in what the registry serves.

# Rejected

- **A per-domain list of registry signer keys** in each domain's
  association, for the withdrawal-coordination reason above.

# How to apply

When a tenant delegates authority to a service, separate the delegation
(what the tenant chose) from the delegated service's key lifecycle (what
the service rotates), and give each its own signer. Anchor "which version
is current" in a channel the service cannot rewrite on its own. Test
withdrawal with more than one unrelated tenant, so a design that quietly
needs every tenant to act shows up.

This sits beside [owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
and [vary independent assurance dimensions](/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md):
each authority answers only its own question. Related, pending review:
`decisions/portable-standing-with-public-invalidation.md` and
`decisions/applied-feed-freshness-is-one-rule-for-every-verifier.md`, whose
feed and standing keys are the ones this key set publishes.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-coordination, 2026-11-28; notes/registry-rotates-its-keys-independently-of-domain-selection.md.
The harvester checked the two-authority split, the stable issuer identity,
the subscriber domains being unaffected by a key change, and the
discovery-anchored digest against `docs/design/standing-organisation-records.md`
sections 1 and 2 at 53a8abbb7 on `one-organisation`. The review identifiers
and the rejected alternative are source-reported.
