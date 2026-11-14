---
type: Decision
title: Legacy outage grace is not protected authority
description: Ordinary legacy messaging keeps its existing registry-outage grace measured from the original data age, protected teams and governance effects get no outage grace, and missing or older-registry protection evidence stays unavailable rather than being inferred legacy, including after bootstrap or restore. Accepted 2026-11-14 (source-reported); not a release or implementation design.
tags: [decision, protected-teams, freshness, outage, revocation, compatibility]
timestamp: 2026-11-14
---

Accepted by the operator on 2026-11-14, relayed by the coordinator by mail.
This base cannot read that record, so the acceptance is **source-reported**,
not verified.

**Status:** a ruling on the conflict, not an implementation. The
representation of legacy outage admission, the startup behaviour, the cache
architecture and any operator-scope restriction are **not decided** here. The
operator-scope statement was explicitly left undecided.

# The conflict

Enforcing protected-team governance freshness collides with keeping existing
users available through a registry outage. There are two silent ways to
resolve it, and both are rejected:

- **Renewing stale authority** so that protected effects keep working through
  an outage. A cache hit or a failed refresh never renews evidence, and an
  error is never positive evidence of anything.
- **Removing the established legacy outage allowance** so that every team
  fails closed as fast as protected teams do. That would turn stronger
  protected governance into an availability regression for existing users
  who never opted into protection.

# Decision

- **Ordinary legacy messaging keeps the existing outage grace**, measured from
  the original age of the cached data, never from a refresh attempt. The
  canonical contract and its constants are in `docs/trust-model.md`
  (revocation and team-controller key outage grace); this concept does not
  restate them.
- **Protected teams and governance effects get no outage grace.** Their
  protection observation keeps its own validity bound
  (`docs/protected-team-boundary.md`), and a different effect class cannot
  silently borrow the legacy outage policy. Ordinary revocation grace and
  protection-observation validity are specified separately.
- **Missing protection evidence is unavailable, never legacy.** A missing
  response field, an older registry, a malformed binding or a failed lookup
  does not establish legacy, on bootstrap included. Empty local consumer
  history cannot establish that a registry is safely legacy, because a fresh
  install or a restore looks the same.

# Rejected

**Inferring legacy from absent fields** to keep older registries working. The
compatibility measure is ordering instead: upgrade the registry first, so that
absence of protection is projected explicitly, then deploy protected
consumers. Registry-first ordering is deliberate.

# Relation

This refines how [evidence freshness survives lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md)
applies across effect classes: original age is retained across reuse and
awaits, and the legacy outage allowance is not permission to renew a
protected deadline. It follows
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
in keeping existing behaviour for teams that did not cut over. It does not
authorize implementation details, a cutover or a release.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-boundary, 2026-11-14; notes/ordinary-legacy-outage-is-not-protected-authority.md.
The source's compatibility matrix, measurements and candidate implementation
were not promoted as accepted policy.
