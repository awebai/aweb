---
type: Decision
title: Registry outage grace is limited to ordinary legacy messaging
description: During a registry failure, ordinary messaging for a team with explicit legacy (unprotected) evidence may use last-known-good evidence up to 15 minutes of its original age; missing protection metadata, protected teams and governance acts get no grace, protection evidence is specified separately from revocation and key evidence, and rollout is registry first. Accepted, not yet implemented.
tags: [decision, awid, registry, outage, protection, freshness, compatibility]
timestamp: 2026-11-14
---

Ruled by the operator on 2026-11-14 (source-reported: relayed by the OSS
coordinator by mail and recorded independently in a security receipt). It is
an accepted direction; the design, implementation and qualification are still
owed, and nothing here claims runtime behaviour.

# Why

Two distinct failures had been treated as one. A temporary failure to refresh
authority the consumer already established is not the same as the absence of
the authority evidence itself. And ordinary messaging is not the same as an
effect that needs fresh current authority. A shared registry client or cache
refactor that picks a policy by whichever helper the caller uses either
widens outage grace to high-authority effects or, if a stricter field becomes
required, breaks every existing messaging path during an outage. Policy is
chosen by the evidence held and the effect class, never inherited from the
cache helper.

# Decision

- **Ordinary messaging, explicitly unprotected team:** during registry
  failure, last-known-good evidence may be used while its original data age is
  at most 15 minutes, with warnings, then refused. An error is no positive
  evidence and never resets the fetch time or any deadline.
- **No outage grace** for protected teams, for missing or unavailable
  protection metadata, or for any governance act: connect, grant mint and
  revoke, hook binding, owner acts, admission, removal and app tasks.
- **Protection evidence has its own policy.** Revocation and controller-key
  outage grace (documented in `docs/trust-model.md`) and protection-observation
  grace are specified independently; one does not imply the other.
- **Missing metadata stays unavailable on first use.** A consumer facing an
  older registry that lacks the negotiated protection field gets unavailable
  evidence, never inferred legacy. Rollout order is registry, then server, then
  CLI.

# Rejected

- **Inferring legacy from an old registry's missing fields**, backed by the
  consumer remembering it had never observed protection. A newly installed or
  restored consumer's empty memory is not the team's protection history.
- **A qualified compatibility lane** for old registries was considered in
  review and not selected.
- A blanket rule in either direction (grace for everything, or fail closed for
  all messaging) is what this split replaces; reviews should keep the split
  rather than re-derive one.

# Not decided

The wording of the operator's deployment-scope limitation is still open and is
not part of this decision.

# Related

- [Evidence freshness must survive lock waits](/aweb-protocol-expert/lessons/evidence-freshness-survives-lock-waits.md):
  this names where an approved outage window exists; the producer's original
  age still governs across every wait.
- [Released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md):
  the registry-first rollout and explicit operator choice are part of the
  supported deployment contract, not permission for unrelated client
  narrowing.
- The prior public contract is in `docs/protected-team-boundary.md` and
  `docs/trust-model.md` at 16e6862afa.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes, 2026-11-14; notes/legacy-messaging-outage-decision.md.
