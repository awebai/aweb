---
type: Decision
title: The first standing deployment is separate from authority migration
description: The first standing-protocol deployment starts on its own registry while the frozen service keeps the released registry and contract, with no cross-protocol federation in either direction at launch; moving the first existing users is an explicit next milestone with its own transfer, acceptance and change window. A launch-time compatibility bridge was rejected because each direction needs its own adapter and the frozen-to-standing one has weaker freshness evidence. Direction confirmed; design on a branch, not deployed.
tags: [decision, awid, standing, registry, federation, migration, compatibility]
timestamp: 2026-11-28
---

Direction for the million-agent architecture (task aweb-aeal), confirmed on
2026-11-28. **Acceptance: source-reported**: the source cites coordination
messages 7c861069 and 37a6c457, which the harvester cannot read; the proposal
does not say who confirmed. The design records that the operator authorised a
second AWID registry for the pilot on 2026-11-28.

**Status:** design only, on the branch
`agents/aweb-protocol-expert-coordination-aeal` at b664850406
(`docs/design/standing-proof-and-feed.md`, sections 6 and 7), not on main.
Deployment, rehearsal and transfer evidence are still pending.

# Decision

- **A separate registry for the first standing deployment.** The pilot runs
  standing on a new registry with its own origin, deploy unit, database, state
  and credentials. The frozen service and its clients keep the released
  registry and contract unchanged.
- **No cross-protocol federation at launch, in either direction.** A client
  that finds, through trusted discovery, a released-only peer gets a typed
  unsupported-peer refusal; ingress applies the same no-effect rule. An
  unknown or unreachable authority still gets the authority-unavailable
  refusal. Native federation between standing issuers stays part of OSS
  conformance.
- **Moving existing users is its own milestone.** The first cohort of existing
  agents moves in a coordinated migration after the pilot is ready, with its
  own rehearsal against a real source and destination, acceptance and change
  window.
- **A first deployment, not a takeover.** The pilot namespace had no existing
  registration in the inventory. If existing state is found before bootstrap,
  stop and reconcile its authority and history first. Once the new registry
  has accepted writes, pointing DNS elsewhere is not a rollback.

# Why

- **Released reads at the new registry help only one direction.** The new
  registry could serve the released read contract so that a frozen verifier
  can check a standing sender. That covers sender-to-frozen traffic only, and
  only with an exact inventory of the routes, fields and refusals the pinned
  frozen binary uses, private reads kept closed, and the sender also signing
  the released destination artifact.
- **A released-only issuer cannot meet the standing verifier rule.** The
  frozen issuer supplies neither standing nor an authenticated feed, so a
  released federation artifact cannot qualify at a standing route under the
  applied-feed freshness rule (pending review as
  `decisions/applied-feed-freshness-is-one-rule-for-every-verifier.md`).
- **A bridge is a second authority path with weaker evidence.** Admitting the
  frozen issuer would need a separate ingress adapter for an allowlisted peer,
  using online authoritative reads of the legacy registry: request-time
  authority lookups and no 30-second applied-feed guarantee. Keeping it out
  preserves the fail-closed rule and zero request-time lookups on every
  standing route.
- **Continuity belongs in an explicit transfer.** Moving a namespace while
  keeping its identities must fence source writes, export an authenticated
  final cut and verify it before DNS and verifier pins change. That is where
  surviving denies, key and controller history, address continuity and
  historical mail (original signed artifacts, receipts, verification state)
  are reconciled. A DNS change only publishes the selected authority; it does
  not prove continuity.

# Rejected

- **Federating with the frozen service at launch.** Each direction needs its
  own separately approved adapter and bidirectional tests; the
  frozen-to-standing one weakens freshness. Any such path needs explicit
  approval before enablement.
- **Treating the launch as the migration.** Folding the cohort move into the
  first deployment would make denied authority and mail continuity depend on
  a DNS switch instead of an authenticated final cut.

# How to apply

Treat a new protocol launch and a move of existing authority as separate
milestones. Before claiming mixed-version interoperability, check both wire
directions separately: serving the old read contract is not the same as
accepting the old issuer's evidence. A later, separately approved additive
standing issuer at the existing registry is a different option and does not
reopen this launch scope.

Related, pending review: `decisions/portable-standing-with-public-invalidation.md`.
See also [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md):
the frozen service keeps its released contract here.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-coordination, 2026-11-28; notes/standing-cutover-separates-registries.md.
The harvester checked the claims against `docs/design/standing-proof-and-feed.md`
sections 6 and 7 at b664850406 on the source's branch. The confirmation in
7c861069 and 37a6c457 is source-reported.
