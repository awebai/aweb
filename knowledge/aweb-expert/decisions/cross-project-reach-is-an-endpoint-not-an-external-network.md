---
type: Decision
title: Cross-project Compose reach is an explicit endpoint, never an external network
description: When a journey's Compose project must reach a service in another project, it declares only its own networks and connects the one consuming container to the provider's network between create and start; it never declares the other project's network external, and the candidate gate keeps refusing external networks with no exemption list.
tags: [decision, docker, compose, candidate-gate, e2e, networking]
timestamp: 2026-11-14
---

A journey sometimes runs a second Compose project that must reach a service in
the journey's own project (Phase 11b2 runs a customer aweb that must reach the
journey's awid). The candidate gate's network renderer,
`scripts/candidate-network.py`, refuses every caller-declared external network:
it cannot prove who owns one, and adopting it would let a caller pass its own
network off as gate-owned. An overlay that declared the journey's default
network `external: true` therefore stopped a release-candidate gate at its first
`compose config`.

# Decision

- The consuming project declares only its own networks.
- The journey runs `up --no-start` for the consumer, then
  `docker network connect <providing project>_default <consumer container>`,
  then `up -d`, and checks that the running container is the one it connected.
- The guard stays as it is. No exemption list.
- Under the gate the renderer resets every service's `ports`, so a second
  project's URL comes from `journey_url` (the scoped service name), never from
  a published host port.

# Why

- Each project owns only its own networks; the cross-project link is one
  visible endpoint.
- Cleanup order follows from it: the consumer's `down` removes the endpoint
  before the provider's `down` removes its network.
- The same route works on a plain host and under the gate.
- Compose v5.7.1 (`pkg/compose/reconcile.go`, `mustRecreate`) recreates a
  container only on a config or image hash change, or when an *expected*
  network is missing, so a network connected at runtime survives the second
  `up`. This is a source reading; the check that the running container is the
  connected one guards it at runtime.

# Rejected

- **Declaring the other project's network `external`.** That is exactly the
  caller-owned network the gate exists to refuse.
- **An exemption list in the guard.** It would reopen the disguise the guard
  stops.
- **A nonexternal network carrying the provider's explicit `name`.** The
  gate's `prepare()` refuses it on the project label, and it is the same
  disguise.
- **A gate-rendered shared network.** It adds a new ownership concept to the
  renderer for one consumer.

# Status

Decided by the deploy-team seat on 2026-11-14 and implemented in 70e29779c on a
review branch; it was not on main at a035f0211. Its tests fail on a035f0211 and
pass on the fix, and a negative control keeps the external overlay refused on
the real Compose config (source-reported). A real-daemon Phase 11b2 run had not
been made when this was recorded. No human acceptance is recorded.

Related: [Docker published ports are not a stable test path](/aweb-protocol-expert/lessons/docker-published-ports-in-tests.md)
reaches the same conclusion from flaky host-port routing: use the Compose
network's internal endpoints.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14; notes/cross-project-reach-is-an-endpoint-not-an-external-network.md.
