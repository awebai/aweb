---
type: Lesson
title: Docker published ports are not a stable test path
description: On Docker Desktop a reused published port can stop forwarding after its backend is replaced, and a published port reachable through the host gateway may refuse through the bridge gateway; use daemon-assigned ports or the compose network's internal endpoints, and prove the route with controls instead of adding retries or longer timeouts.
tags: [lesson, docker, e2e, networking, flaky-tests]
timestamp: 2026-10-24
---

Three investigations into intermittent end-to-end failures on Docker Desktop
reached the same place.

- **Backend turnover.** Replacing an HTTP server behind the same published host
  port made a client that reused its previous source port time out on connect;
  a fresh source port, a direct connection to the new backend, and a new
  daemon-assigned host port all worked. That justified switching the journey to
  daemon-allocated ports, not changing the server, adding sleeps or adding
  blanket command retries.
- **Gateways differ.** A real PostgreSQL protocol probe completed 300 of 300
  connections through the host-gateway path and 0 of 300 through the bridge
  gateway to the same published port. Pointing the runner at the bridge gateway
  was rejected.
- **What worked.** Attaching the runner to its own compose network and using the
  services' internal endpoints removed the external routing dependency;
  connection pools then opened in about a tenth of a second.

# How to apply

- Prove a network path with controls (fresh source port, direct backend,
  alternative gateway) before attributing a failure to it, and keep the limits:
  these controls established a forwarding failure, not Docker's internal cause,
  and they do not explain every earlier timeout.
- When a pool is slow to start, healthy sessions on the server show only which
  connections completed. Capture the client's thread state and socket inodes
  and match them to TCP state (here: a socket stuck in SYN_SENT with
  retransmits, while the main loop was in epoll).
- A host-green run is not proof of the container runner's network layout.

Related: [reproduce the whole test context](/coordinator/reproduce-the-whole-test-context.md).

# Provenance

Harvested 2026-10-25 from seats `aweb-protocol-expert-p0-review` (note
`ackd-journey-evidence.md`; coordinator assignment d391e3c2) and
`aweb-protocol-expert-app-team-api` (notes
`desktop-published-port-is-not-a-bridge-listener.md`,
`pool-startup-needs-client-socket-evidence.md`), corroborated by
`aweb-expert-naapps-verify` (note `startup-observability-has-stage-boundaries.md`).
