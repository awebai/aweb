---
type: Lesson
title: The first run on a new host type is a portability test
description: A gate that has only ever run on one platform encodes that platform; the first full gate on native Linux failed its checks on two Docker Desktop and non-root assumptions, so treat a new host type's first run as a portability test and never rerun an unchanged SHA after a deterministic failure.
tags: [lesson, testing, gates, docker, linux, portability]
timestamp: 2026-11-11
---

The candidate gate had only ever run on a Mac with Docker Desktop. The first
full gate on a native-Linux VM, at main 7f4be32fa on 2026-11-11, failed its
checks stage in 21 s on two tests that encoded the old host.

- **Host-gateway reachability.** Reaching a port published on 127.0.0.1
  through `--add-host X:host-gateway` works on Docker Desktop. On native Linux
  host-gateway is the bridge IP, and the loopback-published port is not
  reachable. A boundary test asserted the Desktop behaviour, and journeys
  reached services that way. The portability fix (branch acwx,
  gate-reachability) replaces that test with a platform-neutral
  port-reservation test and attaches the runner to the network instead.
  Linux qualification is an acceptance condition for it.
- **A root runner.** The permission boundary test passes the caller's UID as
  `--user`. Run as root, the process bypasses mode 0 (CAP_DAC_OVERRIDE) and
  the test fails. The test is right to require a non-root runner, so it stays.
  Decision: VM gates run as a non-root user in the docker group, matching
  developer hosts, and the host check refuses UID 0.

On acwx 1815e7fe6, run as non-root, the boundary tests (13 of 13) and Compose
adoption passed.

This refines
[Docker published ports are not a stable test path](/aweb-protocol-expert/lessons/docker-published-ports-in-tests.md):
the host-gateway behaviour differs between Docker Desktop and native Linux,
not only between gateways.

# How to apply

- Treat the first run on a new host type as a portability test, not a
  capacity or speed test. Expect host assumptions to fail, and fix them in the
  code or the host.
- **Never rerun an unchanged SHA after a deterministic failure.** It tests the
  same code state twice. Change the code or the host first. Where the gate
  ledger is used it enforces this: a failed key refuses a rerun unless the
  coordinator removes the line for an infrastructure failure.
- A host check that refuses the wrong environment (here UID 0) turns an
  environment assumption into a clear refusal instead of a confusing test
  failure.

Related: [every full gate runs on its own VM](/aweb-expert/decisions/full-gates-run-on-per-run-vms.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-11; notes/gate-assumed-docker-desktop-semantics.md and
notes/split-run-completes-one-pass.md. The VM runs are the source's report;
the ledger refusal was read on main at 7f4be32fa
(`scripts/candidate-docker-gate.sh`).
