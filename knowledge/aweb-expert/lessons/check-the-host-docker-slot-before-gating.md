---
type: Lesson
title: Check the host Docker slot before gating on the shared Mac
description: While /tmp/aweb-host-slots/gate exists an RC gate holds the shared Mac's Docker, so run no candidate-gate or Docker work; authors never prune Docker, the coordinator schedules the checks stage; and a "tree … is already being gated" refusal may be your own earlier background run, so check the lock holder before blaming another agent.
tags: [lesson, environment, macos, docker, gate, shared-host]
timestamp: 2026-11-13
---

Recorded from the coordinator's rule of 2026-11-13 (95cfb602), given when an
author's candidate checks stage was refused for Docker disk space while RC2
gate #18 was running.

The Mac's Docker daemon is shared by every agent's gates and the operator's
own work. An RC gate marks its hold by creating `/tmp/aweb-host-slots/gate`.
That marker is a host convention: `scripts/candidate-docker-gate.sh` does not
check it, so nothing stops a second gate from competing for Docker.

# How to apply

- Before any candidate-gate or other Docker work on the shared Mac, check for
  `/tmp/aweb-host-slots/gate`. While it exists, run none.
- Authors never prune Docker. Disk refusals are cleared between gates by the
  designated operator agent, which prunes leaked unused volumes and keeps
  images and build cache. Pruning as an author can delete other agents' state.
- If the slot is held, send the landing request with the other pass lines
  and let the coordinator schedule the checks stage.
- The gate script holds a per-tree lock and refuses with "tree … is already
  being gated". That holder may be your own earlier background run. Check the
  lock file's holder (`lsof` on the tree's lock under the gate ledger's
  `gate-locks/` directory) before assuming another agent.
- Elimination route: the gate script could refuse while the host slot is
  held, and name the lock holder in its refusal. Until it does, this is a
  manual check.

Related: [never kill by pattern on a shared host](/aweb-expert/lessons/never-pattern-kill-on-a-shared-host.md)
records the same shared-user hazard for processes.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/mac-docker-slot-before-checks-stage.md. The per-tree lock and its
refusal text were confirmed in `scripts/candidate-docker-gate.sh` on main at
940cbe65b; the host-slot marker and the pruning rule are the source's report
of the coordinator's rule.
