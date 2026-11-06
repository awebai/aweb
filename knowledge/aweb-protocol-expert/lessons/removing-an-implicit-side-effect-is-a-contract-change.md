---
type: Lesson
title: Removing an implicit side effect is a contract change
description: A request-path side effect can be the only recovery path for hosts that mount aweb without its lifespan, and a released contract may promise it; removing it keeps the default automatic, gives an explicit opt-out for hosts that own the duty, and never hands hosts a new duty by docstring.
tags: [lesson, compatibility, embedding, outbox, lifespan, contracts]
timestamp: 2026-11-04
---

aweb replayed lifecycle outbox rows on every request. Writers already deliver
their own rows after commit, so the replay only recovered rows left behind by a
crash or a failed delivery. A change that took the scan off the read path
looked like a pure cleanup. But FastAPI runs no lifespan events for a mounted
sub-app, so for a host that mounts aweb the per-request replay
was the **only** recovery. `docs/aweb-sot.md` also promised it to library-mode
embedders. The first version of the change moved the duty to the host in a
docstring, and the OSS runtime reviewer NACKed it as a silent narrowing of a
released contract.

# How to apply

- Before removing request-path housekeeping, ask who else relies on it for
  recovery, and search the source-of-truth docs for a promise of it.
- If something relies on it, make the change additive, as
  [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
  requires of any contract:
  - **Keep the default automatic.** Here the mounted app's first request
    starts a 15 s `recover_outboxes` loop, and no read scans.
  - **Give an explicit opt-out** for a host that owns the duty:
    `create_app(host_runs_outbox_recovery=True)`, for a host whose own
    scheduler runs `recover_outboxes`.
- Never hand hosts a new obligation by docstring or doc edit alone.

The accepted behaviour change is that a failed delivery now retries within
15 s instead of on the next request. Status (verified 2026-11-06): on main
(4d4e1dd14) with `server/tests/test_outbox_recovery.py`, and first released
in server-v1.27.47.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-04; notes/mounted-hosts-own-outbox-recovery.md, notes/released-contract-includes-docstring-promises.md.
