---
type: Decision
title: A pinned-release fixture never builds its environment
description: A test fixture that launches a pinned external release (the production AWID) only starts an environment that a setup step prepared (make production-awid-sync). It checks that environment offline and frozen, refuses an unprepared one by naming the prepare command, and launches with --no-sync. Every CI entry point that runs such tests prepares the environment and provides the services the release needs (Redis for AWID).
tags: [decision, testing, ci, naapp, awid, uv]
timestamp: 2026-11-22
---

Decided on 2026-11-22 in task aweb-adqq, following the naapp reviewer's
triage of a red main. Status on that date: implemented on the source's review
branch (7a2ba33d67, 82f4e32af6) and under review, not yet on main.

The production AWID fixture used to sync its pinned project on first use,
during the tests. Folio CI on main failed with six production-AWID setup
errors ("the production AWID exited before it was ready"). They looked like
product failures and depended on network and lock timing. The sync also ran
under the tests' offline and frozen settings, so those guards turned into
errors. Each CI entry point (Folio, Library's naapp-lib job, Logs, Secrets)
prepared the environment differently or not at all.

# Decision

- Preparing a pinned release's environment is a setup step:
  `make production-awid-sync` for the production AWID.
- The fixture checks the environment with
  `uv sync --offline --frozen --check` and never syncs it. If the environment
  is not prepared, it raises an error that names the prepare command.
- The fixture launches the release with `uv run --offline --frozen --no-sync`.
- Every CI entry point that runs such tests runs the prepare step before the
  tests. It also provides the services the release needs to start.

Any new pinned-release fixture or CI job follows the same pattern. The
fixture's refusal is the guard: a job that skips the prepare step fails at
setup and names the command, rather than syncing during the run.

# Rejected

- **Letting the fixture sync on first use.** It hides a missing setup step
  behind network and lock timing. It also makes the frozen and offline
  protections fail instead of guard.

# Discovered

- The production AWID does not start without Redis. A CI job that runs these
  tests needs a Redis service. The Logs and Secrets jobs had none.
- Known gap (2026-11-22): the CI job cache keys do not include the pinned
  project's `uv.lock`. A warm cache can hide an unprepared environment.
  Proof on a fresh cache needs a cache-busting run, and that has not been done
  yet.

# Evidence

Folio CI on main 4c0bb2b8ed (run 44982670758) had the six production-AWID
setup errors. On the branch at 82f4e32af6 (run 44997846157) they are gone. The
failures left in that run are unrelated pg_restore and runtime-health tests.
A Hetzner VM receipt at 7a2ba33d67 reports naapp-lib 5113 passed, 0 failed.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-22; notes/2026-11-22-pinned-release-fixtures-never-sync.md.
