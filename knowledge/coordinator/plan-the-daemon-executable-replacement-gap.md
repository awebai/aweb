---
type: Lesson
title: Plan the daemon executable replacement gap
description: Replacing the executable of a running macOS daemon can stop delivery before the planned restart.
timestamp: 2026-10-01
---

Treat daemon installation as a transition with an explicit delivery gap.
Preserve rollback material and registrations, stop the old daemon, replace the
coherent package/binary, verify it, then start and verify the running daemon.
A separately reviewed new-path/atomic-swap procedure can serve the same purpose.
Do not assume that installing a new command updates an already running service.

On October 1, 2026, an installer replaced the running aw executable and macOS
terminated the daemon for code-signature invalidation before the explicit
restart. The archived lead directive chose stop/replace/start for future installs.
The incident supports that installation lesson, not an explanation for unrelated
resource failures.

After startup, check the actual daemon version and registration reconciliation,
then exercise a real message through presentation and read confirmation. Keep a
bounded observation period when required by the release handoff. CLI version,
registration success and a live daemon PID are useful but incomplete evidence of
service compatibility and delivery.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `macos-daemon-install-gap.md`, `wake-daemon-version-differs-from-cli.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
