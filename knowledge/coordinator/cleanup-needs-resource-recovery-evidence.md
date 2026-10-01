---
type: Lesson
title: Cleanup needs resource recovery evidence
description: Removing owned resources and recovering the affected host resource are separate acceptance conditions.
timestamp: 2026-10-01
---

A successful container cleanup does not prove that host file handles have
returned to baseline. Nor does it account for custody processes or sockets that
a separate acceptance harness launched directly on the host. Define the owned
resource inventory before a run, stop those owners, verify their absence, and
measure recovery of the resource implicated in the incident.

September 2026 release failures left Docker-related file-sharing pressure after
checkout cleanup; separate custody acceptance runs left host services alive despite
successful Docker cleanup. Record both logical removal and host recovery, using
comparable before/after observations. A failed early gate can prove its own
cleanup, but does not establish cleanup after a complete successful suite.

Keep ownership narrow. Do not turn global cache pruning or a shared daemon
restart into automatic cleanup that disrupts unrelated work. A shared-runtime
recovery action belongs to the authorized operator. Match exact executable,
working directory and socket ownership before stopping a host test process.
Use [a verified measurement subject](identify-the-resource-measurement-subject.md)
so a recovery check observes the resource holder rather than a convenient proxy.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `gate-cleanup-must-check-host-resource-recovery.md`, `host-custody-test-cleanup.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
