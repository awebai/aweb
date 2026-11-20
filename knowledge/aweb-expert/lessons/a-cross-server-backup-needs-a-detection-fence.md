---
type: Lesson
title: A backup across several PostgreSQL servers needs a detection fence
description: A logical backup that spans several PostgreSQL servers is consistent only if a fence detects any write during the capture; sampled snapshots and sampled client lists miss writes, and pausing writers only makes a clean capture likely.
tags: [lesson, postgresql, backup, consistency, test-worlds]
timestamp: 2026-11-14
---

Learned on 2026-11-14 while preserving a kept team-deployment test world whose
state lives on more than one PostgreSQL server. Review refused two capture
packages, and each refusal showed a plausible consistency argument that does
not hold.

# What fails

- **An unchanged `pg_snapshot_xmax` across the capture.** A transaction that
  already holds an xid can commit between two dumps without moving xmax.
- **No xid in progress at the start, with the client list read only at the
  edges.** A session that connects and leaves between two samples is invisible
  there. Sequence changes do not reliably show up in transaction snapshots
  either: `nextval` does not assign an xid on every call.
- **Excluding writers by network or role.** In a test world the database
  servers can share a network with every other container, and a database on
  trust auth admits any client. Nothing excludes a late session.
- **Pausing the writers.** That makes a clean capture likely, but it proves
  nothing. Do not widen the pause by inference either: pausing more containers
  "to be safe" is scope creep, not proof.

# The fence

On every server:
- at the start, no xid in progress and no prepared transaction;
- at the end, an identical snapshot, still with no xid in progress;
- identical `(last_value, is_called)` for every sequence;
- `pg_stat_database.sessions` per database grew by exactly the sessions the
  capture itself opened. Count every session the capture starts. Read the
  counts only after the capture's own sessions have exited, because a backend
  reports its session at exit at the latest.

If any check fails, the capture is not consistent, and a restore must refuse
it. A restore consumes only a capture that ended, passed the fence and matches
its manifest.

**Status (2026-11-14).** The session-count check is reasoning from the
PostgreSQL source and documentation. The real-PostgreSQL proof scenarios were
still pending, and the third capture package was in review. Whoever runs that
proof updates this status.

Related: [a kept test world's registry lives in RAM](/aweb-expert/lessons/a-kept-test-worlds-registry-lives-in-ram.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14;
notes/cross-store-backup-needs-a-detection-fence.md. The refused packages and
the review findings are source-reported. The source's claim that `setval`
takes no xid is not repeated here, because the harvester could not confirm
it.
