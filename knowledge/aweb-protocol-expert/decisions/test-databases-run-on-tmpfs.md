---
type: Decision
title: Test databases run on tmpfs
description: Intermittent PostgreSQL stalls in the test suite are fixed by putting every test database on tmpfs, never by raising a timeout or skipping; the mount must be verified, not assumed. Implemented in the shared candidate test launcher.
tags: [decision, testing, postgresql, flaky-tests, infrastructure]
timestamp: 2026-10-21
---

Approved by the OSS coordinator on 2026-10-21 after an intermittent five-second
PostgreSQL setup timeout blocked a landing. The standing rule: "We don't land
past an unexplained intermittent failure... fix it without raising the
timeout." The approval: test databases that stall for seconds on host I/O are
the defect, and tmpfs removes it.

**Status** (verified 2026-11-09 at aweb main cfdc06255e2a): the shared
candidate test launcher implements this decision since commit 027e97b5. Its
PostgreSQL data and WAL sit on a bounded tmpfs with swap disabled, and the
launcher refuses to run the suite unless the SQL-reported data directory and
the resolved WAL directory are on tmpfs and swap is off. Other test PostgreSQL
launchers, such as end-to-end compose files, have not been audited against
this decision.

# Evidence

A paired comparison during real train activity: disk-backed PostgreSQL stalled
for more than a second in about 50 of 100 batches, worst case 7.56 seconds;
tmpfs had none. Main and the candidate branch stalled at similar rates on disk,
which cleared the branch. The original cancellation that started the
investigation still has no proven cause; do not cite it as storage causation.

# Decision

- Every test PostgreSQL launcher puts the data directory on tmpfs. No timeout
  increases, no skips.
- Assert that the effective `data_directory` and `pg_wal` resolve under the
  tmpfs mount; an image default could otherwise land silently on the overlay
  filesystem.
- Fail when swap accounting cannot be verified, and give CI its own memory
  budget.

# Measurement lessons from the investigation

- A synthetic writer did not make disk-backed PostgreSQL stall either, so "no
  stalls on tmpfs" under synthetic load proved nothing; compare under the real
  workload in a common collection window.
- Keep observers off the measured path: buffer samples in memory and end the
  comparison window before the first flush; report sample gaps with the result.

Related: [identify the resource measurement subject](/coordinator/identify-the-resource-measurement-subject.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-chat-session-fix` (notes
`synthetic-load-is-not-the-failing-workload.md`,
`diagnostics-can-disturb-storage-measurements.md`, `aciq-time-window.md`;
coordinator a0d0120b; reply 145a45c9), with status and A/B figures confirmed
by the OSS coordinator in f8d89364. Status updated 2026-11-09 from an OKF
proposal from aweb-protocol-expert/aweb-protocol-expert-human-kind;
notes/tmpfs-launcher-landed-status.md. Landing source-reported by the OSS
coordinator, verified against main by the harvester.
