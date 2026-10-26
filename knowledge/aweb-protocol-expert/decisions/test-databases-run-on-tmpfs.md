---
type: Decision
title: Test databases run on tmpfs
description: Intermittent PostgreSQL stalls in the test suite are fixed by putting every test database on tmpfs, never by raising a timeout or skipping; the mount must be verified, not assumed. Accepted, not yet landed.
tags: [decision, testing, postgresql, flaky-tests, infrastructure]
timestamp: 2026-10-21
---

Approved by the OSS coordinator on 2026-10-21 after an intermittent five-second
PostgreSQL setup timeout blocked a landing. The standing rule: "We don't land
past an unexplained intermittent failure... fix it without raising the
timeout." The approval: test databases that stall for seconds on host I/O are
the defect, and tmpfs removes it.

**Status:** accepted direction, not landed; confirmed by the coordinator on
2026-10-25. On main, only some end-to-end compose files use tmpfs, and the
shared test launcher still starts PostgreSQL on disk.

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
by the OSS coordinator in f8d89364.
