---
type: Decision
title: Lane trains share main
description: A lane whose work is decoupled from the server builds and lands its own train instead of queueing behind the repository train; it pushes only after the repository-train owner OKs the slot, runs the full candidate gate whenever the train touches the shared naapp library, and never re-gates a tree that already failed.
timestamp: 2026-10-25
---

Trains batch ACKed heads into one covering run and one fast-forward push to
main, instead of a queue of per-branch runs. At first one train per repository
carried everything, and the naapp lanes waited on the server train. On
2026-10-21 the operator overruled that for the secrets lane: "as long as your
work is decoupled from the rest you should be ablet to test and ship secrets
without having to wait". The OSS coordinator then ruled the shape that both
naapp lanes use (2026-10-21), and the secrets coordinator confirmed on
2026-10-25 that it is still current.

## Decision

- A naapp lane coordinator builds and lands its own lane train from exact
  ACKed heads. The train's non-merge commits must equal the union of the
  reviewed heads.
- The lane pushes to main only after the repository-train owner OKs the slot,
  so two trains never race the same main.
- A train whose diff touches the shared naapp library runs the full candidate
  gate (checks, unit, artifacts, integration) on the merged tree, the same
  coverage as the server train. App-only and docs trains keep the lighter lane
  run.
- Since 2026-10-25 each landing request carries a green checks stage on the
  exact head it asks to land.
- Before requeueing a red train, check whether main moved or the heads
  changed. If neither did, put the fix in the train first: the candidate gate
  refuses a tree that already failed (see `docs/release.md`), but a refused
  train run still holds the shared suite lock for its other steps, about an
  hour. A flaky test is a code defect that needs a tree-changing fix, not an
  infrastructure rerun.

## Rejected

- Routing every naapp-library change through the server train: it made
  decoupled lanes wait on unrelated server work, which the operator ruled
  wrong.
- Letting a lane train touch the shared library under a subset gate: the
  library's consumers include the server, so its changes need the server's
  coverage.

## Known trap

The Makefile pins the uv cache under `/tmp`, and the macOS `/tmp` reaper
deletes old files but leaves their directories. Gates then fail with missing
package files in the cache that look like test failures. That is an
infrastructure failure: repair or quarantine the damaged cache entries and
rerun with the reason recorded. A per-run cache was rejected because every gate
would redownload everything and its offline steps would depend on the network.
The permanent fix, a persistent cache outside `/tmp`, is tracked as aweb-acln
(open as of 2026-10-25).

Related: [main CI is a separate signal](main-ci-is-a-separate-signal.md),
[staff by reviewed dependencies](staff-by-reviewed-dependencies.md) and
[migration number collisions](migration-number-collisions.md).

## Provenance

Harvested 2026-10-25 from the `secrets` coordinator seat (session transcripts
of 2026-10-21T00:35Z, the operator turn; 2026-10-21T21:31Z, OSS coordinator
ruling 7dc4b6fe; 2026-10-24T20:34Z, uv-cache diagnosis; notes
`gate-failed-tree-ledger.md` and `uv-cache-tmp-reaper.md`), with current status
confirmed by the seat in 493d3b96 (citing OSS coordinator mails 7dc4b6fe and
2557ce17).
