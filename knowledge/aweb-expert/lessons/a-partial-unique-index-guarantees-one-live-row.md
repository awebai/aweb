---
type: Lesson
title: A partial unique index guarantees one live row, not one row
description: When uniqueness holds only over live rows (a partial unique index WHERE deleted_at IS NULL), a single-row read by that key that does not filter deleted_at must order the live row first; without an order the result follows heap order, which differs between environments, so a green test in one environment is not evidence.
tags: [lesson, sql, soft-delete, review, testing]
timestamp: 2026-11-24
---

A key on a soft-deleted table can hold one live row and any number of deleted
rows when the unique index is partial (`WHERE deleted_at IS NULL`). The index
records "one live row", not "one row". A read that takes one row by that key
without filtering `deleted_at` and without an order cannot use the partial
index, so Postgres returns whichever row comes first in heap order.

In aweb this happened on `agents`: the active-key index on
`(team_id, did_key)` is partial, and `/v1/connect` inserts a new row when the
only row for the key is archived. The native member read added in server
1.27.51 took one row by `(team_id, did_key)` with no order and got the older,
archived row. A member that reconnected after being archived was refused as
"Agent not connected" on every certificate route. Production held six such
pairs when it was found (2026-11-24, task aweb-adwg).

The failure is silent and depends on storage order. The hosted product's
end-to-end test of the same flow stored the live row first and passed on the
unfixed code. The OSS fixture stored the archived row first and failed. A
passing run in one environment therefore proved nothing.

# How to apply

- A single-row read by a key that is unique only over live rows either
  filters `deleted_at IS NULL` or states which row it returns with an explicit
  order. The fix here orders the live row first and then the newest deleted
  row: `ORDER BY (deleted_at IS NOT NULL), created_at DESC LIMIT 1`.
- Prefer one owner for the read and route other callers through it, so the
  order lives in one place.
- When reviewing such a fix, search for every other single-row read by the same
  key. Show each one safe (it reads the whole set, filters live rows within the
  unique scope, also selects by a row id, or is ordered) or route it through
  the owner. Here the audit of every `agents` read by `did_key` found the rest
  safe.
- Write the reproduction so that it asserts the failing storage order as a
  precondition (for example by `ctid`), instead of relying on whatever order
  the run happens to produce. Otherwise the test can pass on unfixed code.

This is a case of
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md):
the other readers of the key are sites too. It is a different defect from
[a projection governs the whole query and the whole result](/aweb-expert/lessons/a-projection-governs-the-whole-query-and-result.md),
which is about query shape under authorization.

Limit: one table and one incident. The ordering rule applies to any
soft-delete schema with a partial unique index.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-withdrawn-address,
2026-11-24; notes/agents-did-key-read-audit.md. The red test (b1cafc234c,
which asserts archived-first by `ctid`) and the fix (daa32b0cf3) are on the
review branch `agents/aweb-expert-withdrawn-address`, not yet on main when
harvested. The production pair count and the hosted-product test result are
source-reported.
