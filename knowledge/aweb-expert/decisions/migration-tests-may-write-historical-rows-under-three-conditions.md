---
type: Decision
title: Migration tests may write historical rows under three conditions
description: Under the product-table write ratchet, a test of migration N may write pre-N rows directly only when it applies the real migrations through the product's migration manager, its marked writes touch only the tables N transforms, and its per-file marked budget is reviewed with the head; a reviewed raise stays red until it is on main.
tags: [decision, testing, migrations, product-state, review]
timestamp: 2026-11-20
---

Reviewer ruling of 2026-11-20 (mail acb73ed4) on a Folio migration verifier
test, applied in cbd75ad5dd and 9e2091c2d4. The OSS coordinator accepted the
citation of that mail (9788d240). This is a team reviewer's ruling, recorded as
the source reported it; it is not a human acceptance.

`docs/test-product-state.md` already says that tests build their worlds through
product owners and that a direct write is allowed only for a state the product
can no longer produce, marked `# unreachable-state:`. A row stored before
migration N existed is such a state: no current owner can write it. The ruling
says how narrow that exception is for a migration test.

# Decision

A test of migration N may write pre-N rows directly only when all three hold:

1. **Real migrations, both sides.** Apply the migrations up to N-1 through the
   product's own migration manager, write the historical rows, then apply N
   through the same manager. Never hand-create the schema.
2. **Only the tables N transforms.** Only migration tests qualify. The marked
   writes touch only the tables N transforms; everything else in the world
   (documents, principals and so on) is still built through owners. Each write
   carries `# unreachable-state:` naming the migration and the state.
3. **A reviewed per-file budget.** The file's `marked_files` ceiling is
   reviewed with the head.

**Why:** without it a data-migration test either cannot exist or hand-builds a
whole world that drifts from the product. The three conditions keep the escape
hatch narrow and auditable. Condition 2 is the one that bites: a first draft
that marked four writes came down to one once documents and principals went
through owners.

# Consequence for the checker

`make check-product-table-writes` compares the head's ceilings with the file
on `origin/main` (`scripts/product_table_writes.py`). A head that raises a
`marked_files` budget, even a reviewed one, stays red there until the raise is
on main. The expected red names only the raise, for example
"marked writes ceiling 1 > reviewed 0". Report it as the reviewed raise; do not
add branch commits trying to clear it, because none can.

The durable home for the three conditions is `docs/test-product-state.md`, and
the lasting fix for the red is a scanner that accepts reviewed marked raises.
Until either lands, this record is the ruling.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links, 2026-11-20; notes/2026-11-20-historical-rows-in-migration-tests.md.
