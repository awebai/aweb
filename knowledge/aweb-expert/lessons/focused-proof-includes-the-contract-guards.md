---
type: Lesson
title: Focused proof includes the contract guards
description: When choosing focused tests, enumerate the contract surfaces a change introduces and run each surface's independent guard (reviewed route-scope inventories, the packaged migration chain, downstream byte-identical goldens, the product-table write ceilings for test changes), not only the behavioural tests.
tags: [lesson, testing, review, contracts, release]
timestamp: 2026-11-26
---

Two seats hit the same gap independently, and each miss cost a full covering
train.

- A new route and migration passed their focused real-service tests, a
  source-inventory checker and the vector-provenance check. The covering train
  then failed two tests the focused run never selected: the reviewed list of
  route grant scopes and the ordered packaged migration chain. The fix was four
  lines of expected test data; product code was unchanged.
- A shared stylesheet change passed the shared package's own hash and
  class-coverage checks. A downstream app's byte-identical parity goldens then
  failed in the train, because the stylesheet fingerprint appears in its
  rendered output. Again only expected outputs changed.

# How to apply

- List the contract surfaces the change introduces or alters (routes and their
  grant scopes, migrations, shared generated assets), then find each surface's
  independent guard and include it in the focused run.
- A checker named for "source inventories" does not establish that every
  inventory was checked. Applying a migration and listing it in the packaged
  chain are separate properties.
- Shared assets have downstream consumers whose generated-output tests are sites
  of the change, not only their runtime callers.
- Do not invent a grant scope just to put a route into an inventory; record the
  route's actual authentication mode.
- Test files are a contract surface too. The product-table write ceilings
  (`make check-product-table-writes`, rules in `docs/test-product-state.md`)
  went red in the gate on 2026-11-26 when a new refusal test's setup rows took
  a file from 7 to 10 unmarked writes. The check takes seconds: run it on any
  head that adds, moves or deletes test database writes, and on a combined
  stack before a gate.
- To test that the database refuses a value under those ceilings, one marked
  write of the refused value is enough. PostgreSQL checks CHECK constraints
  before foreign keys, so no parent rows are needed; assert the exact
  constraint name so a missing parent cannot pass the test (e43fe3317a).

The durable fix would be tooling that maps changed paths to their guards; until
then this is a selection habit. It extends the site enumeration in
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-pages-requests` (note
`focused-proof-needs-contract-inventories.md`; coordinator b8e9d11b) and the
retired seat `aweb-expert-secrets-site` (note
`shared-assets-need-consumer-output-checks.md`; secrets coordinator b9d449f7).

The write-ceiling bullets: OKF proposal from aweb-expert/aweb-expert-cleanup-oss,
2026-11-26; notes/product-table-write-ceilings.md. Checked by the harvester on
aweb main 5c2ee7bad: the rules in `docs/test-product-state.md` and
`scripts/product_table_writes.py`, and e43fe3317a, whose message records the
7 to 10 red and the single marked write.
