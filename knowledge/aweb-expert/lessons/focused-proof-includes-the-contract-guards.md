---
type: Lesson
title: Focused proof includes the contract guards
description: When choosing focused tests, enumerate the contract surfaces a change introduces and run each surface's independent guard (reviewed route-scope inventories, the packaged migration chain, downstream byte-identical goldens), not only the behavioural tests.
tags: [lesson, testing, review, contracts, release]
timestamp: 2026-10-23
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

The durable fix would be tooling that maps changed paths to their guards; until
then this is a selection habit. It extends the site enumeration in
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-pages-requests` (note
`focused-proof-needs-contract-inventories.md`; coordinator b8e9d11b) and the
retired seat `aweb-expert-secrets-site` (note
`shared-assets-need-consumer-output-checks.md`; secrets coordinator b9d449f7).
