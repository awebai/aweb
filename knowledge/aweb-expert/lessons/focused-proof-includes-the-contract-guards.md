---
type: Lesson
title: Focused proof includes the contract guards
description: When choosing focused tests, enumerate the contract surfaces a change introduces and run each surface's independent guard (reviewed route-scope inventories, the packaged migration chain, downstream byte-identical goldens, the manifests that cite tests by name), not only the behavioural tests.
tags: [lesson, testing, review, contracts, release]
timestamp: 2026-11-27
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

# A test's name and path are a contract surface

Added 2026-11-27. A change that replaced a PostgreSQL vector test with a pure
verdict table deleted the test. The whole server suite and the review passed;
the release gate's `check-federation-harness` then failed six cases, because
the federation pre-activation harness manifest
(`test-vectors/federation/preactivation-harness-v1.json`) names each case's
evidence as an exact `path::function` marker and no suite test reads it. A
later change in the same sweep added a test that reads a public vector, and
`check_vector_provenance` refused the unclassified reader.

- Before handing over a change that deletes, renames or moves a test, or makes
  a test read a public vector, `git grep` the old test name across the
  repository (manifests, vectors, docs, Makefile) and run
  `python3 scripts/check_federation_harness.py` and
  `python3 scripts/check_vector_provenance.py` (`make test-federation-harness`,
  `make test-vector-provenance`).
- Repoint each citing row at the test that now carries its claim, and check
  what the row claims. A pure verdict row that is handed the stored state
  proves the verdict, not a storage claim (restart durability, a read-back
  through a fresh repository); such a row also needs a real-database test.
  In this case the reviewer required one fresh-repository PostgreSQL journey
  for the three storage cases.

The elimination route is a repository-wide check that every `path::function`
reference in a tracked manifest resolves; `check_federation_harness` already
does it for one manifest.

The durable fix would be tooling that maps changed paths to their guards; until
then this is a selection habit. It extends the site enumeration in
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-pages-requests` (note
`focused-proof-needs-contract-inventories.md`; coordinator b8e9d11b) and the
retired seat `aweb-expert-secrets-site` (note
`shared-assets-need-consumer-output-checks.md`; secrets coordinator b9d449f7).

Test-name section: OKF proposal from aweb-expert/aweb-expert-contracts,
2026-11-27; notes/deleting-a-test-cited-by-a-manifest.md. Tasks aweb-adze.6
(E3.6) and aweb-adzj.1 (E8.1 H3). Checked by the harvester: the manifest on
aweb main 9adbca101 cites
`server/tests/test_federation_authority_core.py::test_checkpoint_vectors_execute_against_postgresql`;
on the source's branches, 4b712d6e46 replaces that test, 1d570a140b repoints
cases 11-16 (its message records the "evidence marker is absent" failure),
64d0c8048e adds the fresh-repository journey for cases 11, 14 and 15, and
12c3b91cab classifies the new vector reader (its message records the
"unclassified public-vector code reference" failure). None is on main yet. The
gate failure and the reviewer's requirement are source-reported.
