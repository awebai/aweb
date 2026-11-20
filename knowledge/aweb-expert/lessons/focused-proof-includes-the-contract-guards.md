---
type: Lesson
title: Focused proof includes the contract guards
description: When choosing focused tests, enumerate the contract surfaces a change introduces and run each surface's independent guard (reviewed route-scope inventories, the packaged migration chain, downstream byte-identical goldens), not only the behavioural tests; a green candidate checks stage runs no Go tests, so a Go change also needs a full make test-cli run.
tags: [lesson, testing, review, contracts, release]
timestamp: 2026-11-09
---

Three misses of the same kind, each costing a full covering train.

- A new route and migration passed their focused real-service tests, a
  source-inventory checker and the vector-provenance check. The covering train
  then failed two tests the focused run never selected: the reviewed list of
  route grant scopes and the ordered packaged migration chain. The fix was four
  lines of expected test data; product code was unchanged.
- A shared stylesheet change passed the shared package's own hash and
  class-coverage checks. A downstream app's byte-identical parity goldens then
  failed in the train, because the stylesheet fingerprint appears in its
  rendered output. Again only expected outputs changed.
- A Go change raising the supported app manifest version passed the candidate
  checks stage (`AWEB_CANDIDATE_STAGES=checks make candidate-gate`) and
  focused Go package runs. The train's full gate then failed it in
  `cli/go/internal/conformance`, which the focused runs had not selected. The
  checks stage runs lints, reference and vector-provenance checks; `make
  test-cli` (`go test ./...` under `cli/go`) belongs to the unit stage, so a
  green checks stage said nothing about the Go suite.

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
- A green checks stage is not Go test evidence. A landing request for a Go
  change carries the checks stage and a full `make test-cli` run, in a clean
  agent environment, on the exact head. The stage contents are in
  `scripts/candidate-suite.sh`; read them rather than assume a stage's name
  covers a suite.

The durable fix would be tooling that maps changed paths to their guards; until
then this is a selection habit. For the Go suite, the fix belongs to whoever
owns the landing-request rule in
[lane trains share main](/coordinator/lane-trains-share-main.md), which asks
for a green checks stage and does not say that stage omits Go tests. It
extends the site enumeration in
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md);
the conformance failure above is worked through in
[widening a supported set moves its negative controls](/aweb-expert/lessons/widening-a-supported-set-moves-its-negative-controls.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-pages-requests` (note
`focused-proof-needs-contract-inventories.md`; coordinator b8e9d11b) and the
retired seat `aweb-expert-secrets-site` (note
`shared-assets-need-consumer-output-checks.md`; secrets coordinator b9d449f7).

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-09;
notes/checks-stage-does-not-run-go-tests.md (aweb-acgh.16.40 at aa2704d96,
train 33 gate; fixed in d3e8af4e3). The stage contents were confirmed in
`scripts/candidate-suite.sh` on main at 0b67bf256.
