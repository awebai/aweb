# Release process

Status: approved replacement release specification for aweb and AC. It
supersedes the release driver, the per-component tag lanes, the runnerless
document, and the ship-gate-on-every-landing model. Implementation lands the new
mechanism and the deletions below in one reviewed change set. Machinery facts:
audit on task `aweb-abds.4`.

## Operating model

- `main` in each repository is the agent integration branch. Comprehensive
  release CI does not run on `main` landings; PR CI stays as it is.
- Each repository has a `release` branch that is only a publication pointer,
  advancing fast-forward-only to an exact commit already on `main`. Release-only
  code never exists; a bad candidate is fixed on `main` and re-promoted.
- Expensive correctness gates run once, locally, in clean Docker, before
  `release` moves. GitHub never repeats them: advancing `release` triggers only
  thin packaging/publication/deployment plus cheap integrity, installability,
  digest, and health verification. GitHub rebuilds from the exact locally tested
  source SHA; this pragmatic boundary is accepted and the cheap post-publication
  checks cover it.
- Juan gives one global go against one script-generated release card; the agent
  then runs a single idempotent continue operation. No per-repository,
  per-artifact, phase, migration, or deployment approvals exist.
- Exactly two operator commands. Branch moves, version discovery, artifact-set
  calculation, registry polling, workflow dispatch/monitoring, retries, and
  verification are scripted; the agent never manually builds, tests, publishes,
  migrates, edits pointers, or deploys.
- Audit trail: GitHub workflow run identity and logs, registry state, provider
  deployment records. No release IDs, manifests, receipts, anchors, claim
  stores, or custom audit stores.

## Artifacts

aweb (github.com/awebai/aweb) publishes:

| Artifact | Registry | Version source |
|---|---|---|
| aweb server | PyPI `aweb` | `server/pyproject.toml` |
| AWID service | PyPI `awid-service` | `awid/pyproject.toml` |
| AWID image | `ghcr.io/awebai/awid` | `awid/pyproject.toml` |
| aw CLI | GitHub Release + npm `@awebai/aw` via repo `awebai/aw` | remote `aw-v*` tag history |
| channel plugin | npm `@awebai/claude-channel` | `channel/package.json` |
| pi extension | npm `@awebai/pi` | `pi-extension/package.json` |
| skills | npm `@awebai/claude-skills` + ZIPs on the `skills-v*` GitHub Release | `packages/claude-skills/package.json` |
| a2a-gateway image | `ghcr.io/awebai/a2a-gateway` | equals server version |
| awid.ai site | Render static site via `deploy-awid-landing` branch | n/a |

AC (github.com/awebai/ac) publishes:

| Artifact | Registry / target | Version source |
|---|---|---|
| product image | `ghcr.io/awebai/ac` | `backend/pyproject.toml` |
| production deployment | Render service `aweb-cloud`, by image digest | the image |
| aweb.ai site | Render static site via `deploy-landing` branch | n/a |

Explicit non-artifacts (nothing here builds or publishes them): `channel-core`
(bundled into channel and pi), the five `skills/aweb-*` sources (bundled into
pi, claude-skills, and the ZIPs), server source baked into the AWID image,
`packages/codex-plugin`, `naapp/*`, `naapp-lib`,
`packages/hermes-aweb-platform`, `resource-packs/`, `oas/`, `test-vectors/`.
Marketplace pointer and AC pin are publication effects, not artifacts (see
Pointers). Sites deploy through their existing branch-push mechanism, invoked
by the continue command, outside the artifact ordering.

## The static DAG

The complete verified ordering (audit, task `aweb-abds.4`):

1. PyPI `awid-service` before PyPI `aweb` (aweb requires `awid-service>=`).
2. npm `@awebai/aw` before npm `@awebai/pi` when pi's floor moves (`^` dep).
3. npm channel and skills publication before the marketplace pointer advance.
4. All intended aweb/AWID publications served by the public registries before
   the AC gate runs, because AC installs them from PyPI.
5. AC image pushed before deployment; deployment before digest/health verify.

Bundling (channel-core, skills sources, server source in the AWID image) is
same-commit content, not an ordering edge. Unresolved edges, stated not hidden:
the internals of `awebai/aw` (goreleaser + npm publication) and of
`awebai/claude-plugins` are unaudited external repositories; the continue
command treats them as dispatch-and-verify targets only.

## The two commands

### `make release-prepare` (before the go)

Inputs, the only judgment the agent supplies: `PURPOSE="..."` and
`COMPAT_BREAK="none"` or a one-line description of the intentional break.

The script, with no further prompts:

1. Fetches; selects the exact aweb and AC `main` commits (tips unless
   `AWEB_SHA=`/`AC_SHA=` name older commits on `main`); refuses dirty trees or
   unpushed selections with the exact commands to fix.
2. Computes the artifact set: a component moves iff its manifest version is not
   in its registry (aw: next tag-history version; a2a-gateway: server version
   absent from GHCR). Prints the set and versions.
3. Runs the aweb release gate once in clean Docker: builds every moving
   artifact release-shaped (wheels, npm packs, OCI images) and runs the required
   suites (current `make test` content, cli e2e, federation e2e, channel
   integration, locked suites, freshness, vulnerability audits, version-bump
   guards). One additional run is allowed only for one last-released/new
   mixed-version compatibility pairing when a moving component has one.
4. Prepares, on AC `main` as a normal reviewed commit, the pin/lock update
   naming the aweb versions being published (`release-pin.toml`,
   `backend/uv.lock`). The AC gate itself cannot run yet (dependencies
   unpublished); the card says so.
5. Generates and prints the release card.

Failure at any step stops with the failing step, the log path, and the one next
command (fix on `main`, rerun prepare). Nothing has been published; `release`
branches have not moved.

### The release card

Script-generated, answering only: dependency closure (exact aweb and AC commits,
artifacts and versions, in DAG order); customer compatibility, including the
explicit known break or "none"; tests/e2e state (which suites ran, at which SHA,
result); purpose; whether production deployment is included. For AC artifacts it
states: dependency, test, and compatibility gates are pending and will be
enforced automatically before AC publication; the go cannot waive them. Juan
replies with one go to the card.

### `make release-continue` (after the go)

Idempotent; safe to rerun until it prints DONE. The steps, in order:

1. Advance aweb `release` fast-forward to the prepared SHA.
2. Dispatch and monitor the thin aweb publication workflows for the moving set,
   in DAG order: PyPI awid-service, PyPI aweb, AWID image, aw sync to
   `awebai/aw`, npm channel/pi/skills + skills ZIPs, a2a-gateway image. Each
   workflow rebuilds from the exact `release` SHA, publishes, pushes its version
   tag, and runs its cheap verification (registry serves the exact version;
   installability; image digest resolves).
3. Advance the marketplace pointer to the published channel/skills versions.
4. Poll the public registries until every intended aweb/AWID version is served;
   bounded wait with a clear still-waiting message.
5. Run the AC release gate once in clean Docker at the prepared AC `main`
   commit: `make release-ready` content, with the image build installing the
   just-published public wheels.
6. Advance AC `release` fast-forward; dispatch and monitor the thin AC image
   workflow (build from the `release` SHA, push to `ghcr.io/awebai/ac`, emit
   the immutable digest).
7. If the card includes deployment: verify the Render service is configured for
   explicit-digest deploys with auto-deploy disabled (refuse otherwise), apply
   pending migrations via the scripted migration step, deploy the exact digest,
   then verify the provider-reported running digest and health.
8. Deploy any moving sites via their branch-push targets. Print DONE with the
   published versions, digests, and workflow run URLs.

Stop/retry semantics: registry items that already match exactly are skipped; a
registry conflict (same version, different or un-adoptable state) stops with
the conflict named; transient mechanical failures retry the failed job only.
Tests never rerun on retry. A rerun with unchanged commits, versions, artifact
bytes, compatibility result, and deployment intent reuses the same go; any
material change requires a new prepare, card, and go. Every stop names its
state and the resume command (rerun continue); the operator never reconstructs
state by hand.

## Release branch lifecycle

Both branches only ever fast-forward to reviewed `main` commits; force-pushing
them is prohibited. A failed candidate leaves the branch where it was: fix on
`main`, rerun prepare (new card, new go). If publication partially completed,
the published registry versions stay (publication is immutable; fix forward);
the rerun's artifact-set computation naturally excludes what already published.

## Pointers: prepared on main vs moved during publication

Prepared on `main` before the go: version bumps, AC's `release-pin.toml` and
`backend/uv.lock`. These are reviewed source that gates builds, so they must
exist as ordinary commits before any gate runs. Moved during publication by the
continue command: `release` branches, version tags, the marketplace pointer,
site branches. These advertise published state, so they can only be true after
publication; writing them earlier would advertise artifacts that may never
publish.

## AC dependency rule

AC consumes only actually published aweb/AWID packages from public registries —
never staged, unpublished, or cross-workflow candidates. Implementation note:
today's `Dockerfile.release` overlays pinned git source over the installed
wheels; this specification removes the overlay so the image ships the published
wheels the lock resolves (finding F1, task `aweb-abds.4`). The train stops
before AC's `release` branch moves if the AC Docker gate fails, if hosted image
publication fails, or if deployment verification fails; aweb's already-published
artifacts remain published, and recovery is a corrected AC `main` commit plus a
new prepare of the AC half only.

## Production configuration

One-time, verified by the continue command on every deploy: the Render service
deploys only explicit immutable image digests, with registry-push auto-deploy
disabled (as of 2026-08-11 the service points at the mutable `latest` tag with
auto-deploy enabled; the implementation includes correcting this). Rollback is
deploying a previous digest through the same scripted step.

## GitHub outage

No runnerless system is maintained. In an outage, with Juan's explicit risk
override recorded in the go, the kept exact-publish scripts
(`scripts/npm-exact-publish.sh`, `pypi-exact-publish.sh`, `oci-exact-publish.sh`)
may publish the locally built, locally gated artifacts directly; tags and
release assets are pushed when GitHub returns. This is a documented break-glass
use of kept primitives, not a parallel lane.

## Migration: keep, replace, delete

One mechanism must remain. Cleanup is part of the same reviewed change set as
the new scripts, not a follow-up.

Keep (aweb): the test suites and their infra (`make test` content, cli e2e,
federation e2e, channel integration, locked suites, freshness, audits),
`docker-compose.e2e*.yml`, version guards (`check-server-version-bump.sh`,
`cli-release-version.sh`), copy/provenance guards, the three exact-publish
scripts and their tests, PR CI workflows (`test.yml`, `server-ci.yml`,
`cli-e2e.yml`, `federation-e2e.yml`, `library-ci.yml`,
`a2a-copy-guardrails.yml`, `exception-deadlines.yml`).

Replace (aweb): `pypi-release.yml`, `npm-release.yml`, `awid-image-release.yml`
(re-trigger from `release`; strip stage/continuation provenance; keep exact-match
publish and cheap verify); `aw-release.yml` and `a2a-gateway-release.yml`
(re-trigger from `release`; no tag-triggered publication remains);
`scripts/pointer-adapter-marketplace-pointer.py` and `pointer-adapter-ac-pin.py`
(become continue steps, driver protocol removed); `make release-awid-site`
(invoked by continue); `.claude/skills/release`, `deploy-awid-site`,
`cross-repo-change`, and `docs/contributing.md` release sections (rewritten).

Delete (aweb): `scripts/release_driver.py`; `release/components.toml` and
`release/measurements/`; `.release-runs/`; `release-anchor.yml`;
`scripts/release_receipt_archive.py`; the skew-harness family
(`release_skew_harnesses.py`, `release_skew_cli_server.py`,
`release_channel_pi_skew.py`, `release_federation_skew.py`,
`release_persisted_state_skew.py`) and `measure-release-*` targets; all
`scripts/e2e/test_release_*` and `test_pointer_adapter_*` tests tied to deleted
code; `ship.yml` and the `ship`/`ship-gate`/`ship-suites`/`check-ship-*`
targets with `run-ship-suites.sh`/`ship-env.sh` (suite list moves into the
prepare gate); the per-component `release-*-{check,tag,push}` Makefile lane;
`scripts/check-release-tag-monotonic.sh` (+ self-test; both callerless);
`docs/runnerless-release.md`; `docs/setup-surface-release-gates.md` (fold
still-live checks into the gate first); the `test_ship_ci_contract.py` and
`test_release_gate_contract.py` contracts are rewritten against the new
workflows or deleted with them.

Keep (AC): `make release-ready` content as the AC Docker gate; migration
manifest and verifiers; `check_release_model.py` / `check_release_overlay.py`
(re-targeted to wheels-only); `release-pin.toml` + lock mechanics; two-service
and journey suites; site deploy targets; `prod-migrate-direct` as the scripted
migration step.

Replace (AC): `aweb-cloud-ci-cd.yml` (trigger from `release`, keep thin
build/push/model checks, emit digest); `ship`/`ship-tag`/`release`/`deploy`
targets (become the two commands); the manual Render procedure (scripted
digest deploy + verify); `.claude/skills/ship` and the ops release SOP.

Delete/fix (AC): the `Dockerfile.release` source overlay (F1); stale
`ghcr.io/awebai/aweb-cloud` references (`Makefile` `PROD_IMAGE`,
`OPERATIONS.md`, `docker-compose.prod.yml`); the dangling "Cloud Deploy Image"
reference in `ci-failure-alert.yml`; the stale `use-aweb-pypi` refusal.

## Residue check

Implementation is complete only when, in both repositories: repository-wide
searches for `release_driver`, `components.toml`, `release-anchor`,
`runnerless`, `release-plan`, `release-run`, `release-receipt`, `ship.yml`,
`ship-tag`, `stage-only`, `publish-continuation`, `manifest-id`, and the
deleted doc/skill paths return only this document and its history; `make help`
and both Makefiles expose no deleted target; no workflow in either repository
can publish or deploy except the `release`-triggered ones defined here; every
tag-triggered publication path is gone; obsolete tests and fixtures are deleted
with the code they covered; and all surviving documentation describes the local
Docker gate, thin GitHub publication, the two-repository staged train, and the
one global go.
