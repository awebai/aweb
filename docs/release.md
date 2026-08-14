# Release process

Status: proposed replacement release specification for aweb and AC; it becomes authority only
after independent review ACK and the coordinator's constraint check. It supersedes the release
driver, the per-component tag lanes, the runnerless document, and the ship-gate-on-every-landing
model; implementation lands the new mechanism and the deletions below in one reviewed change
set. Facts: audit on `aweb-abds.4`; binding decisions F1-F4 and C1-C4: coordinator, 2026-08-11.

## Operating model

- `main` in each repository is the agent integration branch; no comprehensive release CI runs
  on `main` landings. PR checks stay; four workflows lose their `main`-push triggers (Migration).
- Each repository's `release` branch is only a publication pointer: fast-forward-only to an
  exact commit already on `main`, never force-pushed. Release-only code never exists. A failed
  candidate leaves the branch put; the fix lands on `main` and prepare reruns (new card, new go).
  Already-published versions stay published (fix forward); the rerun's set computation excludes them.
- Expensive correctness gates run once, locally, in clean Docker, before `release` moves. GitHub never
  repeats them: advancing `release` triggers only thin packaging/publication/deployment plus cheap
  integrity, installability, digest, and health verification. GitHub rebuilds from the exact locally
  tested SHA — an accepted boundary covered by those checks.
- Juan gives one global go against one script-generated card; the agent then runs one
  idempotent continue operation. No per-repository, per-artifact, phase, migration, or
  deployment approvals. Exactly two operator commands: branch moves, version discovery,
  artifact-set calculation, registry polling, workflow dispatch/monitoring, retries, and
  verification are scripted; the agent never manually builds, tests, publishes, migrates,
  edits pointers, or deploys.
- Audit trail: workflow run identity and logs, registry state, provider deploy records. No
  release IDs, manifests, receipts, anchors, claim stores, or custom audit stores. Ordering is
  the fixed ten-edge DAG, hardcoded — not a graph engine.

## Artifacts

| Repo | Artifact | Registry / target | Version source |
|---|---|---|---|
| aweb | aweb server | PyPI `aweb` | `server/pyproject.toml` |
| aweb | AWID service | PyPI `awid-service` | `awid/pyproject.toml` |
| aweb | AWID image | `ghcr.io/awebai/awid` | `awid/pyproject.toml` |
| aweb | aw CLI (binaries `aw` + `aweb-a2a-gw`) | GitHub Release + the 7 npm packages below, via `awebai/aw` | `aw-v*` tag history |
| aweb | channel plugin | npm `@awebai/claude-channel` | `channel/package.json` |
| aweb | pi extension | npm `@awebai/pi` | `pi-extension/package.json` |
| aweb | skills | npm `@awebai/claude-skills` + ZIPs on `skills-v*` GitHub Release | `packages/claude-skills/package.json` |
| aweb | a2a-gateway image | `ghcr.io/awebai/a2a-gateway` | equals server version |
| aweb | awid.ai site | Render static, branch `deploy-awid-landing` | n/a |
| AC | product image | `ghcr.io/awebai/ac` | `backend/pyproject.toml` |
| AC | production deploy | Render `aweb-cloud`, by image digest | the image |
| AC | aweb.ai site | Render static, branch `deploy-landing` | n/a |

The seven aw npm packages: `@awebai/aw` and `@awebai/aw-{linux,darwin,windows}-{x64,arm64}` (D2).

Non-artifacts (nothing here builds or publishes them): `channel-core`, the five `skills/aweb-*` sources,
and server source in the AWID image (bundled inputs); `packages/codex-plugin`, `naapp/*`, `naapp-lib`,
`packages/hermes-aweb-platform`, `resource-packs/`, `oats/`, `test-vectors/`. The marketplace pointer and
AC pin/lock are publication effects. Sites deploy by branch push, invoked by continue, outside the ordering.

## The static DAG (all ten audited edges)

Ordering (O), same-commit bundle (S), equality (E), independent (I):

1. O: PyPI `awid-service` before PyPI `aweb` (dependency floor).
2. O: npm serves `@awebai/aw` + platform packages (published by `awebai/aw`) before `@awebai/pi`
   when pi's floor moves; the aw step completes when the registry serves it, not at sync time.
3. O: channel and skills publication before the marketplace pointer advance.
4. O: registries serve all intended aweb/AWID versions before the derived AC pin/lock commit and
   AC gate (AC installs from PyPI).
5. O: AC image push before deploy; deploy before digest+health verify.
6. S: `channel-core` into channel and pi.
7. S: the five `skills/aweb-*` sources into pi, claude-skills, and the ZIPs.
8. S: server source into the AWID image.
9. E: a2a-gateway version equals server version (checked at set computation).
10. I: both sites, via branch push, independent of the artifact train.

External repos `awebai/aw` and `awebai/claude-plugins`: dispatch-and-verify only (U1, U2).

## The two commands

Both run from the aweb repository root; the scripts resolve and validate the sibling AC checkout.
Exact invocations: `PURPOSE="..." COMPAT_BREAK="none" make release-prepare` (or the one-line intentional
break — the only judgment the agent supplies), then after the go exactly `make release-continue`.

### `make release-prepare` (before the go)

The script, no prompts:

1. Fetches; selects the exact aweb and AC `main` commits (tips unless `AWEB_SHA=`/`AC_SHA=` name
   older commits on `main`); refuses dirty trees or unpushed selections, printing the fix. An
   older selection is captured from a detached temporary worktree at that exact commit; if a
   crash leaves its registration behind, `git worktree prune` in the checkout recovers it.
2. Computes the artifact set: a component moves iff its manifest version is not in its registry (aw: next
   tag-history version; a2a-gateway: server version absent from GHCR); prints the set and versions.
3. Runs the aweb gate once in clean Docker: builds every moving artifact release-shaped (wheels,
   npm packs, OCI images) and runs the mapped suite inventory (see Migration). One extra run
   only for one last-released/new mixed-version compatibility pairing.
4. Records the reviewed AC base SHA, the intended public dependency versions, and the only
   permitted derived files: `backend/pyproject.toml` dependency floors (if not already intended)
   and `backend/uv.lock`.
5. Generates and prints the release card.

Failure stops with the failing step, log path, and next command (fix on `main`, rerun prepare); nothing published, `release` unmoved.

### The release card

Script-generated, answering only: dependency closure (exact aweb `main` commit and exact AC base
SHA, artifacts and versions, in DAG order); customer compatibility with the explicit known break
or "none"; tests/e2e state (suites, SHA, result); purpose; the inferred deployment set —
production iff the AC image moves, each site iff it moves — plus, while live state requires it,
the pending one-time production correction (C1). The final AC SHA is stated as pending — a
dependency-only derived commit created, verified, and gated automatically before AC publication;
the go cannot waive it. Juan replies with one go.

Prepare writes the displayed card and gate references to one fixed, git-local, untracked card
file. Continue takes no arguments: it reads only that file and rejects any material mismatch.
The file is transient: reused for idempotent retry until continue reaches DONE, then consumed
and removed; a missing, changed, or consumed card means a fresh prepare/card/go. It carries no
release ID and is not a manifest protocol, receipt, audit store, or cross-machine mechanism;
workflow, registry, and provider records remain the audit trail.

### `make release-continue` (after the go)

Idempotent; rerunnable until it prints DONE. Steps:

1. Advance aweb `release` fast-forward to the prepared SHA.
2. Dispatch and monitor the thin publication workflows for the moving set, in DAG order: PyPI
   awid-service, PyPI aweb, AWID image, aw sync to `awebai/aw`, npm channel/pi/skills + ZIPs,
   a2a-gateway image. Each rebuilds from the exact `release` SHA, publishes, pushes its tag, and
   cheaply verifies (exact version served, incl. aw's npm platform packages; installable; digest resolves).
3. Advance the marketplace pointer to the published channel/skills versions.
4. Poll public registries until every intended aweb/AWID version is served (bounded wait, clear
   still-waiting message). Then, requiring AC `main` still at the recorded base SHA, mechanically derive
   the dependency-only commit: bump the recorded floors, regenerate `backend/uv.lock`, assert the diff
   touches only the declared files and versions, advance AC `main` to it, print its final SHA. The commit
   is code-free and independently inspectable. A moved base, unexpected file/diff, version mismatch, or
   need for source change stops the train and invalidates the card (fresh prepare/card/go); no third
   command, prompt, or new go.
5. Run the AC gate once in clean Docker at the derived commit (`make release-ready` content; the
   image installs the published wheels).
6. Advance AC `release` fast-forward to the derived commit; dispatch the thin AC image workflow
   (build from the `release` SHA, push `ghcr.io/awebai/ac`, emit the immutable digest).
7. If the AC image moved, production deployment is included: on the first release, once the exact
   AC digest exists, perform the card's pending one-time correction — disable registry-push
   auto-deploy and configure/deploy the known Render `aweb-cloud` service to that exact digest;
   on later releases fail closed if those standing properties have regressed. Apply pending
   migrations via the scripted migration step; deploy the exact digest; verify standing
   configuration, provider-reported running digest, and health. No extra prompt or approval.
8. Deploy any moving sites via their branch-push targets. Print DONE with versions, digests, and run URLs.

Stop/retry: exact-match registry items are skipped; a conflict (same version, different or un-adoptable
state) stops, named; transient mechanical failures retry the failed job only; tests never rerun. A rerun
with unchanged commits, versions, bytes, compatibility, and deployment intent reuses the same go; any
material change needs a new prepare, card, and go. Every stop names its state and the resume command
(rerun continue). The train stops before AC `release` moves if derivation, the AC gate, publication, or
deploy verify fails.

## Pointers: prepared on `main` vs moved during publication

On `main` before the go: version bumps and the reviewed AC base commit — source that gates
builds. During publication, by continue: `release` branches, version tags, the marketplace
pointer, site branches, and the derived AC pin/lock commit — state that advertises or consumes
published artifacts, true only after publication. `release-pin.toml` is deleted with every
consumer rewritten (F1/N1, see Migration); AC release authority becomes the dependency floors,
`backend/uv.lock`'s exact public versions/URLs/hashes, and the final AC SHA plus
provider/registry records.

## Production configuration (F2/C1)

No production change occurs during implementation or rehearsal. While the live state requires the
one-time correction (today: mutable `latest` tag, auto-deploy enabled), the card shows it as pending;
the first post-go `release-continue` performs it once the exact AC digest exists (continue step 7), and
subsequent releases fail closed if the standing properties — explicit immutable digest, auto-deploy
disabled — have regressed. The known service only, no provider-account discovery framework. Rollback
deploys a previous digest the same way.

## GitHub outage (F3)

No runnerless system is maintained. If GitHub is unavailable, the normal release stops. Under
an explicit human risk override, an operator may invoke the kept per-artifact exact-publish
primitives (`scripts/npm-exact-publish.sh`, `pypi-exact-publish.sh`, `oci-exact-publish.sh`)
against locally built, locally gated outputs; when GitHub returns, bookkeeping resumes — tags,
release assets, the `release` branch, and the marketplace pointer advance by exact-match
adoption. Not a maintained lane, completeness guarantee, third command, or framework.

## Migration: keep, replace, delete

One mechanism remains; cleanup lands in the same reviewed change set.

Keep (aweb): the suites and infra (`make test` content, cli e2e, federation e2e, channel
integration, locked suites, freshness, audits, `docker-compose.e2e*.yml`); version guards
(`check-server-version-bump.sh`, `cli-release-version.sh`); copy/provenance guards; the three
exact-publish scripts + tests; `scripts/e2e/test_pointer_adapter_ac_pin.py` and
`test_pointer_adapter_marketplace.py` (retargeted, driver protocol removed); all current PR checks.

Replace (aweb): `pypi-release.yml`, `npm-release.yml`, `awid-image-release.yml` (trigger from
`release`; drop stage/continuation provenance; keep exact-match publish + cheap verify);
`aw-release.yml`, `a2a-gateway-release.yml` (trigger from `release`; no tag-triggered
publication remains); `library-ci.yml`, `federation-e2e.yml`, `server-ci.yml`, `a2a-copy-guardrails.yml`,
and `cli-e2e.yml` lose their `push: main` triggers, keeping PR checks; both pointer-adapter scripts (become
continue steps); `make release-awid-site` (invoked by continue); `.claude/skills/release`,
`deploy-awid-site`, `cross-repo-change`, and `docs/contributing.md` release sections
(rewritten).

Delete (aweb): `scripts/release_driver.py`; `release/` (graph, measurements); `.release-runs/`;
`.github/workflows/release-anchor.yml`; `scripts/release_receipt_archive.py`; skew harnesses
`release_skew_harnesses.py`, `release_skew_cli_server.py`, `release_channel_pi_skew.py`,
`release_federation_skew.py`, `release_persisted_state_skew.py` and `measure-release-*` targets;
under `scripts/e2e/`, exactly the 12 driver/skew tests `test_release_adapter.py`,
`test_release_adopted_preplan.py`, `test_release_channel_pi_skew.py`, `test_release_driver.py`,
`test_release_driver_cli.py`, `test_release_federation_skew.py`, `test_release_persisted_state_skew.py`,
`test_release_receipt_archive.py`, `test_release_receipt_process.py`,
`test_release_repository_measurement.py`, `test_release_runnerless.py`, `test_release_skew_cli_server.py`,
plus the skew-cell helpers `test_cli_server_skew_shell.py`, `run_cli_server_skew_cell.sh`,
`mark_read_skew_control.py`; `test_release_gate_contract.py` and `test_ship_ci_contract.py` (rewritten
with their workflows or deleted with them); mechanical check: 12 deleted + 2 rewrite-or-delete + 2 kept
pointer-adapter tests = all 16 matching files; the Make targets `release-plan`, `release-run`,
`release-receipt`, `cli-server-skew-cell`, `test-release-adopted-preplan`, `test-release-channel-pi-skew`,
`test-release-driver`, `test-release-federation-skew`, `test-release-persisted-state-skew`,
`test-release-receipt-archive`, `test-release-receipt-process`, `test-release-repository-measurement`,
`test-release-runnerless`, `test-release-skew-cli-server`; the hosted-stage gate targets
`release-server-gate`, `release-awid-pypi-gate`, `release-awid-image-gate`, deleted after any unique
correctness checks move into the local Docker gate; `ship.yml` and the `ship*`/`check-ship-*` targets
with `run-ship-suites.sh`/`ship-env.sh`; the per-component `release-*-{check,tag,push}` Makefile lane;
`check-release-tag-monotonic.sh` + self-test (callerless); `docs/runnerless-release.md`;
`docs/setup-surface-release-gates.md` (fold still-live checks into the gate).

Suite mapping (F4): before `ship.yml` and its wrappers are deleted, every unique artifact-relevant
suite they run is mapped into the local Docker gate, and that gate passes green from a clean
checkout — in the same change set. The ship gate's currently red suites (audit F4) are fixed, not
dropped. A duplicate is removed only with proof the survivor covers it; an irrelevant suite only with
evidence it covers no released artifact. Failures are never masked, skipped, grandfathered, or
converted to warnings.

AC — keep: `make release-ready` content as the AC gate; migration manifest + verifiers;
two-service and journey suites; site deploy targets; `prod-migrate-direct` as the scripted
migration step. Replace: `aweb-cloud-ci-cd.yml` (trigger from `release`; keep thin build/push
checks; emit digest); `ship`/`ship-tag`/`release`/`deploy` targets (become the two commands);
the manual Render procedure (scripted digest deploy + verify); `.claude/skills/ship` and the ops
release SOP. Delete (F1/N1): the `Dockerfile.release` git-source overlay, its
`aweb_server`/`aweb_awid` build contexts and CI aweb checkout, and `release-pin.toml` itself. Every
consumer of the obsolete git-source authority is rewritten to the public-package model in the same
change — code `scripts/verify_docs_contract.py`, `scripts/check_release_model.py`,
`backend/scripts/migration_manifest.py`; test `backend/tests/test_docs_contract.py` + fixtures;
config `.github/workflows/aweb-cloud-ci-cd.yml`, `.gitignore`; docs `docs/README.md`, `docs/sot.md`,
`release/README.md`, `docs/publication-sources.json`; published mirrors
`site/content/docs/hosted-service.md`, `site/static/docs/hosted-service.md`; agent docs
`agents/souls/operations/legacy.md`,
`agents/souls/operations/.agents/skills/sop-release-execution-chain/SKILL.md` — 14 tracked files,
found by repository-wide `rg --hidden`. On the aweb side, `scripts/pointer-adapter-ac-pin.py`, its
test, and `.claude/skills/release` are retargeted to the derived public-dependency commit. No
ceremonial git SHA survives; the AC clean-Docker gate must be green with the file absent
(`check_release_overlay.py`'s no-editable check is kept).

Audit discrepancies, each addressed:

| # | Disposition |
|---|---|
| D1 | a2a-gateway joins the release-branch set; its tag path dies |
| D2 | aw npm platform packages + `aweb-a2a-gw` declared in the artifact table; registry-verified in continue step 2 |
| D3 | the ZIPs are a declared skills output |
| D4 | dead monotonic guard deleted; per-surface guards stay |
| D5 | graph `sites` lane dies with the graph; the Make target survives as a continue step |
| D6 | `awid-release.yml` reference dies with its Makefile lane |
| D7 | coordinator memory naming nonexistent workflows is corrected |
| D8 | `ghcr.io/awebai/aweb-cloud` refs (`Makefile` `PROD_IMAGE`, `OPERATIONS.md`, `docker-compose.prod.yml`) become `ghcr.io/awebai/ac` |
| D9 | dangling "Cloud Deploy Image" reference removed |
| D10 | `use-aweb-pypi` rewritten for the wheels-only model |
| D11 | committed `.claude-plugin/plugin.json` == `package.json` version equality asserted by the prepare gate |
| D12 | tags become publication outputs only; `contributing.md` tag-push narrative rewritten |
| D13 | `ship.yml` deleted per the F4 mapping above |

Audit uncertainties as bounded verification criteria:

| # | Verification |
|---|---|
| U1 | before first aw release: read the `awebai/aw` workflow; confirm its trigger and that it publishes the Release + all 7 npm packages |
| U2 | before the first release moving channel/skills: read the live `marketplace.json`; confirm the adapter's expected shape |
| U3 | resolved 2026-08-12 by coordinator read-only Render reads: both static sites had been bound to `main`; the deploy branches were restored at the exact served commits and both services repointed (`deploy-landing`, `deploy-awid-landing`), so the site rows describe live state. First-release readiness re-verifies the branch trigger fires, since neither service has deployed from a push since the repoint |
| U4 | query GHCR for `awebai/aweb-cloud`; delete or record-absent the stale namespace |
| U5 | verify `ghcr.io/awebai/ac` tags/digests with one authenticated read; thereafter the workflow-emitted digest is authoritative |
| U6 | ship.yml's library/blueprint pins die with it; confirm the cli-e2e PR workflow's checkouts remain current |

## Residue check

Implementation is complete only when, in both repositories: repository-wide hidden-inclusive
searches (`rg --hidden`) for `release_driver`, `components.toml`, `release-anchor`, `runnerless`,
`release-plan`, `release-run`, `release-receipt`, `ship.yml`, `ship-tag`, `stage-only`,
`publish-continuation`, `manifest-id`, `release-pin`, `test-release-`, `cli-server-skew-cell`,
`release-server-gate`, `release-awid-pypi-gate`, `release-awid-image-gate`, and the deleted
doc/skill paths return only this document and history; no Make target invokes a deleted file;
both Makefiles and `make help` expose no deleted target; no workflow can publish or deploy except
the `release`-triggered ones defined here; every tag-triggered publication path is gone; no kept
workflow triggers on `main` pushes; obsolete tests and fixtures are gone with their code; the
continue script implements the C1 first-release production correction (no production change
before the first go); the AC gate is green with `release-pin.toml` absent; and all surviving
docs describe the local Docker gate, thin GitHub publication, the staged train, and one global go.
