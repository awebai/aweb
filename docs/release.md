# Shipping aweb OSS artifacts

`main` remains the reviewed synchronization branch and never publishes by
itself. Each artifact is released by an immutable tag on one exact tested
commit.

| Tag | Published artifact |
|---|---|
| `server-vX.Y.Z` | PyPI `aweb` |
| `awid-service-vX.Y.Z` | PyPI `awid-service` |
| `aweb-naapp-vX.Y.Z` | PyPI `aweb-naapp`, the shared naapp toolkit in `naapp-lib/`, then its dev-only test support `aweb-naapp-testing` (`naapp-lib/testing/`) at the same version |
| `awid-vX.Y.Z` | `ghcr.io/awebai/awid` image |
| `aw-vX.Y.Z` | `aw` CLI distributions and npm platform packages |
| `channel-vX.Y.Z` | npm Claude channel; the unpinned marketplace resolves the public package |
| `pi-vX.Y.Z` | npm Pi extension |
| `skills-vX.Y.Z` | npm skills package, unpinned marketplace source, and resumable hosted ZIP assets |
| `a2a-gw-vX.Y.Z` | `ghcr.io/awebai/a2a-gateway` image |
| `secrets-vX.Y.Z` | `ghcr.io/awebai/secrets` image |
| `logs-vX.Y.Z` | `ghcr.io/awebai/logs` image |
| `aweb-secrets-runner-vX.Y.Z` | PyPI `aweb-secrets-values`, then `aweb-secrets-runner`, at the same version |

Manifest-backed tags must equal the version in their package manifest. A tag
that publishes two packages (`aweb-naapp-v`) requires both manifests at the tag
version, and `aweb-naapp-testing` requires exactly that `aweb-naapp`. CLI and
A2A gateway versions are explicit in their tags.

The [customer Secrets/Logs/runner procedure](../naapp/secrets/deploy/RELEASE.md)
uses these same entry points and additionally requires the full Secrets gate.
The runner and values manifests must have equal versions, and the runner must
require exactly that values version. Neither image recipe nor these tag mappings
alone qualifies a customer release or a target platform.

## Release candidates and the Cloud pair

Python lanes also accept strict `X.Y.ZrcN` versions, with `N >= 1`:
`server-v1.27.34rc1`, `awid-service-v0.5.32rc1`, and
`aweb-naapp-v0.4.1rc1`, or `aweb-secrets-runner-v0.1.0rc1`, for example.
The manifest versions, including `aweb-naapp-testing` or the runner's lockstep
values package, must equal the tag. The aw spelling is SemVer:
`aw-v1.36.48-rc.1`. Other artifact lanes continue to accept final versions only.

The coordinator publishes these RCs first. The Cloud candidate pins the exact
RC versions and must pass its ordinary pin gate against real services before
OSS final publication and Cloud deployment. Python RCs publish to PyPI. Every
aw RC npm package publishes with `--tag next`; final packages use `latest`
unless the release explicitly stages the final on `next` as described below.
The downstream `awebai/aw` workflow accepts `v*`, uses the synced
`npm/publish.sh`, and GoReleaser's `release.prerelease: auto` marks an RC GitHub
release as a prerelease. Its workflow needs no separate RC syntax change.
Runnerless npm publication remains available without GitHub; hosted binary
assets remain resumable.

### Stage a final CLI before promoting public installations

When a CLI needs a dependent service upgrade first, publish its final version
on `next`, qualify and deploy the service with that exact final artifact, then
promote the same npm versions to `latest`. Publishing and promotion are separate;
never publish to `latest` and move it back during the deployment window.

Create the normal gated candidate with an explicit staging choice:

```sh
make release-candidate STAGE_AW_FINAL=1 \
  TAGS='server-v1.27.45 awid-service-v0.5.35 aw-v1.36.53'
```

This adds `Npm-Publish-Channel: next` to the annotated **aw tag only**. The
ordinary source identity and whole candidate gate still apply. Both runnerless
`python3 scripts/publish_release.py aw-v1.36.53` and the tag-triggered publisher
read that declaration. The source sync carries it to the distribution tag, so
the wrapper and all six platform packages publish on `next`. Unmarked final
tags still publish on `latest`; RCs still publish on `next`. The lower-level
exact-tar publisher and distribution `npm/publish.sh` also accept
`--staged-final` for explicit final-only publication to `next`.

In GitHub Actions, the distribution publisher first fetches the exact tag from
`origin` again. `actions/checkout` can replace its local annotated tag with the
event's peeled commit even with full history, losing the channel declaration.
This fetch restores the tag object before channel selection; failure stops
publication. Runnerless publication continues to use its local tag or explicit
staging option.

After the dependent service deploys and its ordinary joining path is verified,
the coordinator promotes the existing packages:

```sh
python3 cli/go/npm/publication.py promote-latest --version 1.36.53
```

Before changing any tag, this reads all seven exact published versions,
downloads and verifies their SHA-512 integrity and packed name/version, and
checks that the wrapper pins those same six platform versions. It prints each
verified integrity and SHA-256. It then moves and reads back each `latest` tag,
platforms first and wrapper last. It never compiles, packs or republishes.
An interrupted promotion reports its failure; it does not roll back tags or
invent replacement versions. A later explicit invocation repeats the same
checks and same-version tag assignments.

Before final tagging, `release_candidate.py` selects the highest numbered
existing RC tag for the same artifact and base version. Its commit must be an
ancestor of the final commit. The complete RC-to-final diff is checked for the
package being promoted: `server/`, `awid/`, `naapp-lib/` (including its lockstep
`testing/` package), or `cli/go/` (including all npm platform packages). These
trees include source, manifests, locks and package build configuration. The
shared build commands in `scripts/publish_release.py`, root checkout filters
(`.gitignore`, `.gitattributes`), and the lane's build configuration also count:
Python's root `pyproject.toml`, `uv.toml`, `uv.lock`, `.python-version` and PyPI
workflow; Go's root `go.work`, `go.work.sum`, aw release workflow and shared
`scripts/npm-exact-publish.sh` packing recipe.
Unrelated files elsewhere, including the root Makefile and another package's
source, do not force a new RC of this package.

Within that scope, only manifest versions and exact dependency pins or
lower-bound floors on promoted packages may move to the same final base.
A pin may change only when its target package's manifest is promoted in those
same compared trees; external manifests provide that version evidence without
pulling their source into this package's scope. Parsed extras, markers, scripts
and other metadata remain equal. Existing uv/npm lock records may promote those
same versions; artifact URLs, hashes, sizes, integrity and upload times may
change only for promoted records. Lock records may not be added or removed.
File additions, deletions, renames, mode changes and source changes within the
scope refuse. Commit package-local release notes before RC1; unrelated release
notes outside the package do not block promotion.

The same check runs in the tag publisher, including runnerless publication.
The aw sync workflow calls the read-only `publish_release.py --check-tag`
entry point before it clones, syncs, pushes or tags the downstream repository.
It proves source identity plus version promotion, **not qualification**.
The coordinator must separately hold the Cloud train's green receipt for the
exact selected RC before final tagging. A paired-package final with no
matching RC refuses; there is no implicit exception path. Both candidate
creation and publication need the RC tag history: run `git fetch --tags`
before either entry point. A missing fetch fails closed. Tags are immutable.

## 1. Test the final candidate locally

Choose every artifact tag that this commit should publish, then run one command:

```sh
make release-candidate \
  TAGS='awid-service-v0.5.19 server-v1.35.0 awid-v0.5.19'
```

The command requires a clean commit on `origin/main`. It runs the explicit
product-test list in `scripts/candidate-suite.sh`—all unit, integration,
packaging, image, audit, and E2E journeys—in isolated local Docker. There is no
artifact scoping. The Docker entry point locks the source tree before allocating
resources and records each passing stage (checks, user-paths, unit, artifacts, integration)
in one host ledger, `~/.cache/aweb-oss/candidate-gate-ledger.tsv`. It runs only
missing stages; a fully passed tree returns without building. Only after all
stages pass does it create the requested annotated tags locally on the exact tested
SHA.

Integration includes `make e2e-folio-wakes`, the same real document-change and
browser-wake acceptance script run by Folio CI. Its services share a private
network namespace and publish no host ports. In the candidate it reuses the
gate's bounded builder, scopes its Compose project, images and fixture volume
to that run, and retains its evidence under the integration log directory's
`folio-wakes/`. Standalone runs can select a project with `FOLIO_WAKES_PROJECT`;
they create and remove their own bounded builder when none is supplied.

`make candidate-gate`, direct `scripts/candidate-docker-gate.sh` calls and the
release command use that same ledger. The test-stage key includes the source tree,
effective CLI/A2A versions, external Library/blueprint revisions, and non-default
resource settings. Stage selection and log paths do not create another key.
`AWEB_GATE_LEDGER` and `AWEB_GATE_LOG_DIR` relocate the ledger and retained logs; all callers must share them.

For focused pre-landing checks, use `AWEB_CANDIDATE_STAGES='checks unit' make
candidate-gate`. Release candidates always require all five stages, even if that
environment variable is set. Passes are reused across callers with equal inputs.
A recorded test failure blocks every stage for those tree inputs; an artifact
failure blocks that commit's artifact identity: fix the code and gate
the changed tree. For infrastructure failures only, the coordinator removes the
failed ledger line and supplies `GATE_RERUN_REASON='<reason>'`; the next recorded
result retains that reason. Cleanup failures also block reuse.

`main` may move while the gate runs. The tested SHA and its local tags do not.

Before allocating Docker resources, the gate waits for the critical free-space
floor plus one gate's peak budget on Docker's backing host filesystem. Defaults
are `AWEB_GATE_MIN_FREE_GB=50` and `AWEB_GATE_RESERVE_GB=30`, requiring 80 GiB
free. The reserve covers the measured 20–28 GB peak of the private builder cache,
tool/suite images, workspace and runner; it is separate from the critical floor.
Both settings accept nonnegative integer GiB values, including a smaller reserve
for a deliberately smaller fixture. Before any self-test or Docker test,
`make release-candidate` and `make candidate-gate` check this floor once and
refuse with the measured free space and required floor when it is not met.
They do not spend the ledger self-test's 900-second timeout waiting for disk.
The direct gate retains its minute-by-minute wait; `--check-disk` performs the
one-shot preflight. The ledger fixture clears inherited make control variables
for its nested commands so its pinned fixture versions cannot be overridden.
Both `make release-candidate CLI_VERSION=... STAGE_AW_FINAL=1 TAGS='...'` and
`CLI_VERSION=... STAGE_AW_FINAL=1 make release-candidate TAGS='...'` are supported;
these values still govern the real candidate, not the self-test's ledger key.
This is startup headroom, not a disk quota or a shared admission lock. Concurrent
gates remain possible; their operator must leave capacity for all outstanding
gate budgets before starting another run.

Each gate owns its builder, BuildKit cache, service data, and workspace volume.
The checkout and exact Git input snapshots are copied through the Docker API;
dependency caches stay in Docker storage. Only the Docker socket, run logs, and
small sibling-container fixtures are bind-mounted from the host. No host
checkout or dependency-cache tree is mounted. The wrapper records nested
builders and Compose projects before creation, and cleanup runs on success,
failure, SIGINT, and SIGTERM. It removes only run-owned resources, verifies
absence, and removes the temporary root and buildx configuration. It never
prunes or restarts shared Docker. The suite's existing 10GB prune applies only
to its own builder during the run; that builder is removed at the end.

Evidence stays in `/tmp/aweb-candidate-gate-<SHA>/`: `owned-resources.tsv`, raw
host snapshots, `host-before.json`, `host-after.json`, and
`host-recovery.json`. On macOS, cleanup passes only if Docker VM total `lsof`
rows return to at most their baseline plus 5,000. The host-wide `kern.num_files`
count and its delta are diagnostic evidence only: unrelated sessions on a shared
host can change that count without a gate leak. The VM check observes host-side
file-sharing rows, not guest descriptors inside containers. Retained containers
and their guest resources are covered by the gate's labeled-resource removal
and absence checks.
The measured process must be exactly one Apple `VirtualMachine` or legacy
`hyperkit` process whose open files include Docker's container/group-container
data. The launcher is excluded. Zero, multiple, or incompletely observed
candidates make the sample unavailable; candidate PIDs, commands, matched
Docker paths, and raw observations are retained as identity evidence.
Total rows exclude the header; numeric-FD rows are reported separately and do
not determine acceptance. Missing samples or a changed VM PID cannot count as passing recovery samples.
Other platforms report these macOS-specific measurements as not applicable.
Recovery keeps up to four numbered samples (`host-after-1.json` through
`host-after-4.json`, with their raw snapshots), 15 seconds apart. It stops at
the first passing sample and records its number in `host-recovery.json`;
`host-after.json` mirrors the last sample. Four failures make recovery fail.
The focused macOS control uses an installed `python:3.12-slim` image and an owned
bind mount to hold host files through the production discovery/settle path:
`AWEB_TEST_DOCKER_VM_RECOVERY=1 python3 scripts/test_candidate_cleanup.py`.
It requires failure while files are held and recovery after guest close/unlink
and container removal. Set `AWEB_VM_RECOVERY_EVIDENCE` to an empty directory to
retain its raw snapshots and receipts. This control never pulls images or
restarts shared Docker.
For interruption, signal the gate's process group: a signal sent only to the
Bash PID can wait for its foreground Docker command before running the trap.
A cleanup or recovery failure makes the gate fail even when the suite passes;
an earlier suite failure retains its original exit status.

## 2. Publish the tested tags

Push the tags explicitly, one command at a time:

```sh
git push origin refs/tags/awid-service-v0.5.19
git push origin refs/tags/server-v1.35.0
git push origin refs/tags/awid-v0.5.19
```

Each tag starts only its owning thin publisher. Publishers rebuild or stage the
exact tagged source, publish or adopt exact bytes, verify registry readback,
and stop. They do not run product suites, move a branch, infer changed
artifacts, create another aweb tag, or contact AC.

Npm readback allows **25 minutes** after publishing or adopting exact staged
bytes: registry propagation has taken about 19 minutes, so the window includes
six minutes of margin. Missing metadata, a stale dist-tag, or an unavailable
registry remains uncertain until the deadline; none permits another publish.
A package identity, integrity or tarball mismatch refuses immediately. Success
requires the staged bytes, SHA-512 integrity and intended `next` or `latest` tag.

Both the aw distribution workflow and runnerless aw publisher pack each of
the six platform packages and the wrapper once, publish or adopt those exact
archives, and then verify all seven with one shared 25-minute readback deadline.
npm records no `gitHead` for a published tarball, so both publishers write the
source commit their binaries are stamped with into each package's `gitHead`,
and the readback refuses any of the seven whose registry `gitHead` differs. The verifier lives at
`cli/go/npm/readback.py`; the other npm lanes call it through
`scripts/npm-exact-publish.sh verify-published-bounded`. The aw release workflow
is maintained at `cli/go/.github/workflows/release.yml` and copied into
`awebai/aw` by the existing source sync. Both npm publishing workflows allow
60 minutes for build, publication and readback. A successful publish command
alone is not a successful release.

Publisher subprocesses disable npm's update notifier, including build, pack,
publish and promotion commands. Release registry traffic must not depend on
whether npm's unrelated self-update check is due in the operator's cache.


The Claude marketplace does not duplicate channel or skills versions. Its npm
sources omit `version`, so Claude resolves npm's public `latest`; the packaged
`.claude-plugin/plugin.json` supplies the installed version and the candidate
gate keeps it equal to `package.json`. A successful npm publication is therefore
the complete release action—there is no marketplace-pointer commit or follow-up
command.

GitHub omits tag-push events when more than three tags are pushed together, so
never batch this step. When `awid-service` moves together with `aweb` or
`aweb-naapp`, push each tag separately, `awid-service` first. The `aweb` and
`aweb-naapp` publishers wait for the in-repo AWID version to become public
before publishing their package, and `make check-naapp-lib-package` refuses an
`aweb-naapp` whose `awid-service` floor is newer than the in-repo AWID.

## Runnerless publication

Every registry-backed tag can publish from the operator machine using the same
tag dispatcher:

```sh
make release-publish TAG=server-v1.35.0
make release-publish TAG=channel-v1.2.3
make release-publish TAG=awid-v0.5.19
```

Provide the credential required by the destination:

- PyPI: `UV_PUBLISH_TOKEN`
- npm: `NODE_AUTH_TOKEN` or `NPM_TOKEN`
- GHCR: `GHCR_USERNAME` and `GHCR_TOKEN`

The runnerless path builds from a detached worktree at the local tag and
refuses a same-version byte conflict. `aw-v` can publish all npm platform
packages directly; hosted binary assets remain resumable when GitHub returns.
Skills ZIPs are likewise resumable hosted assets after the npm package is safe.

## Repository boundary

This repository never changes or deploys AC. For a paired release, publish the
relevant OSS RCs first. AC updates its exact dependency lock and runs its
ordinary candidate pin gate. Only after that gate is green does the coordinator
publish the version-only OSS finals and deploy the paired Cloud/Folio release.

There are no release-intent tags, done tags, release branches, workflow
monitors, or cross-repository release transactions.

## Candidate artifact inputs

The artifact stage precedes journeys and integration, including focused stage
selections. It builds the Python wheels and sdists and the npm tarballs (including
all seven CLI packages) at the versions supplied by the candidate's manifests
and CLI input. `CANDIDATE_ARTIFACT_DIR` holds those files, `manifest.json` and
`SHA256SUMS`. The gate retains that directory with its logs and caches it under
its test-stage key plus source commit. The manifest binds that full key, source
commit, effective CLI/A2A versions, lock hashes and the pinned backend constraints
in `scripts/release-build-constraints.txt`. Reuse verifies this binding and hashes,
including after an infrastructure reset removes the ledger row. An identical tree
at another commit reuses checks, user-paths, unit and integration; only artifacts
rebuild, because the CLI stamps the commit. Artifact ledger rows select both key
and commit, while test rows select the tree-based key.

Before accepting a restamp, the artifact stage compares it to the last retained
manifest for that key. Tree, external inputs, file set and non-CLI hashes must be
identical. CLI non-executable files must match except package.json gitHead. For
executables, module path, dependencies with versions/sums, Go version and every
embedded build setting are compared. Only vcs.revision, vcs.time, main.commit and
a main-module pseudo-version derived from that exact revision/time may differ;
both builds must have vcs.modified=false. Under pinned Go 1.26.10, -trimpath omits
ldflags from embedded build info: the manifest therefore records the effective
producer ldflags, compares them except main.commit, and requires that requested
commit string in each executable. This is a mechanical check of the same code
identity and build settings, not a machine-code equality claim. Journeys on
commit A prove the tree's behavior for commit B when this restamp check passes.
It does not silently regenerate a missing or changed wheel behind a green receipt.

For an already-tagged Python version, the gate builds that release tag with the
same toolchain and compares the installed file set, file bytes, requirements,
Python requirement, extras and entry points. ZIP timestamps, RECORD and metadata
long descriptions do not decide this comparison. An unchanged installed package
passes with excluded source differences logged; changed installed code or metadata
requires a coordinated version bump. The package import check additionally runs
at declared in-repository dependency floors so a newer local AWID cannot hide a
missing module in an older allowed release.

The shared wheel installer verifies each input hash, replaces editable installs,
checks installed payload bytes and logs `installed manifest wheel:` with the
package, version and SHA-256. Services repeat this check at startup, and standing
journeys check each live service environment before running the tests. The guard
rejects editable direct URLs and active `.pth` paths/import hooks; only uv's exact
`_virtualenv.pth` bootstrap (`import _virtualenv`) is allowed. This bootstrap is
part of an ordinary uv venv, not a source-package path. Naapp applications install
non-editably as well, so their own source hook cannot mask a dependency.
The normal federation journey uses its existing
exact-wheel mode. Explicit historical/skew wheel inputs retain their selected
released server and constraints. Developer image builds without prepared
candidate artifacts retain their source mode; maintained journeys prepare wheels
before building those images. Materialization creates a per-run temporary named
BuildKit context outside the checkout; it never writes wheels under the source
tree. Callers remove their temporary contexts in EXIT handlers; failed
materialization removes its partial context. Channel integration copies into its
existing parent-owned test directory before the preparation shell exits, and
that directory follows the test's cleanup. Retained manifest artifacts survive
this cleanup. Compose and direct callers pass CANDIDATE_WHEEL_MODE=1 and the verified
CANDIDATE_SOURCE_TREE. The installer checks that tree against the manifest before
installing. Without explicit wheel mode, images refuse a nonempty
`.candidate-artifacts` (apart from `.gitignore`), so stale checkout files cannot
silently override source. Standalone preparation requires a clean checkout.

The maintained callers share these operations:

| Operation | Callers |
|---|---|
| Artifact targets and stage ordering | `candidate-suite.sh`, reached by `candidate-docker-gate.sh`, `make candidate-gate` and `release_candidate.py` / `make release-candidate` |
| Python build and manifest | `_candidate-artifact-server`, standalone `check-naapp-lib-package.py`, and `prepare-release-wheels.sh` |
| Package import checks | `_candidate-artifact-naapp-package` and `make check-naapp-lib-package` |
| npm build operations | Candidate artifact targets and `publish_release.py`; tag workflows invoke that publisher |
| Standing user paths | `make e2e-user-paths` → `e2e-user-paths.sh` → the existing `user_paths_stack.py` |
| OSS and federation journeys | `make test-e2e`, `make test-federation-e2e`, and federation CI's direct script calls |
| Channel integration | `make test-channel-integration` and direct `npm run test:integration` invoke the same test setup |
| A2A gateway journey | `make test-a2a-gateway-e2e` → `e2e-a2a-gateway-docker.sh` |
| CLI/Library stack | `make cli-e2e`, `make -C cli e2e`, CLI CI and direct `e2e-library-stack.sh up` |
| Naapp integration | `make e2e-naapp` and Folio/Library CI's `make e2e`; their `e2e-up` targets prepare the same wheels |
| Folio wakes | `make e2e-folio-wakes` and Folio CI's direct `e2e-folio-wakes.sh` |

CI callers fetch release-tag history and use the same preparation scripts. These
changes retain the existing RC/final promotion policy. Publishing directly from
the retained manifest is a separate change; the current publisher still builds
its publication inputs.
