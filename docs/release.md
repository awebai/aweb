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

Manifest-backed tags must equal the version in their package manifest. A tag
that publishes two packages (`aweb-naapp-v`) requires both manifests at the tag
version, and `aweb-naapp-testing` requires exactly that `aweb-naapp`. CLI and
A2A gateway versions are explicit in their tags.

## Release candidates and the Cloud pair

Python lanes also accept strict `X.Y.ZrcN` versions, with `N >= 1`:
`server-v1.27.34rc1`, `awid-service-v0.5.32rc1`, and
`aweb-naapp-v0.4.1rc1`, for example. The manifest versions, including
`aweb-naapp-testing`, must equal the tag. The aw spelling is SemVer:
`aw-v1.36.48-rc.1`. Other artifact lanes continue to accept final versions only.

The coordinator publishes these RCs first. The Cloud candidate pins the exact
RC versions and must pass its ordinary pin gate against real services before
OSS final publication and Cloud deployment. Python RCs publish to PyPI. Every
aw RC npm package publishes with `--tag next`; final packages use `latest`.
The downstream `awebai/aw` workflow accepts `v*`, uses the synced
`npm/publish.sh`, and GoReleaser's `release.prerelease: auto` marks an RC GitHub
release as a prerelease. Its workflow needs no separate RC syntax change.
Runnerless npm publication remains available without GitHub; hosted binary
assets remain resumable.

Before final tagging, `release_candidate.py` selects the highest numbered
existing RC tag for the same artifact and base version. Its commit must be an
ancestor of the final commit. The complete RC-to-final **tree** diff may only
promote manifest versions and exact dependency pins to the same final base.
A pin may change only when its target package's manifest is promoted in that
same tree. Parsed extras, markers, scripts and other metadata remain equal.
Existing uv/npm lock records may promote those same versions; artifact URLs,
hashes, sizes, integrity and upload times may change only for promoted records.
Lock records may not be added or removed. File additions, deletions, renames,
mode changes and source changes refuse. Commit release notes before RC1:
docs and CHANGELOG changes after the selected RC also refuse.

The same check runs in the tag publisher, including runnerless publication.
It proves source identity plus version promotion, **not qualification**.
The coordinator must separately hold the Cloud train's green receipt for the
exact selected RC before final tagging. A final with no existing RC retains
the prior candidate-gate behavior. Keep RC tags in the fetched local tag
history when preparing or publishing a final; tags are immutable.

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
resources and records each passing stage (checks, unit, artifacts, integration)
in one host ledger, `~/.cache/aweb-oss/candidate-gate-ledger.tsv`. It runs only
missing stages; a fully passed tree returns without building. Only after all
stages pass does it create the requested annotated tags locally on the exact tested
SHA.

`make candidate-gate`, direct `scripts/candidate-docker-gate.sh` calls and the
release command use that same ledger. The key includes the source tree,
effective CLI/A2A versions, external Library/blueprint revisions, and non-default
resource settings. Commit metadata, stage selection and log paths do not create
another key. `AWEB_GATE_LEDGER` and `AWEB_GATE_LOG_DIR` relocate the ledger and
retained logs; all callers must share them.

For focused pre-landing checks, use `AWEB_CANDIDATE_STAGES='checks unit' make
candidate-gate`. Release candidates always require all four stages, even if that
environment variable is set. Passes are reused across callers with equal inputs.
A recorded failure blocks every stage for those inputs: fix the code and gate
the changed tree. For infrastructure failures only, the coordinator removes the
failed ledger line and supplies `GATE_RERUN_REASON='<reason>'`; the next recorded
result retains that reason. Cleanup failures also block reuse.

`main` may move while the gate runs. The tested SHA and its local tags do not.

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
`host-recovery.json`. On macOS, cleanup passes only if both `kern.num_files`
and Docker VM total `lsof` rows return to at most their baseline plus 5,000.
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
