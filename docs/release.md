# Shipping aweb OSS artifacts

`main` remains the reviewed synchronization branch and never publishes by
itself. Each artifact is released by an immutable tag on one exact tested
commit.

| Tag | Published artifact |
|---|---|
| `server-vX.Y.Z` | PyPI `aweb` |
| `awid-service-vX.Y.Z` | PyPI `awid-service` |
| `awid-vX.Y.Z` | `ghcr.io/awebai/awid` image |
| `aw-vX.Y.Z` | `aw` CLI distributions and npm platform packages |
| `channel-vX.Y.Z` | npm Claude channel; the unpinned marketplace resolves the public package |
| `pi-vX.Y.Z` | npm Pi extension |
| `skills-vX.Y.Z` | npm skills package, unpinned marketplace source, and resumable hosted ZIP assets |
| `a2a-gw-vX.Y.Z` | `ghcr.io/awebai/a2a-gateway` image |

Manifest-backed tags must equal the version in their package manifest. CLI and
A2A gateway versions are explicit in their tags.

## 1. Test the final candidate locally

Choose every artifact tag that this commit should publish, then run one command:

```sh
make release-candidate \
  TAGS='awid-service-v0.5.19 server-v1.35.0 awid-v0.5.19'
```

The command requires a clean commit on `origin/main`. It runs the explicit
product-test list in `scripts/candidate-suite.sh`—all unit, integration,
packaging, image, audit, and E2E journeys—in isolated local Docker. There is no
artifact scoping and no reuse of a previous green result. Only after every test
passes does it create the requested annotated tags locally on the exact tested
SHA.

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
never batch this step. When `awid-service` and `aweb` move together, push both
tags separately. The `aweb`
publisher waits for the exact declared AWID dependency to become public before
publishing its package.

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

This repository never changes or deploys AC. When AC needs a new OSS version,
publish the relevant OSS tags first. AC then updates its exact dependency lock,
runs its own complete Docker candidate gate, and publishes its own `vX.Y.Z` tag.

There are no release-intent tags, done tags, release branches, workflow
monitors, or cross-repository release transactions.
