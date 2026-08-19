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
| `channel-vX.Y.Z` | npm Claude channel |
| `pi-vX.Y.Z` | npm Pi extension |
| `skills-vX.Y.Z` | npm skills package and resumable hosted ZIP assets |
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
