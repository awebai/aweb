# Release process

`make release` is the release process for aweb and aweb Cloud (AC). It has no
prepare/continue split, release card, prompt, or release-time compatibility
question. If the reviewed source declares valid versions and both clean-Docker
gates pass, the command publishes and, when AC changed, deploys production.

Run it from a clean aweb checkout at `origin/main`, with a clean AC checkout:

```sh
make release AC_ROOT=/path/to/ac
```

The command is safe to rerun after a process, network, workflow, or credential
failure. A rerun discovers the unfinished intent from Git and reconciles it; it
does not choose new commits or versions.

## Authority

- Reviewed manifests declare versions. A changed manifest is release content;
  major and minor releases do not need a second release-time declaration.
- The `aw` CLI has no manifest. Its next patch comes from `aw-v*` history.
- Source tags identify the commit that produced an artifact.
- Public registries and exact-publish verification establish that the expected
  bytes are served.
- `backend/pyproject.toml` and `backend/uv.lock` together declare the complete
  aweb dependency set inside AC. The release never filters this check by what
  happened to publish in the current process.
- AC deploys by immutable image digest, never by a mutable tag.

## Artifacts

| Source | Output | Version |
|---|---|---|
| `server/` | PyPI `aweb` | `server/pyproject.toml` |
| `awid/` | PyPI `awid-service` | `awid/pyproject.toml` |
| `awid/` + `server/` | `ghcr.io/awebai/awid` | `awid/pyproject.toml` |
| `cli/go/` | GitHub release, seven `@awebai/aw*` npm packages | next `aw-v*` patch |
| `channel/` + `channel-core/` | npm `@awebai/claude-channel` | `channel/package.json` |
| `pi-extension/` + bundled sources | npm `@awebai/pi` | `pi-extension/package.json` |
| `packages/claude-skills/` + `skills/` | npm package and release ZIPs | package manifest |
| `cli/go/` + server version | `ghcr.io/awebai/a2a-gateway` | server version |
| AC application | `ghcr.io/awebai/ac` and Render production | `backend/pyproject.toml` |

Static sites are deliberately independent. Their deploy targets are not part of
an application/artifact release.

## What one run does

1. Fetch both repositories and reject dirty checkouts.
2. If an unfinished intent exists, use it. Otherwise select the two exact
   `origin/main` commits, compare artifact-owned paths with their newest source
   tags, validate declared versions, and run the complete aweb clean-Docker gate.
3. Write the same annotated `release-intent-*` tag in both repositories. Its
   canonical JSON binds the aweb SHA, AC base SHA, every desired version, and
   the exact set of artifacts that must publish. This is automatic crash state,
   not an operator document or approval surface.
4. Fast-forward aweb's `release` branch. Path-scoped workflows build the exact
   commit, publish or adopt exact bytes, verify the public result, then create
   source tags. The command waits for every expected workflow and verifies the
   complete desired public aweb set before continuing.
5. Update the marketplace pointer to the public channel and skills versions.
6. If AC's source or complete dependency state differs, mechanically update
   both dependency floors, regenerate `backend/uv.lock`, and commit only those
   two files. Re-check the complete desired dependency set, then run AC's full
   clean-Docker gate at that exact commit.
7. Fast-forward AC's `release` branch. Its thin workflow builds and verifies the
   exact image and reports the immutable digest.
8. Immediately before production, check the complete dependency floor and lock
   again. Run migrations (pgdbm serializes concurrent runners with advisory
   locks), converge Render to auto-deploy disabled and the exact digest, and
   verify provider state and health at the expected AC commit.
9. Write matching `release-done-*` tags in both repositories.

If AC did not change, steps 6–8 are skipped. An aweb-only release does not mint
an AC version or redeploy an unchanged application.

## Failure and retry rules

- Before the intent tags, failure has made no publication decision; fix source
  on `main` and rerun.
- After the intent tags, the intent is authoritative until done. Rerun the same
  command. Exact matches are adopted and completed workflows are reused.
- A public version containing different bytes, a conflicting tag, a non-fast-
  forward pointer, a changed AC base before derivation, an incomplete lock, or
  a failed gate stops the run. Nothing turns those conditions into success.
- There is no “resume” command and no editable state file.
- Tests do not justify a content mismatch. Publication workflows compare or
  verify the built output; AC's dependency content is checked before build and
  again before deploy.

## Burned artifact

`ghcr.io/awebai/ac:0.7.15`, digest
`sha256:52f7b45bf53729b80dc7cd233a14b63e3331eccdc9883427ed1ac9c866063779`,
must never be deployed. It was built from commit `22ab8bbe`, whose lock contains
`aweb 1.27.1` and `awid-service 0.5.15`, although the release had published
`aweb 1.27.2` and `awid-service 0.5.17`. The version is permanently spent.

The replacement process prevents this class of failure structurally: the full
desired dependency map is the input to both derivation and verification, and AC
cannot build or deploy until its floor and lock exactly match that map.

## Kept low-level mechanisms

The large orchestration stack was deleted. The remaining release-specific code
keeps only boundaries that independently prevent corruption:

- clean-Docker aweb and AC gates;
- exact npm, PyPI, and OCI publication/adoption helpers;
- release-tag helpers;
- the marketplace pointer updater; and
- the single reconciler in `scripts/release.py`.

If GitHub is unavailable, the normal release stops. Direct use of low-level
publish helpers is an emergency operation requiring an explicit human decision;
it is not a second maintained release path.
