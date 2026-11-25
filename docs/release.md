# Shipping aweb OSS artifacts

`main` remains the reviewed synchronization branch and never publishes by
itself. Each artifact is released by an immutable tag on one exact tested
commit.

| Tag | Published artifact |
|---|---|
| `server-vX.Y.Z` | PyPI `aweb`, and the `ghcr.io/awebai/aweb-server` image |
| `awid-service-vX.Y.Z` | PyPI `awid-service` |
| `awid-vX.Y.Z` | `ghcr.io/awebai/awid` image |
| `aw-vX.Y.Z` | `aw` CLI distributions and npm platform packages |
| `channel-vX.Y.Z` | npm Claude channel; the unpinned marketplace resolves the public package |
| `pi-vX.Y.Z` | npm Pi extension |
| `skills-vX.Y.Z` | npm skills package, unpinned marketplace source, and resumable hosted ZIP assets |
| `a2a-gw-vX.Y.Z` | `ghcr.io/awebai/a2a-gateway` image |

Manifest-backed tags must equal the version in their package manifest. CLI and
A2A gateway versions are explicit in their tags.

The naapp applications and their packages (`aweb-naapp`, the Secrets and Logs
images, the Secrets runner) release from `github.com/awebai/naapp`, not from
this repository: the release tools refuse their tags before any gate runs.

## Approval service SDK check

Before a server release, replace the approval service's temporary development
AWID source pin with a released `awid-service` version that provides
`get_team_certificate_status_fresh`, regenerate its lock and check normal
service startup. The key holder always builds against this checkout's `awid`.

## Release candidate spellings

Python lanes also accept strict `X.Y.ZrcN` versions, with `N >= 1`:
`server-v1.27.34rc1` and `awid-service-v0.5.32rc1`, for example. The
registry image lane, whose version is awid's manifest, uses the same spelling:
`awid-v0.5.40rc2`.
The manifest version must equal the tag. The aw spelling is SemVer:
`aw-v1.36.48-rc.1`. Other artifact lanes continue to accept final versions only.

RCs are optional: a final needs no prior RC. One full gate qualifies the exact
tree that is tagged, and that tree is what publishes. Python RCs publish to
PyPI; server and registry RCs also publish the immutable RC image tag without moving
`latest`. On every image lane only a final published by its own tag push
moves `latest`. A `workflow_dispatch` of the image workflow publishes an
existing tag's image again as a recovery (`--recovery`): it publishes and reads
back the version only, rc or final, and reports `latest unchanged (recovery)`.
Images are published by the tag workflow. A direct `publish_release.py` or
`make release-publish` run without `--recovery` behaves like a tag push and
moves `latest` for a final, with no serialization against workflow runs.
Every
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

Tags are immutable. Run `git fetch --tags` before either entry point.

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
resources and records stage verdicts (checks, user-paths, unit, artifacts,
integration) and their `stage/target` results in one host ledger,
`~/.cache/aweb-oss/candidate-gate-ledger.tsv`. The run's `summary.tsv` has both
row types. Target rows include the duration, log and any failure or skip
reason. A failed target leaves its stage red while the stage's independent
targets continue. Integration skips the OATS and naapp targets if its lane's
CLI build fails, and names that prerequisite in their rows. Other journeys
build their own inputs or use no stage artifact. Only passing stages are
reusable. Each stage is recorded as soon as it passes, so a run killed later
keeps its completed stages. Only after all stages pass does the command create
the requested annotated tags locally on the exact tested SHA.

After static, every pending stage runs at once, each in its own lane: its own
runner, its own workspace volume seeded from the same clean clone, and its own
PostgreSQL and Redis. Lanes share the Docker daemon, the run's resource label
and bind root (mktemp paths only), and the run's builder and its cache. Nothing
prunes the builder while lanes build; cleanup removes it, with its cache, after
the last lane ends. No stage reads what another writes:
integration builds its own CLI in its own workspace, as it does when artifacts
is reused. The first red stage stops the others. A stopped stage is reported
STOPPED and records no stage row; target rows and stage rows already written
stay. The wrapper is the only writer of `summary.tsv`: each lane writes its own
summary, merged when the lane ends.

The gate is sized from its budget, `GATE_CPUS` and `GATE_MEMORY_MIB`, which
default to the Docker engine's CPU count and memory (`scripts/gate_budget.py`).
Every container CPU cap and the server's worker count derive from it. The
budget sizes a run and is not a gate input: it is recorded in the run's
`budget.tsv` and stays out of the ledger key.
The release command puts no deadline on the gate. The machine that runs it
bounds the run and stops it with TERM, which lets the gate clean up and record
its verdict.

Integration includes `make e2e-folio-wakes`, the same real document-change and
browser-wake acceptance script run by Folio CI. Its services share a private
network namespace and publish no host ports. In the candidate it reuses the
gate's bounded builder, scopes its Compose project, images and fixture volume
to that run, and retains its evidence under the integration log directory's
`folio-wakes/`. Standalone runs can select a project with `FOLIO_WAKES_PROJECT`;
they create and remove their own bounded builder when none is supplied.

`make candidate-gate`, direct `scripts/candidate-docker-gate.sh` calls and the
release command use that same ledger. The key includes the source tree,
effective CLI/A2A versions, external Library/blueprint revisions, explicit
per-container resource overrides, and the content of synchronized main's product-table write
ceilings, the only part of main a stage reads. Commit metadata, main's commit,
stage selection and log paths do not create another key. `AWEB_GATE_LEDGER` and `AWEB_GATE_LOG_DIR` relocate the ledger and
retained logs; all callers must share them.

The static stage runs first: the identity and source-of-truth inventories,
vector provenance, the private boundary and the Secrets shard manifest. When it
fails, no later stage starts; they are reported as NOT-RUN and nothing is
recorded for them. The gate checks neither types nor style: pull-request CI
type-checks the naapp packages (`make typecheck-naapp`).

For focused pre-landing checks, use `AWEB_CANDIDATE_STAGES='checks unit' make
candidate-gate`. Release candidates always require all six stages, even if that
environment variable is set. Passes are reused across callers with equal inputs.
A recorded failure blocks every stage for those inputs: fix the code and gate
the changed tree. For infrastructure failures only, the coordinator removes the
failed stage ledger lines and supplies `GATE_RERUN_REASON='<reason>'`; the next recorded
result retains that reason. A refusal lists all failed stages and their retained
logs. Cleanup failures also block reuse. After an interruption, completed stages
are reusable only if the wrapper records successful cleanup. A missing cleanup
verdict is recorded as a cleanup failure. A run killed outright records no
cleanup verdict, so the stages it recorded before the kill stay reusable.

When the budget allows parallel server workers, the Secrets package uses two
whole-module shards on two Postgres and Redis pairs owned by its isolated
runner. The
measured partition is in `candidate-gate/secrets-shards.json`. The static stage
qualifies it by collecting tests without starting services. It reports modules
missing from collection and collected modules missing from the manifest. The
runner compares the ordered shard collections to the unsharded collection under the
same unit selector before it executes either shard. Both shard outcomes and
logs reach the unit stage. A serial budget and the standalone package
target run the complete Secrets unit suite in one process.

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
prunes or restarts shared Docker. The run's own builder is removed, with its
cache, at the end.

Evidence stays in a directory created for the invocation under
`/tmp/aweb-candidate-gate-<SHA>-<run-id>/` by default. A caller with its own
scratch directory may set `AWEB_GATE_RUN_LOG_ROOT` to that existing absolute
directory. Raw logs include `owned-resources.tsv`, host snapshots,
`host-before.json`, `host-after.json`, and
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
and stop. The PyPI lane is the exception: it never builds (see
[PyPI publication](#pypi-publication)). They do not run product suites, move a branch, infer changed
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
never batch this step.

## PyPI publication

PyPI receives the gated files themselves, never a rebuild. For a
`server-vX.Y.Z` or `awid-service-vX.Y.Z` release, the release command:

1. creates the annotated tag at the gated aweb commit. Its message holds one
   line per gated file in `sha256sum` format, the lowercase sha256, two
   spaces and the file's basename: exactly the package's wheel and sdist, so
   `git tag -l --format='%(contents)' <tag> | grep -E '^[0-9a-f]{64}  ' | sha256sum -c`
   checks a local copy;
2. pushes the tag and runs `gh release create <tag> --verify-tag` with exactly
   those two files attached;
3. waits until PyPI serves exactly those files.

Publishing the release starts `.github/workflows/pypi-release.yml`; a tag push
alone publishes nothing to PyPI. The workflow fetches the annotated tag object,
downloads every release asset and runs
`publish_release.py --only pypi --assets <dir> <tag>`. That refuses unless the
tag is annotated, its message lists files, and the assets are exactly those
files with those sha256 digests: a missing file, an extra file or a different
digest refuses before anything is uploaded. It then requires one sdist and one
wheel of the tag's package and version, uploads only the files PyPI does not
yet serve, with the repository's `PYPI_TOKEN` secret, so a rerun after a partial upload
adopts what is there, and reads PyPI back. A file PyPI already serves with
other bytes refuses permanently.

The `aweb` upload first waits up to three minutes for the in-repo
`awid-service` version to be public, so release `awid-service` first and wait
for PyPI to serve it before releasing `aweb`. The PyPI token lives only in
that GitHub secret, never on the operator's machine.

## Runnerless publication

Every registry-backed tag can publish from the operator machine using the same
tag dispatcher:

```sh
make release-publish TAG=channel-v1.2.3
make release-publish TAG=awid-v0.5.19
```

Provide the credential required by the destination:

- npm: `NODE_AUTH_TOKEN` or `NPM_TOKEN`
- GHCR: `GHCR_USERNAME` and `GHCR_TOKEN`

The runnerless path builds from a detached worktree at the local tag and
refuses a same-version byte conflict. PyPI is not runnerless: only the release
workflow uploads, with the repository's PyPI secret, so a runnerless `server-v` uses
`python3 scripts/publish_release.py --only oci <tag>`. `aw-v` can publish all npm platform
packages directly; hosted binary assets remain resumable when GitHub returns.
Skills ZIPs are likewise resumable hosted assets after the npm package is safe.

## Manual npm repairs

Two manually dispatched workflows change npm metadata for a version that is
already published. Neither builds nor publishes, and both use the repository's
`NPM_TOKEN` secret.

- `npm-dist-tag.yml` points a dist-tag other than `latest` at an exact
  published version (inputs: package, tag, version), then prints the package's
  dist-tags. `latest` moves only through `publication.py promote-latest`.
- `npm-deprecate.yml` deprecates an exact published version with the message
  npm shows on install (inputs: package, version, message), then reads the
  deprecation back.

## Repository boundary

This repository never changes or deploys AC. For a paired release, the OSS
finals are tagged from their one green full gate and published. AC then pins
those finals, builds its image once, runs one full gate on that image's digest,
and tags and deploys that same digest.

There are no release-intent tags, done tags, release branches, workflow
monitors, or cross-repository release transactions.

### Candidate journey networks

Candidate Compose services do not publish host ports. The candidate Docker
wrapper adds project-scoped service aliases, creates
run-labelled networks and attaches the runner before `compose up`, `create` or
`run`. Compose adopts these networks using their project/network labels and
unchanged nonexternal definitions; creation options and existing service aliases
are preserved. The wrapper detaches the runner before `compose down`. Service
clients use those names and the service's container port. Both producers and
consumers call `scripts/candidate-network.py hostname PROJECT SERVICE`: it uses
at most 30 readable ASCII characters and a 128-bit SHA-256 prefix of the JSON
project/service pair, followed by `.test`. The first label is at most 63 bytes,
the whole hostname at most 68; truncation, normalization and ambiguous hyphen
joins cannot erase the pair's hash. Container and network resource names are
unchanged. Temporary A2A clients
also join their journey network. Existing federation DNS/TLS aliases remain.
Services using `network_mode: service:aweb` retain that shared namespace and
its signed loopback audience; the overlay adds no separate networks to them.
The local quickstart test's loopback bridge stays inside the runner and forwards
to the direct service endpoints; it does not use a host-published port.
Standalone host journeys retain their existing host endpoint configuration.

Every wrapped Compose command ends with `exec`, so exit statuses and the
caller's timeout/kill target remain the Docker CLI. A failed startup can leave
the runner attached to its network without a running service. Compose removes
the networks on `down` after runner detachment, so sequential journeys release
address pools. Gate cleanup removes any remaining run-labelled networks and
checks for leaks. Compose overlays likewise live under the run-owned bind root and are removed by gate cleanup, including after a CLI timeout. Cleanup
fails if that root survives; the focused tests exercise this check with an
overlay-retention mutation.

The runner pins `docker-compose-plugin` to `5.7.1-1~debian.12~bookworm` and
verifies the installed package against that pin during the image build. The
checks stage runs `ComposeAdoptionTests`: pre-created default/internal network
IDs must stay unchanged, the runner must reach a service alias, and `down` must
remove both networks before fallback cleanup. Keep this guard when upgrading
Compose. Caller-declared external networks are refused before Docker access.

The only candidate publication controls are
`HostPublishedPortTests.test_docker_assigned_published_port_is_reserved_by_its_service`
and `ComposeNetworkTests.test_real_services_start_despite_competing_host_port_and_stay_isolated`.
Docker chooses and holds the actual published binding in both. The first runs
on the Docker host from the exact candidate checkout when checks is pending,
before the bridge runner starts. It requires the original mapping and distinct
HTTP response to survive a competitor's attempt: Linux refuses that attempt;
Desktop may start the competitor with no host mapping. Either outcome must
leave the original response reachable through the host's real loopback socket.
The probe pins a multi-architecture index; its diagnostics and failures remain
in checks evidence. The remaining Docker boundaries run inside the runner.
The latter holds
a competing host port while two intended services start successfully without
publishing, serves distinct responses over their scoped aliases, exercises a
sibling client, and checks that one journey cannot resolve the other's service.
Run its focused proof in an approved Docker slot:

```sh
AWEB_TEST_DOCKER_NETWORK=1 python3 scripts/test_candidate_network.py ComposeAdoptionTests ComposeNetworkTests ComposeExitStatusTests ComposeTimeoutTests NetworkLinkGuardDockerTests -v
```

The diagnostic commits preceding this change demonstrated a possible socket and
journey-container reservation gap. They did not establish the historical
forwarding incident's cause. Those candidate paths no longer allocate host
ports; their failing diagnostics are replaced by the positive network regression
and endpoint controls. Reachability errors report the service, address, network
path and underlying curl error separately from an application health response.

Each gate invocation retains distinct logs even at the same SHA. The ordinary
ledger still serializes/reuses proof for a tree. An explicitly authorized
concurrency proof uses separate `AWEB_GATE_LEDGER` directories for its two runs;
it must not share either ledger or retained artifact directory. Resource labels,
Compose project names, networks, workspaces and logs remain unique per run.

### User-path event evidence

The real channel receiver appends one UTF-8 JSON object followed by a newline
for each event. Journey readers consume only newline-terminated records: an
unfinished trailing record is pending evidence, including when its final UTF-8
character is incomplete. It cannot establish delivery or fail a case merely
because the reader observed an append in progress. A malformed complete record
still fails and identifies the retained log and record to inspect. The existing
delivery deadline and receiver-liveness checks remain in force; an incomplete
record cannot extend the deadline or qualify a missing event. Normal delivery
and failure cleanup use the same record reader.

## Server OCI image

A `server-v*` tag dispatches both the Python and image publishers. The PyPI
workflow selects `--only pypi`; the service image workflow selects `--only oci`,
so each needs only its own registry credentials. The PyPI lane runs on the
published release, not on the tag push, and needs the downloaded release
files (`--assets`). Both selectors still validate the tagged manifest
version before checking out that exact commit.

A server tag publishes `ghcr.io/awebai/aweb-server`, the coordination server,
from `server/Dockerfile` and the repository root. It builds Linux amd64 and
arm64 into one OCI archive, checked before the registry is touched. The exact
OCI helper validates the archive and each platform's version/source labels.
Version tags are immutable: a conflicting digest refuses, an identical one is
adopted, and each published index is read back. The printed `release-index`
receipt carries the repository, digest, source SHA and version. Deployments pin
`ghcr.io/awebai/aweb-server@sha256:...` from that receipt.

`python3 scripts/test_server_image_publish.py` covers dispatch, identity,
immutability, readback and archive handoff without registry writes.
`make test-server-image-build` builds the archive through the same function,
validates it with the exact helper, and runs the packaged imports and server CLI
as the image's non-root user on the daemon's native platform. Runtime probes
have a 120-second bound.
A one-host PASS qualifies only the platform printed in its receipt.

Complete platform qualification requires the same archive, index and source SHA
on native Linux amd64 and native Linux arm64 hosts. On the authorized x86 build
host (Docker buildx, skopeo and build support for both architectures):

```sh
AWEB_SERVER_IMAGE_ARCHIVE_OUT=/evidence/server.oci.tar make test-server-image-build
```

The output path must not already exist. Preserve the archive and its printed
SHA-256/size/index/source receipt. Transfer it to the authorized ARM host and
verify its file hash. From the **same source checkout SHA** on that host (Docker
and skopeo; no build or emulated execution needed):

```sh
AWEB_SERVER_IMAGE_ARCHIVE_IN=/evidence/server.oci.tar make test-server-image-build
```

An input archive must exist: the ARM run never silently rebuilds it. Each host
validates both platforms and their version/source labels before loading its
native variant, and prints the same archive identity with its actual native
platform. The external input/output archive survives test cleanup for transfer
and audit; the operator owns its final removal. Probe containers and loaded
image tags are removed by the test. With neither variable, the archive is
temporary and removed after the one-host run. Input and output are exclusive.

These tests do not publish to a registry. The tag publisher's authenticated
readback establishes registry digest and source identity, not public pullability.

Before the first server image release, the coordinator must arrange package
provisioning and the release identity's access, so authenticated tag listing
succeeds. An unavailable listing remains a refusal; a 403 or 404 is not
permission to assume absence. GHCR's "name unknown" for a repository that does
not exist yet is never taken as absence on its own either: a new repository is
published only by a `workflow_dispatch` whose `first_publication` input names it
(`--first-publication <repository>`), and then only if the listing says exactly
that. A named repository that already lists tags refuses as "not a first
publication"; a tag push never passes the flag.

The coordinator must also arrange public package visibility and verify
anonymous retrieval in an environment with no registry credentials. Read the
immutable version tag, require its index digest to equal the publication receipt,
and fetch both platform manifests, configs and layers by digest. Record that
anonymous-read result alongside the source and digest receipt before declaring
the server image publicly pullable. Authenticated publication success alone does
not complete this acceptance step.
