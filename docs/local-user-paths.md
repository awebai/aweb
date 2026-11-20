# Local user-path feedback

From a clean committed checkout, run:

```sh
make test-user-paths-local
```

The target resolves the current Docker context (or explicit `DOCKER_CONTEXT` /
`DOCKER_HOST`) and pins its local Unix endpoint for every operation. It runs the
existing candidate disk guard before preparation and again immediately before
**each** lane, using that same pinned endpoint. A refusal retains `preflight.log`,
prints the current and remaining lanes as NOT_RUN, and starts no further stack.
A remote Docker endpoint refuses. A disk refusal names the prune and fstrim
recovery steps; the target never prunes automatically.

Preparation uses the committed source archive and the existing
`candidate-gate/Dockerfile`. The first run builds a runtime, including its Linux
CLI with the selected commit stamp. Later runs can reuse the image for that same
commit and tree. `USER_PATHS_RUNTIME_IMAGE` selects an already prepared image;
wrong-source or missing labels refuse. Unset the override to let the target
build its own image. PostgreSQL 17 and Redis 7 are pulled only when absent.
The Dockerfile's locked dependency installation and the registry/release-tag
lookups need network access during preparation.

The artifact owner freezes exact npm metadata for **1.36.58** and **1.36.40**.
Each stack then verifies the wrapper/platform SHA512, exact package/version and
source stamp through the normal released-client fetcher. It never resolves
`latest`. The Linux candidate exported from the prepared image is used for the
forward/reverse invocation; no host-platform binary is substituted.

Three sequential invocations run with separate projects and evidence:

1. Head and released **1.36.58**, each using its own client for bootstrap and cases.
2. Head and older **1.36.40**, including the older client's supported bootstrap.
3. Candidate **forward/reverse** messaging using the source-stamped Linux binary.

Each stack owns an internal network, PostgreSQL on tmpfs, Redis, registry,
servers, and DNS. It publishes no host service ports and does not use the host's
5432 or Redis. On success, failure or interruption, the existing stack owner
removes its containers, networks and volumes and checks their absence. The
wrapper waits for this cleanup on INT/TERM and stops remaining lanes after an
interruption; an ordinary failed lane is recorded while the other independent
lanes still run. The temporary stopped binary-export container is removed too.
Prepared images and retained evidence remain for reuse and diagnosis.

The command prints its evidence directory and one summary line per invocation.
Each directory contains `lane.log`, the native exit in `exit.json`, and `stack/`
with the original source, artifact, case, timing and cleanup evidence. The
outer directory retains the image/source inputs and candidate binary hash.
It defaults to `/private/tmp` on macOS; `AWEB_DOCKER_BIND_ROOT` may select another
existing Docker-visible directory. A nonzero preparation or lane result makes
the target fail. An interruption prints the remaining selections as NOT_RUN.

These are local user-path results, not canonical-gate ledger entries. They retain
the stack's existing human-coverage annotation and reviewed released-client
budget. The canonical full gate stays on the gate machines.

Whole-suite invocations share the host-wide [local suite slots](local-suite-slots.md)
with Cloud (default three), held from preparation through cleanup.
