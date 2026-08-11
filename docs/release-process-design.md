# Release process design

Status: proposed replacement design for the universal release driver, covering
the aweb and AC repositories. Normative once approved and integrated by the
coordinator. Until then, `scripts/release_driver.py` and
`release/components.toml` remain the operative release machinery, and nothing
in this document authorizes a release.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY are used as in
RFC 2119. Paths in this repository are written repo-relative in backticks.
Paths in the AC repository (`github.com/awebai/ac`) are written with an `ac:`
prefix, for example `ac:release-pin.toml`; the prefix marks the repository and
is not part of the path.

## 1. Scope

This specification defines the release process for every artifact currently
represented by release tooling in the aweb repository, plus the AC hosted image
and its production deployment. It replaces the release-execution model
implemented by `scripts/release_driver.py` (plan/freeze/receipt/resume,
G1–G5, three authorization types) with a model built around one global release
set, one immutable manifest, and exactly one human authorization per release.

It is a design contract for implementers. It prescribes observable behavior,
invariants, and interfaces between components; it does not prescribe the
internal structure of any single program, and it explicitly rejects a giant new
orchestration program (§16.6).

## 2. Goals

- **One human go per release.** A release — regardless of how many artifacts,
  repositories, or deployment targets it spans — is authorized by exactly one
  human decision, made once, on evidence bound to the exact bytes that ship.
- **Four substantive inputs.** The human decision consumes exactly four product
  questions (§7.2): dependency closure, customer compatibility, test results on
  the exact candidate, and stated purpose. Everything else is mechanical
  integrity the tooling enforces without asking.
- **Test once, ship those bytes.** Each candidate is built once and each
  required test runs once against it; publication promotes the tested bytes,
  never a rebuild.
- **Runner independence.** The process keeps a first-class runnerless lane. No
  release capability may permanently depend on GitHub or GitHub Actions
  (§8.5).
- **Small mechanical parts.** Per-artifact workflows own mechanical jobs; a
  thin cross-repository coordinator composes them. No mechanical job may
  create a human approval point.

## 3. Non-goals

- **Redesigning versioning.** Independent semver per artifact and strict
  monotonicity are retained unchanged (`scripts/cli-release-version.sh` for the
  CLI's tag-history versioning; pyproject/package.json elsewhere).
- **Redesigning migration policy.** Applied migrations remain immutable
  (`docs/aweb-sot.md`, "Migrations"); this design consumes that rule, it does
  not restate or alter it.
- **AC decomposition.** The embedded-OSS architecture of the hosted service
  (OSS `aweb` mounted in-process) is out of scope. `docs/restructuring-sot.md`
  is superseded and generates no work here. This design releases the system as
  it is.
- **Content publication.** The aweb.ai site (`ac:Makefile` `deploy-site`) and
  the AC public-docs snapshot (`ac:docs/publication-sources.json`) are content
  operations owned by AC, not releases; they are out of scope (§17).
- **Library and folio.** Neither repository is represented by current release
  tooling; both are out of scope.

## 4. Terminology

- **Artifact** — one releasable unit with its own version and registry
  identity (for example PyPI `aweb`, npm `@awebai/pi`, GHCR `awebai/ac`).
- **Candidate** — the exact bytes of an artifact built once from a stated
  source SHA by the candidate pipeline, identified by content digest.
- **Candidate pipeline** — the fixed-topology hosted workflow that builds all
  of a repository's candidates from a default-branch SHA and runs the full
  correctness and end-to-end suite against them (§8).
- **Release set** — the ordered set of artifacts selected to ship together,
  drawn from candidates.
- **`release_id`** — the unique identifier of one release attempt. One
  `release_id` names exactly one manifest and at most one go.
- **Manifest** — the immutable release-set document (§6.2). Its canonical
  bytes hash to the **`manifest_digest`**.
- **Go** — the single human authorization, bound to
  (`release_id`, `manifest_digest`) and spent by one execution attempt (§7).
- **Publication** — making a candidate's exact bytes available at its registry
  identity.
- **Promotion** — the act of publishing already-staged, already-tested bytes;
  the opposite of rebuilding.
- **Pointer** — a repository record that advertises a published version to
  consumers (the marketplace pointer in `awebai/claude-plugins`; the AC pin
  `ac:release-pin.toml` plus `ac:backend/uv.lock`). A pointer is stale by
  definition when its source artifact moves.
- **Read-back** — re-reading authoritative registry or deployment state after
  an effect, and comparing it to the manifest.
- **Adoption** — accepting a pre-existing published item as satisfying a
  manifest entry without republishing, permitted only on proven identity and
  payload equality (§11.4).
- **Deployment intent** — the manifest field stating whether and where this
  release deploys (§13).
- **Coordinator (tool)** — the thin cross-repository release-set tool defined
  in §16.6. Distinct from the team-role coordinator; in this document
  "coordinator" unqualified means the tool.

## 5. Current state

### 5.1 Artifact and dependency graph

The operative graph is `release/components.toml`. Artifacts and their
registry identities:

| Artifact | Source | Published at | Tag |
|---|---|---|---|
| `server` | `server/` | PyPI `aweb` | `server-v{v}` |
| `awid-pypi` | `awid/` | PyPI `awid-service` | `awid-service-v{v}` |
| `awid-image` | `awid/` | GHCR `awebai/awid` | `awid-v{v}` |
| `aw` | `cli/go/` | GitHub Releases `awebai/aw` | `aw-v{v}` |
| `channel` | `channel/` | npm `@awebai/claude-channel` | `channel-v{v}` |
| `pi` | `pi-extension/` | npm `@awebai/pi` | `pi-v{v}` |
| `skills` | `packages/claude-skills/` | npm `@awebai/claude-skills` | `skills-v{v}` |
| `sites` | `docs/identity-guide.md`, `docs/trust-model.md`, `awid/site/` | awid.ai (branch deploy) | — |
| AC image | `ac:backend/` + overlaid aweb source | GHCR `awebai/ac` | `v{v}` |

Non-published graph nodes: `channel-core` (bundled into `channel` and `pi`),
`agent-skills` (the five `skills/aweb-*` directories, bundled into `pi` and
`skills`), `server-image-payload` (the server paths copied into
`awid-image`), and the two pointers `marketplace-pointer` and `ac-pin`.

Ordering edges: `awid-pypi` → `server`; `aw` → `pi`;
`channel`/`skills` → `marketplace-pointer` (forced);
`server`/`awid-pypi` → `ac-pin` (forced). The AC image consumes the pin, and
production deployment consumes the AC image, extending the same order across
repositories: `awid-pypi` → `server` → `ac-pin` → AC image → deployment.

Runtime-contract (version-skew) edges: `aw`↔`server`, `channel`↔`server`,
`pi`↔`server`, `server`↔`server` federation, and `server`↔`server`
persisted-state (schema rollout). All are policy `additive-only`.

The AC side today: the hosted image is built by `ac:Dockerfile.release`, which
installs the locked PyPI `aweb` first and then overlays the exact aweb source
commit named by `ac:release-pin.toml` (`git_sha`, authoritative) via BuildKit
build contexts. In CI (`ac:.github/workflows/aweb-cloud-ci-cd.yml`) those
contexts come from a checkout of `awebai/aweb` at the pinned SHA. Locally they
default to sibling-checkout paths (`ac:Makefile`, `AWEB_SERVER_SOURCE ?=
../aweb/server`). `ac:scripts/check_release_model.py` enforces three-way
pin/lock/source agreement and commit identity ("source-version equality cannot
substitute for commit identity"). The image bakes `AC_GIT_SHA` /
`AWEB_GIT_SHA` build provenance, surfaced at `GET /api/v1/release`. Render
deployment and production migrations are manual; the CI publish workflow runs
no tests by design — the gate is local `make release-ready`.

### 5.2 Current machinery being replaced

`scripts/release_driver.py` (~9,850 lines) implements: plan computation from
the graph; a frozen plan artifact ("G4") with drift detection; dispatch-only
stage/publish-continuation/verify-only lanes ("G1",
`.github/workflows/pypi-release.yml`, `npm-release.yml`,
`awid-image-release.yml`, plus `release-anchor.yml` for content-addressed
anchoring); a runtime-support gate ("G5") over the skew edges with a typed
`G5Authorization` deferral bound to content-hashed edge identities; sealed
receipts validated field-exactly; two resume mechanisms (`--resume` from the
anchored staged manifest, and the separate `adopted-preplan-recovery` verb);
three non-substitutable human-authorization types (per-component `Approval`,
runnerless risk record, `G5Authorization`); and a runnerless local lane
(`docs/runnerless-release.md`) with subprocess adapters over
`scripts/npm-exact-publish.sh`, `scripts/pypi-exact-publish.sh`, and
`scripts/oci-exact-publish.sh`. The comprehensive ship gate
(`.github/workflows/ship.yml`) is informational and gates nothing
mechanically. G2 and G3 have no referent in the tree; G1, G4, and G5 are the
labels that exist (§16 disposes of each).

### 5.3 What this design removes

The current model is mechanically strong and humanly expensive. Its costs, all
observed in operation:

- Multiple human authorization records per release, each with its own syntax,
  refusal modes, and content-hash ceremony (`G5_AUTHORIZATION` edge ids;
  `LOCAL_RISK_AUTHORIZATION`; per-component approvals).
- Four of five skew edges are declared-incomplete, so in practice every server
  release requires the G5 deferral ceremony — the exceptional path is the
  normal path, which is how an authorization becomes a formality.
- The driver reads the working tree it runs from, coupling correctness to
  checkout hygiene (stale-sibling and stale-checkout failures).
- Laptop-resident steps (the `ac-pin` lane's `EXTERNAL_CONTEXT` sibling
  checkout) put a cross-repository effect on an operator's machine.
- Resume-under-spent-approval semantics are subtle enough to need two distinct
  mechanisms and a separately authorized continuation class.

## 6. The release set

### 6.1 `release_id`

Every release attempt MUST have a fresh `release_id`, unique across all
attempts forever. The `release_id` MUST be assigned when set selection begins
and MUST appear in every record the attempt produces. A `release_id` MUST
never be reused, including for retries of the same content.

### 6.2 The manifest

The manifest is one document describing everything the go authorizes. It MUST
be serialized canonically; its SHA-256 over those canonical bytes is the
`manifest_digest`. After the go is granted, the manifest MUST NOT change; any
change produces a different `manifest_digest` and therefore requires a new
attempt and a new go (§7.4).

The manifest MUST contain:

- `release_id`.
- **Sources**: the exact aweb source SHA and, when any AC artifact or
  deployment is in the set, the exact AC source SHA. Each MUST be the
  default-branch commit its candidate pipeline ran on (§8.2).
- **Artifacts**: every selected artifact with its version, its registry
  identity, and its complete digest set (every file or layer that will be
  published, each with SHA-256; for images, the manifest-list digest).
  Bundled build inputs (`channel-core`, `agent-skills`,
  `server-image-payload`) are not listed as artifacts; their content is bound
  through the digests of the artifacts that embed them.
- **Dependency edges**: the ordering edges among selected artifacts, including
  forced pointers and, when applicable, the AC image and deployment, in the
  topological order publication will follow.
- **Candidate evidence**: for each repository, the candidate pipeline run ID
  and attempt number, and the per-suite results (§8.4). Evidence MUST be
  bound to the same SHAs and digest sets named above.
- **Compatibility result**: per touched runtime-contract edge, one of
  `compatible`, `breaking`, `could_not_measure`, with the evidence reference
  for each (§10).
- **Purpose**: a non-empty statement of why this release exists.
- **Deployment intent**: `none`, or the deployment target(s) with exact image
  digest, the ordered migration set to be applied, and the irreversibility
  statement (§13, §15).
- **Authority**: `hosted` or `local-runnerless` (§8.5), stating where
  candidate evidence and publication execution live.

The manifest SHOULD contain the delivery obligations of the selected artifacts
(plugin restart, Pi cache refresh — the `delivery_restart` facts from
`release/components.toml`) so the audit record shows what adoption work the
release creates; these are operational follow-ups, not release gates, and MUST
NOT block sealing (§13.3).

### 6.3 Graph source

The dependency and skew edges MUST come from one declared, versioned graph
file (today `release/components.toml`, retained — §16.1). Set selection MUST
refuse an artifact whose required edges are absent from the graph. The graph
file is reviewed code; nothing may inject edges or artifacts at run time.

## 7. The single human go

### 7.1 One go, ever, per attempt

There is exactly one human authorization for the release as a whole. There
MUST NOT be a second human approval point anywhere in the process: not per
repository, not per artifact, not per phase, not for deployment, not in a
workflow environment protection rule, not in a registry setting. Per-artifact
workflows are mechanical jobs (§8, §11); if any of them acquires a manual
approval step, that is a defect against this specification.

The human's single interaction is: read the presented manifest and its four
substantive inputs, and either grant the go or decline. Preparation of the
set, the manifest, and the evidence MAY be done by agents and tooling with no
human involvement.

### 7.2 The four substantive inputs

The go presentation MUST answer exactly these four questions, each derived
from the manifest:

1. **Dependency closure.** Every dependency required by the release set is
   already released (proven by registry read-back at manifest assembly) or is
   included in the same set, ordered before its dependents. This includes the
   cross-repository chain `server` → `ac-pin` → AC image → deployment when
   those are in the set.
2. **Customer compatibility.** For every touched runtime-contract edge, the
   compatibility state is known (§10). A known `breaking` interval MAY be
   deliberately accepted in the go; `could_not_measure` MUST block the go.
3. **Correctness on the exact candidate.** All required correctness tests and
   end-to-end tests passed on the exact candidate bytes (run IDs and digest
   bindings in the manifest). A red or missing suite MUST block the go.
4. **Purpose.** The manifest states why this release exists.

### 7.3 Mechanical integrity is not a fifth input

Exact tested artifacts, immutable identifiers, trusted publication,
authoritative read-back, and non-reusable authorization are mandatory
properties the tooling enforces (§8, §11, §20). They MUST be enforced
mechanically and MUST NOT be presented to the human as questions. If a
mechanical property cannot be established, the attempt is not presentable for
a go at all.

### 7.4 Binding and spending

The go record MUST contain: who granted it, when (UTC), the `release_id`, the
`manifest_digest`, and any deliberately accepted risks in prose (a named
breaking interval per §10.3; runnerless-lane risk per §8.5; irreversible
deployment steps per §15.4). The record MUST be stored in the audit record
(§20) before any outward effect.

A go authorizes exactly one execution attempt of exactly that manifest. The
go is **spent** by starting execution, whether execution completes, fails
partway, or is abandoned. The following each invalidate a go that has not yet
been executed, and require a new attempt with a new `release_id`, manifest,
and go — never a per-repository or per-artifact re-approval:

- any retry of a candidate pipeline (new run or new attempt number);
- a changed source SHA in either repository;
- a changed artifact set, version, or digest;
- a changed compatibility result;
- a changed deployment intent;
- any materially changed evidence (the mechanical definition: any change to
  the manifest bytes, since all evidence is bound through the manifest).

Execution MUST verify, immediately before its first outward effect, that the
manifest's external claims still hold (registry versions it read at assembly,
the pointer repositories' state, the deployment target's current version). If
any drifted, execution MUST refuse without publishing; the go is then spent by
that refused attempt only if an outward effect had begun, otherwise it remains
unspent but bound to a manifest that can no longer execute — either way the
recovery is a new attempt (§12).

## 8. The candidate pipeline

### 8.1 Hosted, per repository

Each repository (aweb, AC) MUST have one candidate pipeline: a hosted CI
workflow that builds every releasable candidate from one source SHA and runs
the full required suite against those exact bytes. The aweb candidate
pipeline subsumes the current comprehensive gate content
(`.github/workflows/ship.yml` journeys) and the artifact staging currently
done by the stage-only lane modes; the AC candidate pipeline is the hosted
equivalent of `ac:Makefile` `release-ready` (release-model checks, migration
gates, backend/frontend suites, two-service e2e, and the cloud user journeys
against the built release image).

### 8.2 Default-branch-only

The candidate pipeline MUST run only against commits on the repository's
default branch. It MUST refuse arbitrary refs. A release set MUST reference
candidates whose SHA is an ancestor-or-equal of the default branch at
selection time. Work that is not on main does not exist for release purposes.

### 8.3 Fixed topology

The workflow topology is fixed in the workflow file and reviewed like code.
The pipeline MUST NOT accept: artifact selectors, test selectors, skip flags,
arbitrary source refs, or command overrides. There MUST be no input whose
value can make an empty or partial suite look releasable. The only permitted
inputs are the implicit trigger (push to default branch) and an idempotent
manual dispatch of the same fixed pipeline on the default-branch head.

Artifact *selection* happens at set-selection time — choosing which already
built and tested candidates ship — never at test time. The pipeline always
builds and tests everything it covers.

### 8.4 Outputs

For each releasable artifact, the pipeline MUST produce the exact candidate
bytes as immutable run artifacts with a recorded digest set, and a
machine-readable result document binding (source SHA, run ID, attempt,
per-suite pass/fail, per-artifact digest sets). These outputs are what the
manifest references; nothing else counts as candidate evidence.

### 8.5 The runnerless lane

A first-class local lane MUST exist and MUST be able to complete build-once,
stage, publish, and read-back with GitHub and GitHub Actions entirely
unavailable; tags and hosted release assets MUST be resumable later as
mechanical follow-ups that need no new go. The lane reuses the exact-publish
scripts (`scripts/npm-exact-publish.sh`, `scripts/pypi-exact-publish.sh`,
`scripts/oci-exact-publish.sh`) and the local stage/publish/observe adapter
protocol of `docs/runnerless-release.md`, which this design retains in
simplified form.

Under the runnerless lane the manifest's `authority` is `local-runnerless`,
candidate evidence comes from locally executed suites recorded with the same
digest bindings, and the go's accepted-risks prose MUST state that hosted
evidence was unavailable and what was accepted instead. This is the explicit,
cheap human risk override for an urgent release or runner outage: it is the
same single go, with the risk stated — not an additional approval, and not a
mechanically impossible path.

## 9. Test-once semantics

Each candidate is built and packaged exactly once (§8.4); publication
promotes those bytes (§11.1). Each required correctness and end-to-end test
runs exactly once against the exact candidate, in the candidate pipeline.

Re-running a suite on the same SHA creates a new run attempt and therefore new
evidence; if a go existed, it is invalidated (§7.4). Reviewers and operators
MUST NOT re-run green suites without a concrete unresolved risk; the process
offers no place where a duplicate green run changes any outcome.

**The one permitted second execution** is the mixed-version compatibility
check (§10.2): when dependency-floor compatibility must be measured, the
relevant journey runs a second time in the mixed-version configuration
(published floor × candidate). This is a different measurement, not a repeat
of a same-version suite, and it is the only sanctioned one.

## 10. Compatibility

### 10.1 States

Every runtime-contract edge touched by the release set MUST carry exactly one
of three states in the manifest:

- `compatible` — the mixed-version check ran on the exact candidate against
  the currently published floor, and passed.
- `breaking` — the check ran and failed, or the change is declared breaking by
  design; the customer-visible breaking interval is known and named.
- `could_not_measure` — the check did not produce a result (harness failure,
  environment failure, missing fixture).

### 10.2 Measurement

Compatibility is measured fresh per release attempt, on the exact candidate,
against the floor read from the authoritative registry at manifest assembly.
The existing skew harnesses are retained as the measurement instruments
(`scripts/release_skew_cli_server.py`, `scripts/release_federation_skew.py`,
`scripts/release_channel_pi_skew.py`,
`scripts/release_persisted_state_skew.py`, routed via
`scripts/release_skew_harnesses.py`), plus AC's installed-`aw` compatibility
journey (`ac:Makefile` `test-cloud-user-journeys-compat`) for the hosted
surface. Standing measurement documents (`release/measurements/`) are no
longer an input to release decisions: each manifest carries its own result
(§16.4).

The persisted-state edge measures schema rollout: a database created by the
published release operated by the candidate, and the published server against
the upgraded schema where rollout is non-atomic. Its result feeds the
deployment irreversibility statement (§15.4).

### 10.3 Blocking rules

- `compatible` — releasable.
- `breaking` — releasable only when the go's accepted-risks prose names the
  edge and the accepted breaking interval. The acceptance lives inside the
  single go; there is no separate deferral record, no edge-hash authorization,
  and no per-edge approval.
- `could_not_measure` — MUST block the go. The customer-impact question is
  unanswered, and an unanswered question cannot be accepted. Recovery is to
  fix the measurement or remove the artifact pairing from the set — not to
  authorize around it. This deliberately deletes the current
  `G5_AUTHORIZATION` deferral: under this design there is no authorization
  that converts an unmeasured edge into a releasable one.

## 11. Publication and promotion

### 11.1 Exact bytes, topological order

Execution publishes the manifest's digest sets — the bytes the candidate
pipeline built and tested — in the manifest's topological order. Publication
MUST be a promotion of staged bytes; any step that rebuilds from source at
publish time is a defect. The existing dispatch-only publish workflows
(`.github/workflows/pypi-release.yml`, `npm-release.yml`,
`awid-image-release.yml`, and the dispatch-only workflow in `awebai/aw`) are
retained as the per-artifact mechanical publish jobs, with their
`publish-continuation` mode consuming the candidate pipeline's staged bytes.

Pointers publish after their sources: the marketplace pointer advertises
exactly the published versions from the manifest; the AC pin commit sets
`ac:release-pin.toml` and `ac:backend/uv.lock` to exactly the published
server/awid versions and SHA. Pointer content comes from the manifest, never
from a command line.

### 11.2 Non-reusable authorization at the mechanical layer

Each publish job MUST require (`release_id`, `manifest_digest`, artifact,
version, digest set) and MUST verify, against the audit record, that a go
binding that manifest exists and that no publication record for
(`release_id`, artifact) already exists. One manifest entry authorizes at
most one publication. A publish job invoked outside a live attempt MUST
refuse.

### 11.3 Read-back

After each publication the executor MUST read authoritative registry state
(registry API, `docker manifest inspect`, git remote for pointer
repositories) and record it. The release fails (§12) unless read-back equals
the manifest: version present, digest set equal, pointer content equal. A
tag or release asset that cannot be created because hosting is unavailable is
recorded as an outstanding mechanical follow-up (§8.5), not a failure, because
the registry artifact — the thing consumers resolve — is what publication
means.

### 11.4 Adoption

If a manifest entry's registry identity already holds a published item (a
prior partial attempt, §12), execution MUST NOT republish and MUST NOT fail
blindly. It MAY adopt the existing item only when identity and payload
equality are proven: same version, and digest-set equality between the
registry's authoritative state and the manifest entry. Anything short of
proven equality is a conflict: the version is burned (publication is
immutable) and the recovery set moves to a new version. Go binaries are not
byte-reproducible across builds, so an `aw` version from a lost stage can
never be adopted — it always becomes a new version.

## 12. Failure and partial publication

When any step of an executing attempt fails — a publish job, a read-back
mismatch, a pointer push rejection, a deployment step — execution MUST stop
at the failure point, complete read-backs for everything already attempted,
and seal a partial audit record stating exactly what was published and what
was not. Published items stay published (immutability); nothing is rolled
back, deleted, or overwritten.

The go is spent. There is no automatic reuse of the go, no silent resume, and
no per-repository re-approval. Recovery is a new release attempt: new
`release_id`, new manifest — which adopts already-published items under §11.4,
carries the remaining artifacts, and re-establishes any evidence invalidated
by the failure — and one new go. If the failure changed nothing about the
candidates (say, a registry outage), the new manifest MAY reference the same
candidate runs; the new go is still required, because "resume what the spent
go covered" and "authorize what is now true" are different questions and only
the second is safe to ask.

## 13. Release and deployment boundary

### 13.1 One go may include deployment

When the manifest's deployment intent names production deployment, the same
single go authorizes it, and the attempt executes publication and deployment
as one ordered sequence. There is never a second deployment go inside an
authorized attempt.

### 13.2 Stop-at-publication

When deployment intent is `none`, the process stops after publication and
read-back. Deploying that release later is a new release attempt whose set
contains the deployment (adopting the published artifacts under §11.4) — with
its own manifest and its own single go.

### 13.3 Delivery obligations are not gates

Post-publication adoption work — plugin restarts on installed hosts, Pi cache
refresh, agents picking up a new `aw` — is recorded in the audit record as
outstanding operational work (§6.2). It MUST NOT hold the release open and
MUST NOT require additional authorization. Publication-is-not-delivery
remains true; this design keeps the obligations visible without making them
gates.

## 14. AC hosted image and deployment ownership

AC owns its hosted image and its production deployment. The publish and
deploy jobs for the AC image MUST live in the AC repository and run under
AC's credentials; the aweb repository's tooling never deploys AC. What
changes is only who asks: within a release attempt whose set includes them,
those AC-owned jobs are dispatched by the coordinator under the one go,
instead of by a separate human decision.

**First migration cut** retains the current exact-source overlay build
exactly as `ac:Dockerfile.release` and `ac:scripts/check_release_model.py`
define it — pinned-SHA checkout via CI build contexts, three-way
pin/lock/source agreement, commit-identity verification — but removes the
laptop/sibling-checkout fallback from the release path: the release image
MUST be built by the hosted AC candidate pipeline from the pinned SHA
checkout, never from a `../aweb` sibling tree. (The sibling default in
`ac:Makefile` and the hardcoded sibling paths in
`ac:scripts/e2e-cloud-user-journey.sh` remain available for development, but
no release-path job may consume them; the release path pins journeys to the
built image via the existing image-reuse handoff.)

**A later cut** MAY replace the overlay with a registry-only payload (the
image consuming only the published PyPI `aweb`/`awid-service`). That change
requires content-identity proof — evidence that the registry payload is
content-identical to the overlay payload for the same versions, or that the
overlay's remaining delta is empty — and the corresponding change to the AC
SOT (`ac:docs/sot.md`, "Release and embedded OSS compatibility"), which today
mandates the overlay. Until both exist, the overlay stays.

## 15. Production deployment mechanics

### 15.1 Immutable digest deployment

Deployment MUST target the image by immutable digest
(`ghcr.io/awebai/ac@sha256:…`), the digest from the manifest — never a
mutable tag. Repointing the service and triggering the deploy MUST be
performed by the AC-owned deploy job via the provider API, not by hand in a
dashboard.

### 15.2 Migration preflight

Before repointing, the deploy job MUST run the migration preflight: the
migration checksum and immutability gates AC already has
(`ac:backend/scripts/migration_manifest.py --verify`,
`ac:backend/scripts/verify_migration_immutability.py`) plus an enumeration of
exactly which migrations will apply, compared against the manifest's declared
migration set. A mismatch fails the attempt (§12). Migrations are applied as
an explicit ordered step of the deploy job — not left to startup — and the
container's fail-closed startup check remains as the backstop.

### 15.3 Health and version read-back

After deploy, the job MUST read `GET /api/v1/release` (and health) from the
deployed service and verify: `git_sha` equals the manifest's AC SHA,
`aweb_git_sha` equals the manifest's aweb SHA, and package versions equal the
manifest's. The release is not complete until this read-back matches. A
mismatch is a failure (§12) — the service is left running whatever it
reports, the record states it, and recovery is a new attempt.

### 15.4 Irreversible steps

Any deploy step that cannot be reverted by repointing to the previous image
digest — in practice, a migration that is not backward-compatible with the
previous release, as measured by the persisted-state edge (§10.2) — MUST be
named in the manifest's irreversibility statement, and the go's accepted-risks
prose MUST acknowledge it. When the statement is empty, rollback is:
repoint to the previous digest; the persisted-state result is the evidence
that the schema permits it.

## 16. Disposition of existing machinery

### 16.1 Retained

- `release/components.toml` — the graph stays the single declared source of
  artifacts and edges (§6.3), shed of fields the new model makes standing
  state (per-edge `supported` floors and measurement records; §16.4).
- The dispatch-only publish workflows (`.github/workflows/pypi-release.yml`,
  `npm-release.yml`, `awid-image-release.yml`, `awebai/aw`'s dispatch
  workflow) — as the per-artifact mechanical publish jobs (§11.1), bound to
  (`release_id`, `manifest_digest`) per §11.2.
- The pointer adapters (`scripts/pointer-adapter-marketplace-pointer.py`,
  `scripts/pointer-adapter-ac-pin.py`) — the `ac-pin` adapter's execution
  moves into a hosted AC-owned job, deleting the `EXTERNAL_CONTEXT`
  sibling-checkout requirement.
- The exact-publish scripts and the local stage/publish/observe adapter
  protocol (`docs/runnerless-release.md`) — as the runnerless lane (§8.5).
- The skew harnesses (§10.2) — re-aimed to emit the three-state result.
- The version monotonicity guard and independent per-artifact semver.
- Registry observation code (the driver's per-registry observers) — extracted
  as the read-back library (§11.3).
- `scripts/release_receipt_archive.py`'s durable-archive discipline — as the
  audit record store (§20.3), generalized to manifests, gos, and read-backs.
- AC's release-model, overlay, and migration gates
  (`ac:scripts/check_release_model.py`, `ac:scripts/check_release_overlay.py`,
  migration manifest/immutability checks) — inside the AC candidate pipeline
  and deploy preflight.

### 16.2 Simplified

- **G1** (dispatch-only, stage-once/publish-exact-bytes lanes): retained in
  substance; simplified in that staging moves into the candidate pipeline, so
  the lanes' `stage-only` mode stops being a separately invoked step.
- **G4** (frozen plan artifact): subsumed by the manifest. The manifest is
  the frozen artifact; drift detection becomes the pre-effect verification of
  §7.4. The separate plan/frozen-plan/staged-manifest artifact taxonomy
  collapses into manifest + audit records.
- **G5** (measured runtime support): simplified into per-release three-state
  compatibility (§10). What G5 protected — never inventing a floor, never
  shipping an unmeasured contract silently — survives as `could_not_measure`
  blocking; what it cost — standing measurement documents, edge-hash
  authorizations, deferral ceremony — is deleted.
- **The runnerless lane**: retained first-class (§8.5); simplified from a
  separate authority type with its own risk-record syntax to the same
  manifest/go semantics with `authority: local-runnerless` and prose risk
  acceptance inside the one go.
- **G2/G3**: no referent exists in the tree; the four-phase barrier protocol
  inside `run_plan` is the actual machinery, and it simplifies to: candidate
  pipeline (build+test once) → manifest → go → publish/deploy with
  read-backs.

### 16.3 Deleted

- The driver's plan computation, plan freezing, frozen-plan drift machinery,
  staged-manifest sealing, receipt schemas, `--resume`, and the entire
  `adopted-preplan-recovery` verb: replaced by manifest (§6), pre-effect
  verification (§7.4), partial audit records (§12), and adoption (§11.4).
- All three typed human-authorization records (`Approval` including the
  `sites` `approval_required` flag, `LOCAL_RISK_AUTHORIZATION`,
  `G5_AUTHORIZATION`) and their parsers: replaced by the one go (§7.4).
- `EXTERNAL_CONTEXT` and every laptop-resident release step (§16.1).
- `.github/workflows/ship.yml` as an entity distinct from the candidate
  pipeline: its journey content moves into the candidate pipeline and becomes
  blocking evidence (input 3), ending the informational-gate split.
- The legacy tag-triggered `.github/workflows/aw-release.yml` sync (the
  driver already uses `awebai/aw`'s dispatch workflow) — deleted in the
  migration's final slice, with the sync performed by the candidate pipeline
  or a dispatch job.
- Standing measurement documents under `release/measurements/` as release
  inputs (§16.4).
- The `docs/runnerless-release.md` sections describing
  `LOCAL_RISK_AUTHORIZATION` / `DEFER_G5` interplay — rewritten for §8.5.

### 16.4 Standing measurements become per-release results

The current model maintains measured floors as durable edge state
(`supported.set = "measured:…"` with anchored records). Under this design a
compatibility result lives in the manifest of the release that measured it;
the next release measures again against the then-current floor. This trades
some repeated execution for the removal of a whole class of state that could
go stale, and it is what makes `could_not_measure` an honest, per-attempt
answer rather than a bookkeeping status.

### 16.5 What is deliberately not rebuilt

No replacement is provided for: the driver's `--observation-file` test
transport (tests drive the new components directly); the anchor-artifact
naming scheme (the audit store subsumes it); receipt field-exactness
validation as a separate layer (manifest canonicalization plus digest
verification covers it).

### 16.6 The coordinator stays thin

The cross-repository coordinator is one small tool with five jobs: assemble a
manifest from candidate outputs and registry read-backs; verify completeness
and binding; present the four inputs and record the go; dispatch the
per-artifact jobs in manifest order, each of which does its own work; collect
read-backs and seal the audit record. It holds no registry credentials
(§20.1), builds nothing, tests nothing, and contains no per-artifact logic —
per-artifact knowledge lives in the per-artifact workflows and the graph
file. An implementation that grows per-artifact publishing logic inside the
coordinator is drifting back toward the driver this design replaces.

## 17. Artifact coverage

Explicit treatment for everything current release tooling represents, so
nothing falls out silently:

| Item | Treatment |
|---|---|
| `server`, `awid-pypi`, `awid-image`, `aw`, `channel`, `pi`, `skills` | Released artifacts in the model (§6.2). |
| `channel-core`, `agent-skills`, `server-image-payload` | Bundled build inputs; bound through embedding artifacts' digests; never independently published. |
| `marketplace-pointer` | Pointer artifact; published as a repository commit; content from the manifest; read-back re-reads the repository (§11.1, §11.3). |
| `ac-pin` | Pointer artifact executed by a hosted AC-owned job (§14, §16.1). |
| AC hosted image | Released artifact, new in the model (§5.1, §14). |
| AC production deployment | Deployment intent in the manifest; same single go (§13, §15). |
| `sites` (awid.ai landing) | Released artifact; its current `approval_required` flag is deleted — inclusion in a go-authorized set is its approval (§16.3). A docs-only site refresh outside a release set remains a content operation under `docs/a2a-release-runbook.md`-style maintainer discipline, out of release scope. |
| A2A gateway image (`a2a-gw-v*` tag workflow) | **Excluded.** Outside the current graph by deliberate decision; stays on `docs/a2a-release-runbook.md`. MAY be folded in as a released artifact in a later reviewed slice; until then its exclusion is explicit here. |
| Legacy `aw-release.yml` tag sync | Superseded; deleted in migration (§16.3). |
| aweb.ai site deploy, AC docs snapshot (`ac:docs/publication-sources.json`) | **Excluded**: AC-owned content publication, not release (§3). |
| Library, folio repositories | **Excluded**: not represented by current release tooling; each needs its own future decision. |

## 18. Migration

Delivered as small reviewed slices, each independently landable, ordered so
the current driver keeps working until the new lane has released for real.
Per the operating policy, completed work is not reopened: slices add the new
lane alongside the old, and deletion comes last.

1. **Spec approval** — this document reviewed and integrated.
2. **aweb candidate pipeline** — one workflow: build all candidates once,
   full suite (absorbing `ship.yml` content), digest-bound result document
   (§8.4). No behavior change to the driver.
3. **AC candidate pipeline** — hosted `release-ready` equivalent building the
   release image from the pinned-SHA checkout; the sibling-checkout fallback
   leaves the release path (§14).
4. **Compatibility results** — skew harnesses and the AC compat journey emit
   the three-state, manifest-ready result (§10) from candidate bytes.
5. **Manifest and go** — coordinator assembles manifests, records gos, audit
   store lands (§6, §7, §20.3). Still no outward effects through it.
6. **Publish binding** — publish workflows accept and verify
   (`release_id`, `manifest_digest`) (§11.2); pointer jobs move to hosted
   execution; read-back library extracted.
7. **AC deploy job** — digest deploy, migration preflight, read-back (§15),
   in the AC repository.
8. **Shadow exercise** — one full staging/shadow release through the new
   lane end to end (publication to a staging registry namespace or
   verify-only equivalents, deploy to a staging service), producing a sealed
   audit record reviewed against this specification.
9. **First real release** — one production release through the new lane,
   with the old driver untouched as fallback.
10. **Deletion** — after the first real release is sealed and reviewed:
    delete the superseded driver machinery (§16.3), rewrite
    `docs/runnerless-release.md` and the release skill, update
    `release/components.toml` to its reduced schema, and record the
    completion in the docs index.

## 19. Acceptance criteria and operational targets

Normative acceptance for the implemented process:

- **Exactly one human interaction** per release attempt: the go. Auditable by
  the audit record containing exactly one human authorization, and by the
  absence of manual-approval configuration in every workflow and provider
  setting on the release path (§7.1).
- A release set spanning aweb and AC, including production deployment, ships
  end to end from one go.
- No workflow on the release path accepts a test selector, artifact selector,
  skip flag, arbitrary ref, or command override (§8.3).
- Every published artifact's authoritative read-back equals its manifest
  entry (§11.3); every deployment's version read-back equals the manifest
  (§15.3).
- A deliberately induced mid-attempt failure (shadow exercise, §18.8) yields:
  a sealed partial record, zero automatic retries, and a recovery attempt
  that adopts published items only via proven equality and requires a new go
  (§11.4, §12).
- A `could_not_measure` compatibility result mechanically prevents go
  presentation (§10.3).
- A spent or invalidated go cannot cause a second publication: publish jobs
  refuse a duplicate (`release_id`, artifact) and any manifest-digest
  mismatch (§11.2).
- The runnerless lane completes a real publication with hosted CI unreachable,
  under one go (§8.5).

Operational targets (SHOULD; measured and recorded per release in the audit
record):

- Candidate pipeline elapsed: ≤ 2 hours per repository (bounded by the
  current comprehensive suite; reductions come from test speed, not test
  skipping).
- From go to sealed release: ≤ 30 minutes without deployment; ≤ 60 minutes
  including deployment and read-back.
- **Active human time on the happy path: ≤ 10 minutes** — reading one
  manifest presentation and granting one go. Candidate evidence is typically
  already present when selection starts, because the pipeline runs on push to
  main.
- Human interactions: exactly 1 (MUST, above).

## 20. Security, secrets, and audit

### 20.1 Credential boundaries

- Registry credentials (PyPI, npm, GHCR, GitHub Releases) live only in the
  per-artifact publish workflows' environments. The coordinator holds none.
  Trusted publishing (PyPI Trusted Publishers, npm provenance) SHOULD replace
  long-lived tokens where the registry supports it.
- AC production credentials (deploy provider API key, production database)
  live only in AC-owned jobs and are never readable by aweb-repository
  workflows or the coordinator.
- Pointer-repository write access lives only in the pointer jobs.
- The runnerless lane uses operator-local credentials; the manifest's
  `authority` field makes that visible in the audit record.
- Workflow environments MUST NOT carry manual-approval protection rules on
  the release path (§7.1); authorization is the go, enforced at the job level
  by §11.2, not by a second human click.

### 20.2 The go is attributable

The go record names a human. The store holding go records MUST make them
attributable and tamper-evident (content-addressed records whose digests are
cross-referenced by subsequent records; the sealed chain ends in the final
receipt). No agent may fabricate a go: publish jobs verify the go record's
existence in the audit store, and the audit store's write path is restricted
to the coordinator identity.

### 20.3 Audit record

Every attempt — completed, failed, or refused — seals an audit record
sufficient to reconstruct exactly what the one go authorized and what
actually happened: the manifest bytes, the go record, per-step dispatch and
result records, every read-back, and the final (possibly partial) receipt.
Records are content-addressed and immutable; the store MUST be durable beyond
CI artifact retention (the discipline of `scripts/release_receipt_archive.py`:
an archive is a byte store, never an authority — validation always re-derives
from content digests). Given a `release_id`, a reader MUST be able to answer:
what was proposed, who authorized it, what was published where with what
digests, what was deployed, and what read-backs proved it.

## 21. References

aweb: `release/components.toml`; `scripts/release_driver.py`;
`docs/runnerless-release.md`; `scripts/release_receipt_archive.py`; the skew
harnesses named in §10.2; `.github/workflows/` release lanes named in §16.1;
`docs/aweb-sot.md` (migrations, auth envelope compatibility, awid dependency
surface); `docs/oss-boundary.md` (ownership rule this design's §14 follows);
`docs/setup-surface-release-gates.md` (CLI setup-surface checks, which remain
part of the aweb candidate pipeline's suite).

AC: `ac:docs/sot.md` ("Release and embedded OSS compatibility");
`ac:release-pin.toml`; `ac:Dockerfile.release`;
`ac:scripts/check_release_model.py`; `ac:scripts/check_release_overlay.py`;
`ac:Makefile` (`release-ready`, `test-cloud-user-journeys-compat`);
`ac:.github/workflows/aweb-cloud-ci-cd.yml`;
`ac:backend/src/aweb_cloud/build_provenance.py` and `GET /api/v1/release`.
