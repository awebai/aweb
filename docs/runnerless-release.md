# Runnerless release lane

GitHub Actions is optional for release execution. The normal hosted lane remains
available. During an outage, an explicit human risk authorization selects the
local lane:

```sh
make release-plan AUTHORITY=local-runnerless STORE_ROOT="$PWD/.release-runs"
make release-run AUTHORITY=local-runnerless STORE_ROOT="$PWD/.release-runs" \
  PLAN_ID=<id> PLAN_ARTIFACT_ID=<artifact-id> \
  LOCAL_ADAPTER='server@<exact-reviewed-source-sha>=/absolute/path/to/direct-adapter' \
  LOCAL_RISK_AUTHORIZATION='juan,2026-08-06T12:00:00Z,runnerless risk accepted'
```

`LOCAL_RISK_AUTHORIZATION` accepts the risk of releasing without a hosted
runner. It does **not** accept unmeasured runtime support: those are different
judgments that happen to arrive in the same troubled release, so one is never
recorded as the other.

Deferring runtime-contract measurement needs its own record, on any authority —
hosted, local-development or runnerless:

```sh
make release-run AUTHORITY=local-runnerless STORE_ROOT="$PWD/.release-runs" \
  PLAN_ID=<id> PLAN_ARTIFACT_ID=<artifact-id> \
  LOCAL_ADAPTER='server@<exact-reviewed-source-sha>=/absolute/path/to/direct-adapter' \
  LOCAL_RISK_AUTHORIZATION='juan,2026-08-06T12:00:00Z,runnerless risk accepted' \
  DEFER_G5=1 \
  G5_AUTHORIZATION='who=juan,when=2026-08-06T12:00:00Z,source=<40hex>,plan=<64hex>,edges=<64hex>+<64hex>,risk=unmeasured runtime support accepted'
```

`DEFER_G5` alone records nothing and is refused. The authorization binds the
source, the frozen plan and **exactly** the incomplete edges being deferred, so
it cannot be reused for another release or stretched over an edge nobody read.
Take the edge ids verbatim from `release-plan`'s `deferrable_runtime_contracts`
list — they are canonical content identities, not display strings, because
`a<->b` would alias the two `server<->server` edges.

Deferral excuses only those incomplete edges. Every measured edge in the same
plan still resolves its record and runs its matrix.

`release-plan` reports the source SHA's `ship.yml` state as
`success`, `failure`, `none`, or `unknown`; this is informational and never a
gate.

A local adapter is an executable with three operations:

- `stage --component C --version V --source-sha SHA --stage DIR` builds once and
  writes package files to the empty durable directory.
- `publish --component C --version V --stage DIR` publishes those exact files
  to the real registry and prints JSON. `{"hosting":"deferred",
  "continuation":"tag-and-release"}` records unavailable tag/release hosting
  as resumable work after registry success; it does not roll back publication.
- `observe --component C --version V --stage DIR` reads registry truth and
  prints `{"files":{"name":"sha256"}}`.

The driver hashes the complete staged inventory, seals it in the staged
manifest, passes the same directory to publish, and re-observes exact registry
hashes. Resume loads the durable manifest and never invokes `stage` again.
Adapters should call the existing component scripts (`npm-exact-publish.sh`,
`pypi-exact-publish.sh`, `oci-exact-publish.sh`) or the component's direct
release adapter rather than reimplementing packaging.
