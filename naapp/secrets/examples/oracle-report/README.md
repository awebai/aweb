# Fixed Oracle lab report

This example implements `aweb-acwd.3`: one reviewed read-only report on synthetic
Oracle Database Free data, using the existing `aweb.secrets.job/1` OCI contract.
Its only inputs are `dataset` (`orders` or `inventory`) and `week_start` (an ASCII
ISO date that must be a Monday). The window is exactly seven days, start inclusive
and end exclusive. Neither SQL nor a database destination is an input.

`report.py` binds those two values into one fixed aggregate over
`LAB_OWNER.REPORT_EVENTS`. It returns one JSON object containing public report
metadata and three integer counts: total rows, missing required values, and
invalid statuses. It never selects or returns individual records. The single-row
result and safe integer checks precede serialization; output is at most 1,024
bytes. Driver connect timeout is 3 seconds, each round trip 2 seconds, the program
alarm 10 seconds, and the existing runner hard execution deadline 20 seconds.
The job retains the runner's generic 2,048-byte output bound, projection and
known-value redaction. Driver errors produce a fixed value-free refusal.

The disposable account has only `CREATE SESSION` and object `READ`, and is marked
`READ ONLY`. The report additionally starts a read-only transaction. The test
permission control deliberately omits that transaction: a fresh connection must
read the existing table and refuse valid UPDATE, DELETE, INSERT, CREATE TABLE and
SELECT FOR UPDATE with Oracle permission errors (`ORA-41900` for missing object privileges and
`ORA-28194` for a read-only account), with no table creation or row count change. The database and data are disposable and synthetic; this is not a
configuration for customer access.

## Pins and authority

`job.json` pins the actual ARM64 OCI manifest. `runner-config.json` contains the
same definition and its existing `job_digest`, calculated by the runner. The
public test runner ID and agent UID are lab values. An operator installing this
job uses its registered runner ID and actual agent UIDs, then reviews the changed
job digest and independently protects the matching local pin. Ordinary owner
approval, registration and durable-credential approval remain required by the
existing contract; these files confer none of those authorities.

`image-lock.json` records the archive hash and the Dockerfile, dependency export
and report source hashes used for that image. The reviewed image archive is a
separate build artifact, `.artifacts/report.oci.tar`, not a Git blob. Stage that
exact artifact with `uv run --frozen python stage.py`; it checks those pins before
extracting the OCI layout and loading the same image for the permission control.
The runner itself hashes the image blobs and selects the pinned manifest before
opening credentials. A source rebuild can produce another digest; it must be
explicitly pinned and reviewed, never silently substituted for this artifact.

The image uses a digest-pinned Python base and hash-locked dependencies from
`requirements.txt` (`uv export --frozen --no-dev --no-emit-project`). Build once:

```sh
mkdir -p .artifacts
docker buildx build --platform linux/arm64 --provenance=false --sbom=false \
  --output type=oci,dest=.artifacts/report.oci.tar \
  --metadata-file .artifacts/report-build.json .
```

The Oracle Free ARM64 image is pinned separately in `lab.py`. Oracle's startup
script reads the generated administrator password from `/run/secrets/oracle_pwd`.
The lab supplies that file through private stdin into an ephemeral tmpfs volume;
it never puts a password in Docker environment metadata, argv or image layers.
Seeding waits for Oracle's final startup hook, then uses SQLPlus OS authentication
and private stdin. All client and database
containers share one **internal** Docker network, with no published port. The
report's only endpoint is the fixed lab address `10.203.0.2:1521/FREEPDB1`.

## Real proof

Run from this directory with Docker Desktop ARM64/Linux available. The subnet
`10.203.0.0/24` must be free. First stage the reviewed archive, then build the
existing runner tools and the small proof consumer:

```sh
uv sync --frozen
uv run --frozen python stage.py
docker build --build-context runner=../../runner \
  --build-context values=../../values --build-context naapp=../../../../naapp-lib \
  -t aweb-oracle-runner-tools:06e61 ../../runner/tests/oci
docker build -f proof.Dockerfile -t aweb-oracle-job-proof:06e61 .
```

Run these named test files through the team's suite-lock wrapper with
`SUITE_LOCK_FOCUSED=1`, `SUITE_LOCK_FOCUSED_MAX_LOAD=8`, and one worker:

```sh
uv run --frozen pytest -q --tb=short --assert=plain \
  tests/test_report.py tests/test_oracle.py
```

The pure tests cover valid inputs and bounded projection, plus input and result
refusals. The real tests create one Oracle Free container, a private password
volume and an internal network, seed synthetic records, run both datasets through
actual `RunnerConfig` / dispatch-bound HPKE / `execute_oci` / umoci / rootless
runc, and check exact aggregates, no raw record or credential output, parameter
refusal, actual database write refusal, and bounded value-free failure while
the real database is paused. Credential values are generated in
memory. Never enable pytest locals or capture raw SQL/driver/container output as
evidence. The fixture removes its own randomly named resources on exit.

The proof uses the runner's existing non-root UID 10000, dropped capabilities,
private tmpfs bundles, and relaxed outer syscall/proc restrictions needed for
nested rootless namespaces. Runtime tool pins are derived from that installed
test image; they are not deployment pins. This is a job execution proof. The S19
operator supervisor, protected installation and full HO6 service lifecycle are
separate existing release work.

References: [existing job/OCI contract](../../../../docs/design/secrets.md),
[runner platform proof](../../runner/tests/oci/README.md),
[Oracle image secret files](https://github.com/oracle/docker-images/tree/main/OracleDatabase/SingleInstance#running-oracle-database-in-a-container),
[Oracle read-only users](https://docs.oracle.com/en/database/oracle/oracle-database/26/dbseg/configuring-privilege-and-role-authorization.html),
[Oracle missing-privilege refusal](https://docs.oracle.com/en/error-help/db/ora-41900/),
[driver timeouts](https://python-oracledb.readthedocs.io/en/stable/api_manual/connection.html#Connection.call_timeout).
