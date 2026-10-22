# aweb secrets runner

The runner connects out to a secrets service and runs locally pinned jobs. It
uses its own signing and encryption keys; it is not an AWID team member.

The implementation provides the client side of the published
[S0 protocol](../../../docs/secrets-runner-protocol.md): signed requests,
assignment verification, HPKE opening and a durable SQLite replay journal.
The `register`, `doctor` and `run` commands support fixed-selector exec jobs and
explicitly configured daemonless OCI jobs. The worker verifies service assignments,
journals them before execution, and returns bounded sanitized reports. Customer
activation still requires the dedicated-user S19 journey and server release/report
integration proof on the release candidate.

Run registration as the dedicated runner OS user:

```sh
uv run aweb-secrets-runner register --origin https://secrets.example \
  --state-dir /absolute/private/runner-state
```

Enter the one-use owner-issued code at the hidden prompt. Automation supplies one
line on stdin; the code is never an argument or echoed by the command.

The command generates Ed25519 and X25519 keys locally, sends their public halves
over verified TLS, then pins the exact origin, runner ID and service signing key.
It prints only those public identifiers. `--ca-file` accepts a custom CA bundle
for a self-hosted service. Registration does not follow redirects or use ambient
HTTP proxies.

The state directory is created with mode 0700. `identity.json` and the registration
lock are private to the runner UID. Keys are committed before the exchange and
the registered identity is written as one fsynced atomic replacement. The code
is never stored. Concurrent registration refuses before network activity. A
failed exchange retains the same pending keys and does not retry automatically.
If the service consumed a code before a lost response, obtain a fresh owner-issued
code rather than assuming nothing happened. An already registered identity cannot
be overwritten by this command; rotation requires owner-authorized replacement
and a fresh state directory.

Verification checks the pinned service key, runner and origin, parameter and
credential hashes, and the assignment lifetime, in the protocol's specified
order. It commits the dispatch ID to the local journal before returning a
verified assignment. Invalid assignments do not consume a journal entry. An
accepted dispatch cannot be accepted by another process, including after a
restart. A crash after acceptance therefore requires reconciliation rather
than executing that dispatch again.

The journal directory must already exist, be owned by the runner UID and have
no group or other permissions. The database is created with mode 0600; symbolic
links, hard links and public files are refused. Deployment must also keep this
directory outside agent write authority. SQLite failures refuse work.

The journal also stores exact sanitized report bytes before their first send.
Pending reports survive reopening and assignment expiry; retries reuse those
bytes with a fresh signed nonce. Acknowledgment clears the body while retaining
its private digest/completion marker, so a later retry cannot revive or replace
it. Only accepted dispatches can record a result. The journal grants no server
authority. Incompatible pre-release layouts refuse without resetting records;
no automatic migration or reset runs.

Local job preparation uses a runner-owned JSON configuration with required
keys `v: 1`, `agent_uids` (the actual agent OS UIDs), and `jobs`. An optional
`runtime` key configures the daemonless OCI prerequisites described below. Each `jobs`
entry is keyed by job ID and contains `digest` and `definition`: the owner-approved
`job/1` record. Both the server assignment and this independent local pin must
match. Keep the configuration and its parent directories outside the agents'
write authority. The configured agent UID list must be nonempty; the runner's
actual effective UID and UID 0 are refused as agent identities. This checks the
declared Unix user boundary; operators must list every agent that shares the host.

The local library re-reads that protected configuration and re-hashes the
executable and every declared file before each execution. A changed configuration
refuses work until explicitly reloaded. Root-owned OS files are allowed; files or
parent directories writable by another user are refused. Trusted root-owned
sticky ancestor directories, such as `/tmp`, may contain a runner-owned private
directory. Parameter validation uses the shared pages validators, and credentials
use the sole `aweb-secrets-values` codec. Credential environment bindings name an
explicit slot and field; every slot must use one consistent field family. Missing
fields and NUL-bearing selected values refuse work. This never stringifies a
credential object or chooses a field by dictionary order.

The execution input retains each signed actual `secret_ref` with its sealed HPKE
value, recipient key and dispatch binding. Local pin, parameter, executable and
declared-file checks complete before any HPKE opening. The entire credential
count and fixed-selector label order are checked before the first opening; a
same-family positional swap refuses too. The current release supports fixed
selectors only, while the server's ordinary-child and mint paths remain guarded.
When those paths are enabled, their accepted signed-ordinal substitution rules
must be composed explicitly; equality between a child ref and its parent label
is not a permanent restriction on that contract.

Host execution uses literal argument elements, an empty starting environment
plus the declared names, closed stdin, and a separate process group. Both output
pipes are drained under one combined byte bound, with strict UTF-8 validation,
known-value redaction and credential-shape detection before a report is built.
The deadline includes descendant-held pipes; timeout or cancellation kills the
process group and closes the runner's pipes. A delayed `started` report cannot
extend that deadline. A trusted job can escape a Unix process group, so this is
not a process sandbox. Use the required dedicated user/container deployment
boundary. OCI jobs require the explicit pinned runtime described below and never
fall back to host execution.
If the runner is PID 1 in a container, use an init process, such as Docker's
`--init` or `tini`, to reap orphaned descendants after process-group cleanup.
The runner is not a child subreaper.

The outbound transport library uses verified TLS to the registered origin,
without redirects, ambient proxies or cookie authentication. Every attempt
signs the exact request body with a fresh nonce and current timestamp. Assignment
responses are bounded before verification; report acknowledgments must be empty
204 responses. Public refusal codes are validated without reflecting server
text. A total deadline bounds long polling and response reads, including a
server that keeps a connection active indefinitely. Cancellation closes the
in-flight request. The transport does not automatically retry, open credentials,
or execute a returned assignment; the durable worker loop remains separate.
Private state-directory backups include pending sanitized reports until they
are acknowledged.

Start the outbound worker with the same protected configuration and state:

```sh
uv run aweb-secrets-runner run --config /absolute/runner-config.json \
  --state-dir /absolute/private/runner-state
```

An explicit operator CA can be supplied with `--ca-file /absolute/ca.pem`.
Startup performs the local preflight and holds a private process lock; another
worker using the same state refuses with `runner_busy`. When an OCI runtime is
configured, startup recovers its local workspace before constructing the outbound
transport. It stops known containers and removes only safely stopped owned trees;
uncertain work refuses startup and retains its sensitive transient state for
operator reconciliation. Recovery never changes journal/identity records, acks a
report or reruns an accepted assignment. Pending saved reports are sent before
any claim, including after restart. Assignment verification and
durable replay acceptance precede local checks, HPKE opening and execution.
The execution library samples expiry again after local checks. A completed
process's sanitized report is saved before its first send and cleared only
after an empty 204 acknowledgment. Transient transport failures retry with
bounded backoff and fresh signed nonces; saved report bytes never change.

SIGTERM cancels in-flight work, cleans up the process group and exits 143;
SIGINT exits 130. An interrupted or refused accepted assignment is never rerun
and gets no fabricated process result. A replay or reconciliation refusal stops
the worker with its fixed code. Reconcile the original attempt in the console
and restart with the same journal; deleting replay state is not recovery. No
credential, assignment or result body is printed by the worker.

Check a registered identity and all local job pins before starting a worker:

```sh
uv run aweb-secrets-runner doctor --config /absolute/runner-config.json \
  --state-dir /absolute/private/runner-state
```

`doctor` checks the actual UID, protected configuration, runner membership,
executable and declared-file hashes, working directories and private journal.
For configured OCI jobs it checks runtime tool hashes, private memory storage,
the protected image-store directory and declared read-only mount sources. On
first run it creates `journal.sqlite3` if absent. It
does not contact the service, request an enrolment code, open credentials or
execute a job. Success prints only the runner ID and checked job IDs. Refusals
print a fixed code. A pending unregistered identity and missing OCI prerequisites refuse preflight. This local preflight does not establish current server authority;
the service and worker still recheck each assignment.

Run the focused checks from this directory:

```sh
uv sync --locked
uv run pytest tests/test_protocol.py tests/test_journal.py tests/test_result_journal.py
uv run pytest tests/test_registration.py
uv run pytest tests/test_http.py
uv run pytest tests/test_worker.py
uv run pytest tests/test_filesystem.py tests/test_jobs.py tests/test_execution.py
uv run pytest tests/test_credential_opening.py tests/test_doctor.py
uv run ruff check src tests
uv run mypy src
```

The tests consume the public protocol vectors independently of the server and
exercise real SQLite connections and child processes. Cryptographic operations
use `cryptography`, including its RFC 9180 HPKE implementation.

OCI preparation separates frozen public inputs from credential opening.
`RunnerConfig.inputs` rechecks the local config/job/runner pin, validates supplied
parameters and exact ordered credential labels, then freezes the complete argv,
known environment values and unknown credential-backed slots. It receives no key
or plaintext and confers no execution or opening authority. Exec preparation uses
this same parameter expansion before its existing executable/file checks and
shared credential decoding; there is no second parameter validator.

For a qualified pinned runc runtime, an absent, empty or credential-derived HOME
cannot establish exact environment capability before opening and refuses.
A nonempty HOME supplied by the fixed job literal or a validated frozen parameter
is preserved, including env-only strings beginning with `-`. This runtime-specific
capability does not add a universal job/1 HOME requirement or rewrite a pin.
OCI dispatch uses the same local checks and reviewed private runtime lifecycle.


### OCI operator configuration

The optional `runtime` object has exactly these fields:

```json
{
  "kind": "runc",
  "engine": {"path": "/usr/bin/runc", "sha256": "<64 lowercase hex digits>"},
  "unpacker": {"path": "/usr/bin/umoci", "sha256": "<64 lowercase hex digits>"},
  "supervisor": {"path": "/opt/runner/bin/python", "sha256": "<64 lowercase hex digits>"},
  "images": "/srv/runner/oci-layout",
  "workspace": "/run/runner/private-workspace"
}
```

Supply hashes of the actual qualified installed binaries. `supervisor.path`
must be the exact `sys.executable` of the runner's installed Python environment;
its isolated `-I` helper must import the same installed runner package. Paths are
absolute, without traversal or NUL. Unknown fields, missing pins and other
runtime kinds refuse with `runtime_config_invalid`. There is no automatic tool
lookup, registry pull, daemon or disk-storage fallback.

The image store is an operator-populated protected OCI layout. The workspace
must already exist on Linux tmpfs, owned by the actual runner UID with mode
0700 and protected ancestors. Reserve it for this runner's transient job trees;
keep configuration, identity/journal state and image storage outside it. Runtime
state and credential-bearing bundles are created privately beneath it. Operators
provision these resources separately; loading configuration creates none of them.

`doctor` hashes tools and checks storage/mount permissions without invoking any
tool, unpacking an image, recovering stale work or opening credentials. Image
content, parameters and exact environment capability are checked during the
per-assignment preparation. Configured paths and pins are re-read through the
same protected configuration; changing them requires an explicit worker restart.

Adding `runtime` composes local preflight, startup recovery and OCI assignment
execution through the pinned runtime. The common worker still verifies and
journals the service assignment first. Without a configured runtime, OCI refuses;
exec-only installations can omit it and retain their existing checks. Deployment
still requires the separate-user release journey and server-side activation gates.


### Operator exits and recovery

The worker prints a fixed refusal code, never a response or job body. Use a
supervisor restart delay of at least one minute (for example `RestartSec=60s`),
and alert on repeated refusals. A restart never makes an uncertain assignment safe
to run again. `runner_unavailable` is retried internally with bounded backoff;
other refusals stop the worker.

| Exit / code | Operator action |
| --- | --- |
| `0` | Registration or preflight completed successfully. |
| `2` / `runner_arguments_invalid` | Fix the command arguments. Registration codes belong on private stdin or the hidden prompt. |
| `130` / `143` | SIGINT / SIGTERM stopped the worker. Restart with the same protected config, identity and journal. |
| `1` / `runner_reconciliation_required`, `assignment_replayed` | Reconcile the original dispatch in the console before restarting. Keep the acceptance journal. |
| `1` / `oci_recovery_required`, `oci_cleanup_required` | Stop and reconcile the original local launcher/container before removing only its stopped transient tree. Retained `job-*` trees under the configured workspace may contain sensitive config. This blocks the whole runner, including exec jobs. |
| `1` / `runner_busy` | Check the existing worker/workspace owner. Do not delete identity, lock or journal state. |
| `1` / `runtime_config_invalid`, `config_changed`, `file_pin_mismatch`, `oci_state_invalid`, `oci_image_invalid`, `oci_environment_unsupported`, `runner_runtime_unavailable` | Repair the operator-provisioned paths, permissions, memory storage or approved pins, then rerun `doctor`. Never inject runtime defaults or silently rewrite a job pin. |
| `1` / `runner_unknown`, `runner_unregistered` | Check owner-side runner status. Registration/rotation needs the owner-issued code and the documented identity procedure. |
| `1` / `params_invalid`, `credential_invalid`, `assignment_expired`, `job_not_allowed` | Check the original attempted job and local pin; reconcile that attempt before retrying new work. No exit report was fabricated. |
| `1` / `state_permissions`, `journal_unavailable`, `journal_version_unsupported`, `identity_unavailable` | Restore the same UID, private state access and compatible runner installation. Preserve the journal and identity; do not reset or relabel them. |
| `1` / `assignment_invalid`, `assignment_binding_mismatch`, `assignment_wrong_runner`, `runner_response_invalid` | Check the pinned service and original request with the service operator. Do not weaken verification or log the body. |
| `1` / `job_start_failed`, `job_cleanup_failed`, `oci_prepare_failed`, `oci_execution_failed`, `oci_supervisor_failed` | Establish that the original local processes stopped, repair the runtime and reconcile the original attempt before new work. |
| `1` / `runner_dispatch_unknown`, `runner_result_conflict` while flushing | Preserve the pending bytes and original dispatch for service-side reconciliation. Reports flush before claims, so this refusal blocks new work. There is no discard command; do not hand-edit SQLite or mark an unacknowledged result as acknowledged. |
| `1` / another fixed refusal | Investigate the printed code against the original command/dispatch; preserve state and avoid a rapid restart loop. |

List retained directory names only inside the configured private workspace; do
not print or copy their contents. Empty runtime state is not evidence that a
launcher stopped. Unknown, incomplete or engine-mismatched leftovers require
operator reconciliation; startup never guesses PIDs or reruns the assignment.
