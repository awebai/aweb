# aweb secrets runner

The runner connects out to a secrets service and runs locally pinned jobs. It
uses its own signing and encryption keys; it is not an AWID team member.

The implementation provides the client side of the published
[S0 protocol](../../../docs/secrets-runner-protocol.md): signed requests,
assignment verification, HPKE opening and a durable SQLite replay journal.
Registration and `doctor` are available as commands. The local execution library
checks job pins and runs host executables with bounded, sanitized output. The
claim/report loop, OCI runtime and separate-user end-to-end acceptance remain subsequent
slices of S15b; this package does not yet execute service assignments.

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

Local job preparation uses a runner-owned JSON configuration with exactly three
keys: `v: 1`, `agent_uids` (the actual agent OS UIDs), and `jobs`. Each `jobs`
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
boundary. OCI jobs currently refuse rather than falling back to host execution.
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
worker using the same state refuses with `runner_busy`. Pending saved reports
are sent before any claim, including after restart. Assignment verification and
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
executable and declared-file hashes, working directories and private journal. On
first run it creates `journal.sqlite3` if absent. It
does not contact the service, request an enrolment code, open credentials or
execute a job. Success prints only the runner ID and checked job IDs. Refusals
print a fixed code. A pending unregistered identity and an unavailable OCI runtime
refuse preflight. This local preflight does not establish current server authority;
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
