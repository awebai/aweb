# secrets runner protocol

Status: **contract for aweb-acgh.18.1 (S0).** It turns the transport in
[secrets §9.3](design/secrets.md) into two signed artifacts and one sealing
rule. `docs/vectors/secrets-runner-protocol-v1.json` freezes it. The secrets
server implements the server side (S15a) and the `aweb-secrets-runner` command
the runner side (S15b). A runner written by anyone else must reproduce these
bytes.

## Model

A runner is an app-local principal of one secrets deployment, not an AWID
identity. At registration (§9.2) it generates two keys locally and sends their
public halves:

- a **signing key**, Ed25519, named by its `did:key`;
- an **encryption key**, X25519, sent as its 32 raw public-key bytes in
  base64url.

It receives its `runner_id` and pins two values: the deployment's **origin**
(`https://` scheme, host and optional port, as in the registration command) and
its **service signing key**, an Ed25519 `did:key`.

**Identifiers.** `runner_id` is `rnr_` and `dispatch_id` is `dsp_`, each
followed by at least 16 bytes of CSPRNG output in base64url. secrets answers an
unknown runner with its own code (`runner_unknown`, before the signature check)
for operators' sake. Guessing an identifier of this size is not a practical way
to probe for runners.

Traffic flows one way at the network level: the runner connects out and opens
no port. Authority flows both ways. The runner signs every request to secrets,
and secrets signs every assignment it hands the runner.

## Signed bytes

Both artifacts use the form of
[principal attestation](principal-attestation.md#signed-bytes):

```text
signing bytes = "<type>/1\n" || canonical_json(payload)
signature     = Ed25519(signing key, signing bytes)
```

- `canonical_json` is AWID's (`awid/src/awid/signing.py`): keys sorted, no
  whitespace, UTF-8, integers only (no floats), duplicate keys refused on input.
- **Values.** Every string, key included, is a sequence of Unicode scalar
  values: a lone surrogate escape such as `\ud800` is refused. Every integer,
  in a payload, `params` or `credentials`, is within ±(2^53 − 1), so every
  language reproduces the same bytes. A verifier refuses a value outside these
  rules at its shape step.
- **Which bytes are signed.** A request's header carries the exact payload
  bytes, and they must be canonical: the verifier re-canonicalizes the parsed
  payload and requires the bytes it received. An assignment arrives as a nested
  object in a JSON body, so its signing bytes are the prefix followed by
  `canonical_json` of the parsed `assignment`. The body's own encoding
  (whitespace, key order) is not significant, but duplicate keys and floats
  anywhere in it are still refused.
- Signatures and every other binary value are base64url without padding, with
  exactly one accepted encoding: a verifier decodes, re-encodes and requires the
  same string.
- Timestamps are RFC 3339 UTC strings with a `Z` suffix, second precision and
  ASCII digits only.
- Each payload carries its own `type` and `v`, and the two prefixes differ, so a
  request never verifies as an assignment or the reverse.

## 1. Runner request, `aweb.secrets.runner-request/1`

Every runner request to secrets carries one header:

```text
X-AWEB-Secrets-Runner-Request: b64url(payload bytes) "." b64url(signature)
```

`payload bytes` is the canonical JSON without the prefix. The header is at most
4096 bytes. The payload has exactly these fields:

```json
{
  "v": 1,
  "type": "aweb.secrets.runner-request",
  "origin": "https://secrets.example",
  "runner_id": "rnr_Unqp9DFTnajhUdVDTR1eYQ",
  "kid": "did:key:z6Mk...",
  "method": "POST",
  "path": "/runner/v1/claim",
  "body_sha256": "<64 lowercase hex>",
  "timestamp": "2026-10-20T12:00:00Z",
  "nonce": "<16 random bytes, base64url>"
}
```

- `origin` is the origin the runner pinned. It binds the request to one
  deployment.
- `kid` is the `did:key` of the runner's registered signing key, which signs.
- `method` is the HTTP method. `path` is the raw request target: path and query
  exactly as sent, percent-encoding untouched.
- `body_sha256` is the SHA-256 of the raw request body; an empty body hashes the
  empty string.

secrets verifies in this order and refuses with the first code that applies:

1. **Shape** (`runner_request_invalid`): the header has two parts, each a
   canonical base64url string; the payload is canonical JSON within the value
   rules, with exactly the fields above, `v` 1, the right `type`, a well-formed
   `runner_id`, a 16-byte nonce and a valid timestamp.
2. **Runner** (`runner_unknown`): `runner_id` names an active runner of this
   deployment, and `kid` is its registered signing key.
3. **Signature** (`runner_request_invalid`): the signature verifies under that
   key over the prefixed bytes.
4. **Binding** (`runner_request_binding_mismatch`): `origin` is this
   deployment's, and `method`, `path` and `body_sha256` match the request
   received.
5. **Time** (`runner_request_stale`): the timestamp is within 120 seconds of
   secrets' clock, either way.
6. **Replay** (`runner_request_replayed`): the pair (`runner_id`, `nonce`) has
   not been seen. secrets stores every pair it accepts, including those of
   requests with no effect, such as an empty claim or a poll, until 120 seconds
   after the timestamp. For a request that has an effect, it stores the pair in
   the same transaction as that effect.

## 2. Runner assignment, `aweb.secrets.runner-assignment/1`

A claim that returns work answers with one assignment:

```json
{
  "assignment": { ...payload... },
  "signature": "<b64url>",
  "params": { ...the job's typed parameters... },
  "credentials": [ { "secret_ref": "db-admin", "sealed": "<b64url>" } ]
}
```

The payload has exactly these fields:

```json
{
  "v": 1,
  "type": "aweb.secrets.runner-assignment",
  "origin": "https://secrets.example",
  "service_kid": "did:key:z6Mk...",
  "runner_id": "rnr_Unqp9DFTnajhUdVDTR1eYQ",
  "dispatch_id": "dsp_240bbWTk7JDOszX8Q0TnVw",
  "job_id": "nightly-backup",
  "job_digest": "<64 lowercase hex>",
  "params_sha256": "<64 lowercase hex>",
  "credentials_sha256": "<64 lowercase hex>",
  "issued_at": "2026-10-20T12:00:00Z",
  "expires_at": "2026-10-20T12:02:00Z"
}
```

- `job_id` and `job_digest` name the immutable job definition (§9.4).
- `params_sha256` is the SHA-256 of `canonical_json(params)`. Parameters are
  canonical JSON values: integers only, so an amount is in integer minor units.
- `credentials_sha256` is the SHA-256 of `canonical_json(credentials)`, the list
  in the order sent. A job without credentials sends `[]`.

The runner verifies in this order and refuses with the first code that applies.
It reports nothing it refused as started.

1. **Shape** (`assignment_invalid`): the body is at most 1 MiB; the body and
   payload have exactly the fields above, well-typed and within the value rules,
   with a well-formed `runner_id` and `dispatch_id`; each `credentials` item is
   exactly `{secret_ref, sealed}`, with `sealed` a canonical base64url string.
2. **Signature** (`assignment_invalid`): `service_kid` is the service key the
   runner pinned, and the signature verifies under it over the prefixed bytes.
3. **Audience** (`assignment_wrong_runner`): `runner_id` is the runner's own and
   `origin` is the origin it pinned.
4. **Binding** (`assignment_binding_mismatch`): `params_sha256` and
   `credentials_sha256` match the `params` and `credentials` received.
5. **Time** (`assignment_expired`): `expires_at` is after `issued_at` and at
   most 300 seconds after it, the runner's clock is before `expires_at`, and
   `issued_at` is not more than 120 seconds ahead of the runner's clock.
6. **Replay** (`assignment_replayed`): `dispatch_id` is not in the runner's
   local journal. The runner records it there before it starts the job and keeps
   it at least until the assignment's `expires_at`. Steps 5 and 6 together
   refuse every replay: a replay before `expires_at` meets the journal, and one
   after it is expired.

The runner then applies its own two-key pinning and file checks (§9.4) before
running anything.

## 3. Credential sealing

Each credential travels sealed to the runner's encryption key with HPKE
([RFC 9180](https://www.rfc-editor.org/rfc/rfc9180)), base mode, single shot:

| Parameter | Value |
| --- | --- |
| KEM | DHKEM(X25519, HKDF-SHA256), `0x0020` |
| KDF | HKDF-SHA256, `0x0001` |
| AEAD | ChaCha20-Poly1305, `0x0003` |
| `info` | the assignment's `dispatch_id`, as UTF-8 bytes |
| `aad` | empty |

`sealed` is `b64url(enc || ciphertext)`, where `enc` is the 32-byte
encapsulated key. The plaintext is the credential material, opaque to this
protocol. Because `info` is the dispatch, a credential sealed for one dispatch
does not open under another, even for the same runner. Because the assignment
signature covers `credentials_sha256`, a credential cannot be moved between
slots or assignments without failing the binding check.

The credential exists in plaintext only on the runner host, for that job.

## 4. HTTP bodies, reports and credential fields

This section fixes the shared server/runner adapter contract. The signed header,
assignment, HPKE framing and verification order in §§1–3 are unchanged. Neither a
runner request nor a report supplies a job definition, credential value, runner
override, slot ordinal or new send authority.

### 4.1 Bodies and responses

All three routes use `POST`, with no query string, `Content-Type:
application/json` (an optional `charset=utf-8` is permitted) and no content
encoding. Bodies are UTF-8 JSON objects. Duplicate keys, floats, non-finite
numbers, non-scalar strings, unsafe integers and unknown fields refuse. JSON
whitespace and key order may vary; the signed `body_sha256` always commits the
exact received bytes, not a re-encoding. Claim and started bodies are at most
4096 bytes. An empty byte string is not the JSON object `{}`.

| Route | Exact body | Success |
| --- | --- | --- |
| `/runner/v1/claim` | `{}` | `200` with the exact §2 assignment body, or `204` with no body when no assignment is available |
| `/runner/v1/dispatches/{dispatch_id}/started` | `{}` | `204`, no body |
| `/runner/v1/dispatches/{dispatch_id}/result` | the six fields below | `204`, no body |

All responses carry `Cache-Control: no-store`. A claim waits at most 30 seconds;
there is no database transaction or row lock held during the wait. The final
selection/release transaction rechecks live authority. An empty claim still
consumes its authenticated nonce (§1). An HTTP timeout is not evidence that a
claim released nothing. Every transport retry uses a fresh signed timestamp and
nonce; replaying a signed request itself gives `runner_request_replayed`.

The result body has exactly:

| Field | Type and meaning |
| --- | --- |
| `exit_code` | integer within ±(2^53 − 1), never a boolean; the process exit status reported by the runner |
| `stdout` | Unicode scalar string |
| `stderr` | Unicode scalar string |
| `truncated` | boolean; the runner cut either stream to its output bound |
| `result_withheld` | boolean; local output checks withheld the streams |
| `redaction_count` | integer from 0 through 2^53 − 1, never a boolean; local redaction count |

The combined UTF-8 byte length of the decoded `stdout` and `stderr` is at most
the pinned job's `output.max_bytes`, not that bound per stream. Before JSON
encoding the runner bounds the streams, preserving scalar boundaries, and sets
`truncated` when it cuts output. The encoded HTTP frame is bounded separately at
`6 * output.max_bytes + 1024` bytes, including all keys and JSON escaping. The
server enforces both bounds while reading/parsing. A locally withheld report
requires both streams to be empty. Empty output is still a valid report; a
nonzero exit code is a process outcome, not an HTTP error.

The flags and local count are untrusted observations. The server independently
redacts known values, checks credential shapes on decoded streams before JSON
escaping, then applies the pinned output projection (§9.6). A local withhold
returns no output. Local truncation/withhold/count and server disposition/count
remain visible as result metadata even when projection omits stdout/stderr.
Counts remain separate; they are not added into an overflowing wire integer.
Neither a false flag nor a zero local count disables server checks.

### 4.2 One dispatch, one assignment

The `dsp_` identifier is one immutable, unique, random wire alias on the existing
UUID-backed dispatch/run record, in the same installation and team. It is
persisted before assignment. Assignment signatures, report paths and HPKE
`info` use that alias. There is no second dispatch registry or state machine.

The server selects only an admitted run, applies §11.3's final fence, and commits
`dispatching`, the alias, exact sealed/signed assignment bytes and required
outbox effects before any assignment byte leaves. The authenticated nonce and
these effects commit together. Failure to commit releases nothing. Report state
changes likewise use the shared dispatch transition path and commit atomically
with their nonce and required outbox records.

There is at most one unresolved released assignment per runner. While it is
`dispatching`, another claim returns the stored assignment bytes; it never opens
credentials again, reseals them, extends their expiry or creates an independent
assignment. Concurrent claims serialize this selection. An `outcome_unknown`
assignment blocks a new release to that runner until reconciled; a claim with
no eligible assignment returns `204`. Before returning stored credential-bearing
bytes, recheck current registration/key, installation generation and containment
authority. If those
checks fail, do not return or reseal the assignment. An expired assignment is
not returned as executable work. Expiry, a lost response or failure to receive
`started` does not establish `not_sent`: retain the original attempt and follow
§11's timeout/reconciliation path. Never make the uncertain attempt executable
again under a new alias. The runner's local journal still prevents execution of
an assignment twice (§2); receipt of a duplicate is not another execution.

A report is accepted only from the current authenticated active runner assigned
to that dispatch, within its original installation/team/generation. Unknown,
foreign and unassigned dispatches have the same refusal. A report acknowledges
that runner's observation; it cannot renew approval, execute, open, release,
reseal or authorize any other dispatch.

| Existing dispatch/report condition | Started | Result |
| --- | --- | --- |
| Assignment released, state `dispatching` | `204`; record started once | `204`; sanitize and CAS to `completed` |
| Released attempt already `completed` or reconciled, or `outcome_unknown` | `204`; no state change | `204`; retain sanitized late evidence, without overwriting terminal/unknown state |
| Same accepted report retried with fresh nonce and identical raw body hash | `204`; no additional effect | `204`; no duplicate result, evidence or event |
| Different raw result body after a result was accepted | n/a | `409 runner_result_conflict`; preserve the first report |
| No assignment was released, including `admitted`, `not_sent`, refused or cancelled | `409 runner_dispatch_state_conflict` | `409 runner_dispatch_state_conflict` |

A result need not be preceded by `started`; network reordering or a failed
started acknowledgment must not discard a real exit. Record the first accepted
result's private raw-body SHA-256 (the §1 request binding) with the sanitized
result/evidence in the same transaction; compare it on subsequent reports.
This hash is private deduplication state, never a public audit commitment.
Raw output is processed before persistence and is not retained for comparison.
Re-encoding an accepted result differently changes its raw hash and conflicts;
the runner retains its exact report bytes for retries. An `outcome_unknown` or
already reconciled row is never silently turned into `completed` by a late
report. Reconciliation alone resolves it under §11.4.

The sweeper threshold exceeds the original job timeout plus a margin. Loss of
the runner after release is uncertain even without a started report. A report's
`204` means its sanitized observation was durably accepted or already present;
it does not imply that an earlier unknown outcome has been reconciled.

### 4.3 Original-value redaction context

Server redaction uses the exact values released for this dispatch, including a
1Password value read at release. A later read of a changed vault item is not an
equivalent redaction context. Keep the original known-value context only in
transient memory, bound to this dispatch, with a deadline bounded by its original
job timeout plus sweep margin. Dispose of it on final result, expiry or
containment. Do not persist a plaintext value, create a vault cache across
dispatches, or add an undeclared sealed-value cache.

If that context is unavailable (including restart, worker loss, disposal or a
late report), withhold all returned streams with disposition reason
`release_context_unavailable`. Preserve exit status and local metadata, and
accept/deduplicate the report under §4.2. Do not reread the vault or reopen a
secret to recover a context for output. Local redaction is still required and
is not a substitute for the server check. A lost transient context trades output
availability for confidentiality; it does not authorize a new run.

### 4.4 Explicit environment fields

A job's environment credential reference is exactly
`{"$credential":"<fixed slot label>","field":"<field name>"}`. This replaces
the underspecified one-key reference, including for single-field kinds. The
slot must be declared in the job's ordered credentials. Its label remains the
fixed job label after any approved child substitution; it is not a caller-chosen
child ref or ordinal. Field names and bindings are covered by the job/1 digest,
owner confirmation and runner-local digest pin. Existing pins are not silently
rewritten; a changed definition needs confirmation and new grants/pins.

| Permitted selected fields for one slot | Shared decoder validation kind |
| --- | --- |
| `value` | `bearer` (the `header` and `query` mapping shape is identical) |
| `username`, `password` | `basic` |
| `client_id`, `client_secret` | `oauth2-client-credentials` |
| `access_key_id`, `secret_access_key`, `session_token` | `aws-sigv4` |

Each declared credential slot has at least one env field reference, so its
validation family is determined without a wire kind. Every selected field for
a slot must belong to one row; missing references, mixed families or an unknown
field refuse the job definition. A job may select a subset of a row or
bind one field to several env names. This does not limit the delivered secret
kinds. S13 validates each field against the actual scoped delivered secret's
kind and requires it to exist before release. In particular, an optional native
AWS `session_token` must exist and be nonempty when selected. No empty fallback
is permitted. Basic's empty username remains valid under the shared codec.

The plaintext of §3 is custody's sole structured UTF-8 JSON `Mapping[str,str]`
encoding. The runner chooses the validation kind above from the pinned selected
field names, decodes and validates the **whole mapping** with the shared custody
codec, then selects the named fields. The representative is only a validation
family, not authority to infer a broker kind. There is no new kind field in
`{secret_ref,sealed}`, no extra plaintext wrapper, and no runner-local codec.
Custody owns the required/optional field table and encode/decode implementation;
server and standalone runner consume the same dependency-light implementation.

Both sides refuse a missing selected field or a selected string containing NUL
before release/execution. The runner never chooses dictionary order, stringifies
an object, concatenates fields or substitutes an empty value. Parameter/fixed
env values also refuse NUL. All §9.4 environment-name, empty starting environment
and executable pin checks remain in force.

### 4.5 Transport refusals and implementation boundary

Errors are JSON `{"detail":{"code":"<code>"}}`, with no raw body, output,
credential, identifier lookup detail or exception text. The §1 verification
order remains authoritative; bounded transport framing is checked before
reading an unbounded body. Result frames have a global pre-authentication cap of
`6 * 16 MiB + 1024` bytes (the maximum job output bound); after authentication,
resolve dispatch scope and enforce its smaller pinned bound. Validate the
endpoint body, then apply the locked
state/dedup checks. Failed requests never return assignment bytes or accept a
result. Successful empty/no-effect requests consume the nonce; effects and
nonce insertion are atomic. A transaction failure rolls back both.

| HTTP | Code / condition |
| --- | --- |
| `400` | `runner_request_invalid` for invalid header/signature or claim/started body; `runner_request_binding_mismatch` for origin/method/path/body mismatch; `runner_result_invalid` for malformed result fields or decoded stream bound |
| `401` | `runner_unknown` for an unknown/inactive runner or non-current signing key |
| `404` | `runner_dispatch_unknown` for unknown, foreign or unassigned dispatch |
| `409` | `runner_request_stale`, `runner_request_replayed`, `runner_dispatch_state_conflict`, or `runner_result_conflict` |
| `413` | `runner_request_too_large` for the bounded body frame (an oversized signed header remains `runner_request_invalid` under §1) |
| `415` | `runner_request_invalid` for unsupported media type or content encoding |
| `503` | `runner_unavailable` for a required authority/database/custody dependency failure; log the real failure without output or values |

These adapter errors are not new public hook refusal-code values. Reports do not
create another secret-use intent. Existing dispatch transitions/evidence and
outbox rules apply; publication uses the hook contract's permitted commitments,
not the private report hash or raw output.

Activation requires reviewed server routes, nonce/CAS/outbox integration, job
env validation/confirmation, shared-codec packaging and runner consumption.
Focused runtime proofs must cover lost claim responses/concurrent claims,
containment/key changes before replay, identical/conflicting results, late
reports after sweeping/reconciliation, atomic rollback, exact original-value
redaction (including changed 1Password items and unavailable context), multipart
env fields and NUL. The public HTTP vector fixes body bytes, bounds, field
families and status expectations; it does not replace those runtime proofs.
Short-lived mint authority and the separately guarded derived paths are unchanged.

## Conformance

`docs/vectors/secrets-runner-protocol-v1.json` gives the keys (as fixed test
seeds), signed requests and assignments with their exact signing bytes, sealed
credentials with the recipient key, and refusal cases for every step above:

- a wrong domain prefix;
- a non-canonical payload;
- a duplicate key;
- a float, an integer outside the safe range and a lone surrogate;
- a timestamp with non-ASCII digits;
- a credential item with an extra field or a non-canonical `sealed`;
- a short identifier;
- another method, path, body or origin;
- an assignment for another runner;
- an expired assignment, and one whose lifetime exceeds 300 seconds;
- a replay;
- a credential opened under another dispatch.

The credential plaintexts in the vector are fixtures, not secrets.
`naapp/secrets/tests/test_runner_protocol_vectors.py` consumes every case.

`docs/vectors/secrets-runner-http-v1.json` fixes §4 body bytes and raw hashes,
combined stream bounds, safe metadata, declared env-field families and result
status examples. The same contract reference reader consumes these cases;
server/runner runtime integration proofs remain required by §4.5.
