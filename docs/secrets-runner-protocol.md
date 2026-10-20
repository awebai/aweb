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
  A verifier re-canonicalizes the parsed payload and requires the exact bytes it
  received.
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
   canonical base64url string; the payload is canonical JSON with exactly the
   fields above, `v` 1, the right `type`, a well-formed `runner_id`, a 16-byte
   nonce and a valid timestamp.
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

1. **Shape** (`assignment_invalid`): the body and payload have exactly the
   fields above, canonical and well-typed, with a well-formed `runner_id` and
   `dispatch_id`.
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

## Conformance

`docs/vectors/secrets-runner-protocol-v1.json` gives the keys (as fixed test
seeds), signed requests and assignments with their exact signing bytes, sealed
credentials with the recipient key, and refusal cases for every step above:

- a wrong domain prefix;
- a non-canonical payload;
- a duplicate key;
- a float;
- a timestamp with non-ASCII digits;
- a short identifier;
- another method, path, body or origin;
- an assignment for another runner;
- an expired assignment, and one whose lifetime exceeds 300 seconds;
- a replay;
- a credential opened under another dispatch.

The credential plaintexts in the vector are fixtures, not secrets.
`naapp/secrets/tests/test_runner_protocol_vectors.py` consumes every case.
