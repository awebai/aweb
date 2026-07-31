# Protocol conformance vectors

Status: **canonical index for public JSON fixtures in `docs/vectors/`**. Each
fixture's lifecycle below is part of its authority: current protocol vectors,
experimental A2A vectors, and compatibility vectors do not make the same
stability promise.

These files prevent cross-language drift in canonical JSON, signing and base64,
DID/key derivation, trust continuity, team-auth request binding, E2E wire bytes,
address claims, and optional A2A interoperability.

## Authority and copies

- `docs/vectors/*.json` is the public root authority for the 15 fixtures indexed
  here.
- `server/docs/vectors/` contains compatibility/package copies used by older
  server consumers. Those files are not a second authority and their presence
  does not mean every root fixture is mirrored there.
- `cli/go/internal/conformance/vectors/` contains consumer-local fixtures and
  compatibility copies needed by the Go package. Public protocol changes start
  from the root authority when one exists.
- `test-vectors/app-manifests/` contains digest-pinned experimental app-manifest
  snapshots. They are documented by [`app-manifest.md`](../app-manifest.md), not
  silently promoted into the identity/trust vector family.

A duplicate path must either be checked against its authority or clearly remain
a compatibility copy. File-name equality alone is not proof that bytes match.

## Current protocol fixtures

These fixtures govern shipped non-A2A protocol behavior.

### `message-signing-v1.json`

Canonical UTF-8 message payloads and expected Ed25519 signatures, including
variants with and without stable-ID fields. Signatures use raw standard base64
without padding.

### `identity-log-v1.json`

Canonical identity-only `register_did` and `rotate_key` envelope payloads,
state-hash inputs and hashes, entry hashes, and expected Ed25519 signatures.

### `identity-log-negative-v1.json`

Shared positive and negative DID-log verifier outcomes. Each `cases` entry feeds
a `log_head` and optional cached head to the verifier; `log_cases` feed full
logs to the genesis-anchored chain verifier. Go and TypeScript consume the bytes
together and assert `OK_VERIFIED`, `OK_DEGRADED`, or `HARD_ERROR` so
authorization, state-hash, and anchoring semantics cannot drift.

### `identity-log-raw-wire-v1.json`

Complete wire JSON for decoder-level sequence-number cases. Both runtimes reject
both cases, but the fixture records positive per-runtime expectations because
they reject at different layers. Go rejects a fractional sequence during typed
JSON decoding while TypeScript parses it and rejects it at the safe-integer
guard. Above 2^53, 64-bit Go decodes and rejects at that guard while 32-bit Go
cannot represent the value during decoding.

### `pin-store-raw-wire-v1.json`

Raw YAML pin-store bytes and per-runtime outcomes plus error substrings. Each
runtime feeds the same bytes through its own load-and-validate path (Go
`LoadPinStore`, TypeScript `PinStore.fromYAML`). Three cases record the measured
compatibility divergence for non-string mapping keys: Go rejects them while
`js-yaml` coerces them to strings and TypeScript accepts. The divergence is not
reachable through the normal `aw`-owned write path.

### `stable-id-v1.json`

Canonical `did:key` to stable `did:aw` derivation.

### `rotation-announcements-v1.json`

Canonical single-link and chained rotation-announcement payloads with expected
Ed25519 signatures.

### `dns-txt-v1.json`

Canonical `_awid.<domain>` TXT record names and values, including the default
public registry and explicit `registry=` declarations.

### `atomic-address-claim-v1.json`

Cross-language canonical bytes, proofs, and digests for atomic address claims.

### `atomic-address-claim-conflict-codes-v1.json`

The complete stable conflict-code vocabulary shared by AWID route tests and Go
client mapping.

### `e2ee-v2-cross-language.json`

Deterministic Go/Python encrypted-v2 wire fixture. It contains test-only private
keys that must never be reused outside tests.

### `team-auth-envelope-v2.json`

Current request-bound team-auth canonical bytes and Ed25519 signatures. It
includes a neutral OSS task request and a hosted-route interoperability case;
negative cases cover cross-endpoint/origin replay, body tampering, and a missing
protocol version. The aweb server, Go conformance suite, and public naapp
verifiers consume it. See
[`team-auth-envelope-v2.md`](../team-auth-envelope-v2.md).

## Experimental and compatibility A2A fixtures

A2A is shipped but experimental and optional. These fixtures are release gates
for that surface, not promises that A2A belongs to the default aweb journey.

### `a2a-v1.json` — experimental current protocol fixture

Pins the upstream A2A v1.0.1 source commit, proto-derived field sets, Agent Card
shapes/digests, and JSON-RPC request/response cases used by the current CLI and
gateway. Generated cards are checked against it.

### `a2a-bridge-envelope-v0.json` — current compatibility fixture

Pins the current zero-SDK bridge envelope's semantic section order and required
`a2a-task`/`a2a-reply` fields. The `v0` name is deliberate: it is the gateway's
current compatibility envelope, not a general A2A standard and not a stable v1
wire promise. Prose wording is intentionally not byte-pinned.

### `a2a-awid-publication-v1.json` — digest-only fixture

Pins publication/delegation canonical JSON, assertion digest construction, and
conflict-code order. Its `signature` strings are deterministic placeholder
bytes. They are **not valid Ed25519 verification fixtures** and must not be used
to claim signature verification coverage.

Real cryptographic route tests generate Ed25519 keypairs/signatures at runtime
in `awid/tests/test_a2a_publication_route.py`. The digest-only fixture proves
byte/digest parity; those tests prove verification and authority enforcement.
Both are required.

## Consumer-local extension fixtures

Two extension fixtures currently live under
`cli/go/internal/conformance/vectors/` because that package owns their direct
consumer harness:

- `app-manifest-interpretation-v1.json` — experimental manifest interpretation
  before dynamic signing; see [`app-manifest.md`](../app-manifest.md).
- `app-emit-credential-v1.json` — experimental app-event auth canonical bytes;
  see [`app-events.md`](../app-events.md).

They are current for their experimental surfaces. Their location does not make
old restructuring documents authoritative, and they do not imply a hosted
dynamic gateway ships.

## Encoding classes

Decoder strictness follows the producer and field format; it is not a global
base64 consistency sweep.

| Class | Examples | Required behavior |
|---|---|---|
| Remote signatures | Message, identity log, rotation, A2A assertion, E2E signature fields | Raw standard base64 without padding; malformed remote signatures fail before cryptographic acceptance. |
| E2E binary protocol fields | Public keys, ciphertext, nonce, encapsulated/wrapped keys | Raw standard base64 as defined by the encrypted-v2 wire contract. |
| Team-certificate transport envelope | `X-AWID-Team-Certificate` | Padded standard base64 for compatibility with existing producers. |
| Team-auth signed-payload header | `X-AWEB-Signed-Payload` | Base64url without padding of exact canonical JSON bytes. |
| Local private-key material | PEM and CLI partial-init files | Follow the local file format, validate decoded size and identity binding, and do not apply remote-signature syntax blindly. |
| Public content digests | A2A Agent Card digest | `sha256:<lowercase hex>` over the specified canonical card bytes. |
| Signed assertion digests | A2A delegation/publication assertion digest | `sha256:<raw-standard-base64-no-padding>` over the contract-defined bytes. |

Canonical JSON uses sorted object keys, compact separators, literal UTF-8, and
no insignificant whitespace. A fixture may further constrain default-field
materialization or array ordering; its governing contract wins.

## Validation

The vectors are consumed from their canonical `docs/vectors/` paths by the
relevant component suites. Go's conformance package embeds its release copy;
its test first requires that copy to be byte-identical to the canonical corpus.
Focused commands from the repository root:

```bash
make test-a2a

cd awid
uv run --frozen pytest -q \
  tests/test_conformance_vectors.py \
  tests/test_atomic_claim.py \
  tests/test_atomic_claim_route.py \
  tests/test_a2a_publication_route.py

cd ../server
uv run --frozen pytest -q \
  tests/test_identity_conformance_vectors.py \
  tests/test_team_auth_envelope.py \
  tests/test_e2ee_crypto_helpers.py

cd ../cli/go
go test ./internal/conformance ./a2a ./a2agw ./awid -count=1

cd ../../../channel-core
npm test -- \
  test/registry.test.ts test/pin_store_raw_wire.test.ts test/log_rollback.test.ts
```

TypeScript trust/pin-store consumers run through the normal channel-core test
suite after its declared npm dependencies are installed:

```bash
cd channel-core
npm test
```

A vector change is incomplete until every listed consumer for that fixture
passes and the lifecycle label above still describes what the bytes prove.
