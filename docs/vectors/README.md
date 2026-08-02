# Protocol conformance vectors

Status: **canonical index for public JSON fixtures in `docs/vectors/`**. Each
fixture's lifecycle below is part of its authority: current protocol vectors,
experimental A2A vectors, and compatibility vectors do not make the same
stability promise.

These files prevent cross-language drift in canonical JSON, signing and base64,
DID/key derivation, trust continuity, team-auth request binding, E2E wire bytes,
address claims, and optional A2A interoperability. Identity and continuity
semantics are governed by the [aweb implementation SOT](../aweb-sot.md) and
[identity-key verification](../identity-key-verification.md).

## Authority and repository inventory

`docs/vectors/*.json` is the only public protocol-vector authority for the 19
fixtures indexed here. Python, Go, TypeScript, package references, and generated
references consume these root bytes directly or through the one classified
package copy below. An unclassified hand-maintained copy is forbidden even when
its bytes happen to match; `make test-vector-provenance` rejects a returning
mirror or unclassified consumer-local link.

The other tracked vector directories have disjoint, explicit purposes:

| Directory | Classification |
|---|---|
| `cli/go/internal/conformance/vectors/` | Consumer-local Go fixtures plus the byte-enforced `team-auth-envelope-v2.json` package copy linked by the currently pinned naapp reference generator. |
| `naapp/folio/tests/vectors/` | App test snapshots; `app-emit-credential-v1.json` is byte-checked against its Go consumer authority. |
| `naapp/library/tests/vectors/` | App snapshots plus Library blueprint input/output goldens; the app-emit snapshot is byte-checked. |
| `test-vectors/` | Repository-level policy, blueprint, app-manifest, and packaging fixtures governed by their own indexes. |

There is deliberately no server-local public-vector package copy. Server wheels
do not need public test vectors at runtime, while server source tests load the
repository-root authority. `test-vectors/app-manifests/` contains
digest-pinned experimental app-manifest snapshots documented by
[`app-manifest.md`](../app-manifest.md); they are not silently promoted into the
identity/trust vector family.

## Current protocol fixtures

These fixtures govern shipped non-A2A protocol behavior.

### `message-signing-v1.json`

Canonical UTF-8 message payloads and expected Ed25519 signatures, including
variants with and without stable-ID fields. Signatures use raw standard base64
without padding.

### `identity-log-v1.json`

Canonical identity-only `register_did` and `rotate_key` envelope payloads,
state-hash inputs and hashes, entry hashes, and expected Ed25519 signatures.
The removed server-only corpus encoded the superseded address-bearing
`operation=create` state (`server`, `address`, and `handle`) and a rotation that
continued that state. Those two entries were examined individually and are not
valid current identity-only cases, so merging them would weaken the canonical
contract rather than preserve coverage. Legacy `create` parsing remains an
explicit verifier compatibility test; it is not emitted or represented as a
current positive vector.

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

Deterministic identities, X25519 test-only private material, identity-signed key
assertions, and encrypted mail envelopes for Python↔Go interoperability. Python
decrypts the Go envelope and Go decrypts the Python envelope; both consumers
assert plaintext is absent from the outer envelope. Policy fixtures under
`test-vectors/e2e/` separately pin stored content modes, metadata-only fields,
current/deprecated plaintext flags, and rollout requirements; server tests
consume all three fixtures. The private material must never be reused outside
tests.

### `team-auth-envelope-v2.json`

Current request-bound team-auth canonical bytes and Ed25519 signatures. It
includes a neutral OSS task request and a hosted-route interoperability case;
negative cases cover cross-endpoint/origin replay, body tampering, and a missing
protocol version. The aweb server, Go conformance suite, and public naapp
verifiers consume it. See
[`team-auth-envelope-v2.md`](../team-auth-envelope-v2.md).

### `federation-origin-ip-v1.json`

Immutable pre-activation strict-registry origin, IP-class, all-answer,
direct-peer/trusted-proxy source selection, and pinned-dial cases from the ACKed `aweb-aazd.2.1` contract. Production origins
are HTTPS origin-only and reject literal IPs and every non-global answer; the
HTTP/private exception requires all three isolated-development conditions. The
transport cases pin hostname TLS/SNI with an approved connect IP and prohibit a
second resolution, redirects, ambient proxy state, cookies, and credentials.
These bytes authorize no production resolver behavior by themselves.

### `federation-discovery-v1.json`

Immutable canonical-address, typed DNS walk, public-default selection,
authority-statement canonical JSON/digest, and selected-registry lookup cases.
NXDOMAIN/NODATA/no-AWID answers walk or select the public default, while DNS
failures and malformed/ambiguous AWID records never fall back. The public
default's controller comes from its exact namespace row. These bytes authorize
no production discovery behavior by themselves.

### `federation-authority-state-v1.json`

Immutable selected-policy, bound, checkpoint/CAS, complete cohort tuple,
PostgreSQL lease/fence, claim-independent evidence reuse, exhaustive stable
error, and mandatory-mutation cases from `aweb-aazd.2.1`. It references the
three canonical root identity-log fixtures by path, byte count, and SHA-256;
no log body is copied. The selected 60-second value is a receiver reuse ceiling,
not an external freshness SLA, and contacts are identity-bound with no automatic
transfer. These bytes authorize no storage, ingress, migration, or activation
behavior by themselves.

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

## Experimental extension fixtures

### `mutation-hook-call-sites-v1.json`

Machine-readable source path, enclosing function, and literal event for every
current `fire_mutation_hook` call. Duplicate rows are significant: they preserve
call-site multiplicity when one function emits the same event from multiple
branches. The source-derived checker rejects added, removed, dynamic, or
otherwise unsupported call shapes. See [`aw-hooks-sot.md`](../aw-hooks-sot.md).

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

| Class | Production sites or examples | Required behavior and reason |
|---|---|---|
| Remote signatures | TypeScript `identity/signing.ts` (message envelopes), `identity/trust.ts` (rotation/replacement announcements), and `identity/registry.ts` (DID-log heads); Go `awid/{signing,rotate,a2a_publication,certificate,e2ee_keys,e2ee_messages,atomic_address_claim,stable_identity}.go` signature decodes | Raw standard base64 without padding, with Go/TypeScript acceptance parity. Malformed remote signatures fail before cryptographic acceptance, so rejection does not depend on a verifier accepting an empty signature. |
| E2E binary protocol fields | Go `awid/e2ee_keys.go`, `awid/e2ee_messages.go`, and `cmd/aw/id_encryption_key.go` public-key, ciphertext, nonce, encapsulated-key, and wrapped-key decodes | Raw standard base64 because the encrypted-v2 wire contract defines those fields that way. These are protocol bytes, not signature-verdict sites. |
| Team-certificate transport envelope | TypeScript `identity/certificate.ts` encoder and Go `awid/certificate.go` header encoder/decoder | Padded standard base64. TypeScript emits padding and has no header decoder; switching Go to raw decoding would reject every TypeScript-produced certificate header. |
| Team-auth signed-payload header | `X-AWEB-Signed-Payload` | Base64url without padding of exact canonical JSON bytes. |
| Local private-key material | TypeScript `identity/keys.ts` PEM loader and Go `cmd/aw/init_apikey.go` partial-init state | Follow the file format: PEM is padded and line-wrapped; Go partial-init state uses padded standard base64. Both paths validate decoded size and identity binding. Remote-signature strictness does not apply. |
| Public content digests | A2A Agent Card digest | `sha256:<lowercase hex>` over the specified canonical card bytes. |
| Signed assertion digests | A2A delegation/publication assertion digest | `sha256:<raw-standard-base64-no-padding>` over the contract-defined bytes. |

Canonical JSON uses sorted object keys, compact separators, literal UTF-8, and
no insignificant whitespace. A fixture may further constrain default-field
materialization or array ordering; its governing contract wins.

## Validation

The vectors are consumed from their canonical `docs/vectors/` paths by the
following complete source inventory. Go reads public protocol fixtures from the
repository root except for the classified team-auth package copy, whose bytes are
compared to root before any case executes. The Python and Go federation readers
independently pin each reviewed federation file's exact byte count and SHA-256
before schema checks; deletion, semantic reversal, unknown row fields, and
reference duplication are mutation-tested failures.

| Public fixture | Actual source consumers |
|---|---|
| `a2a-awid-publication-v1.json` | Python AWID `test_a2a_publication_route.py`; Go AWID `a2a_publication_test.go`; Go shared `conformance_test.go` |
| `a2a-bridge-envelope-v0.json` | Go gateway `envelope_vector_test.go` |
| `a2a-v1.json` | Go A2A `card_test.go`; Go gateway `gateway_rpc_test.go`; Go shared `conformance_test.go` |
| `atomic-address-claim-conflict-codes-v1.json` | Python AWID `test_atomic_claim_route.py`; Go AWID `atomic_address_claim_test.go` |
| `atomic-address-claim-v1.json` | Python AWID `test_atomic_claim.py`; Go AWID `atomic_address_claim_test.go` |
| `dns-txt-v1.json` | Python AWID `test_conformance_vectors.py`; Python aweb `test_identity_conformance_vectors.py`; TypeScript channel-core `registry.test.ts` |
| `e2ee-v2-cross-language.json` | Python aweb `test_e2ee_crypto_helpers.py` and pre-activation federation harness; Go AWID `e2ee_cross_language_test.go` |
| `identity-log-negative-v1.json` | Python AWID `test_identity_log_verify.py`; Go shared `identity_log_negative_test.go`; TypeScript channel-core `registry.test.ts` |
| `identity-log-raw-wire-v1.json` | Python AWID `test_identity_log_verify.py`; Go shared `identity_log_raw_wire_test.go`; TypeScript channel-core `registry.test.ts` |
| `identity-log-v1.json` | Python AWID `test_conformance_vectors.py`, `test_did.py`, `test_external_registry.py`, and `test_identity_log_verify.py`; Python aweb `test_identity_conformance_vectors.py` and pre-activation federation harness; Go AWID `registry_register_test.go`, `federation_authority_test.go`, and `federation_external_registry_test.go`; Go shared `conformance_test.go`; TypeScript channel-core `registry.test.ts` and `log_rollback.test.ts` |
| `message-signing-v1.json` | Python AWID and aweb conformance tests, including the pre-activation federation harness; Go shared `conformance_test.go` |
| `mutation-hook-call-sites-v1.json` | Build guard `scripts/check-extension-docs.py` |
| `pin-store-raw-wire-v1.json` | Go shared `pin_store_raw_wire_test.go`; TypeScript channel-core `pin_store_raw_wire.test.ts` |
| `rotation-announcements-v1.json` | Python AWID and aweb conformance tests; Go shared `conformance_test.go` |
| `stable-id-v1.json` | Python AWID and aweb conformance tests; Go shared `conformance_test.go` |
| `team-auth-envelope-v2.json` | Python aweb `test_team_auth_envelope.py`; folio `test_auth_v2_envelope.py`; Go shared `conformance_test.go`, including its root-equality check for the managed embedded copy |
| `federation-origin-ip-v1.json` | Python AWID `test_federation_authority_vectors.py` and `test_external_authority.py`; Python aweb pre-activation federation harness; Go AWID `federation_authority_test.go`; Go shared `federation_authority_vectors_test.go` |
| `federation-discovery-v1.json` | Python AWID `test_federation_authority_vectors.py` and `test_external_authority.py`; Python aweb pre-activation federation harness; Go AWID `federation_authority_test.go`; Go shared `federation_authority_vectors_test.go` |
| `federation-authority-state-v1.json` | Python AWID `test_federation_authority_vectors.py`; Python aweb `test_federation_authority_core.py`, `test_federation_authority_schema.py`, and pre-activation federation harness; Go AWID `federation_authority_test.go`; Go shared `federation_authority_vectors_test.go` |

Package and reference enforcement is also explicit: the root `Makefile` runs the
provenance baseline and mutations from `make test`; the aweb package-data test
builds and inspects both wheel and sdist; folio's `aweb_layout.py` binds its
cross-repository reader to an identified aweb root; and the pinned naapp
reference generator and golden point at the managed, root-checked team-auth
copy.

The provenance gate inventories every tracked vector directory; rejects
same-name or JSON-equal public mirrors regardless of their directory spelling;
verifies managed package and app snapshots; checks the exact vector-name set and
root path markers for every source consumer; rejects unclassified code
consumers; and proves those checks with ten mutations. Focused commands from the
repository root:

```bash
make test-vector-provenance
make test-a2a

cd awid
uv run --frozen pytest -q \
  tests/test_conformance_vectors.py \
  tests/test_federation_authority_vectors.py \
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
