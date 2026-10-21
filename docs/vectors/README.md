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

`docs/vectors/*.json` is the only public protocol-vector authority for the 42
fixtures indexed here. Python, Go, TypeScript, package references, and generated
references consume these root bytes directly or through the two classified
package copies below. An unclassified hand-maintained copy is forbidden even when
its bytes happen to match; `make test-vector-provenance` rejects a returning
mirror or unclassified consumer-local link.

The other tracked vector directories have disjoint, explicit purposes:

| Directory | Classification |
|---|---|
| `cli/go/internal/conformance/vectors/` | Consumer-local Go fixtures plus the byte-enforced `team-auth-envelope-v2.json` package copy linked by the currently pinned naapp reference generator. |
| `naapp-lib/src/aweb_naapp/hooks/catalog-v1.json` | The byte-enforced package copy of `hook-catalog-v1.json`, shipped in the naapp-lib wheel so an installed app loads the catalog (`aweb_naapp.hooks.catalog.packaged_catalog`) with no repository checkout. |
| `naapp/folio/tests/vectors/` | App test snapshots; `app-emit-credential-v1.json` is byte-checked against its Go consumer authority. |
| `naapp/library/tests/vectors/` | App snapshots plus Library blueprint input/output goldens; the app-emit snapshot is byte-checked. |
| `naapp/secrets/vectors/` | secrets' app-internal contracts: the `aweb.secrets.use-approval/1` request object under B2's prefix, and the transition-to-hook-action table checked against `hook-catalog-v1.json`. Each file is consumed by a test in `naapp/secrets/tests/`. |
| `test-vectors/` | Repository-level policy, blueprint, app-manifest, and packaging fixtures governed by their own indexes. |

There is deliberately no server-local public-vector package copy. Server wheels
do not need public test vectors at runtime, while server source tests load the
repository-root authority. `test-vectors/app-manifests/` contains
digest-pinned experimental app-manifest snapshots documented by
[`app-manifest.md`](../app-manifest.md); they are not silently promoted into the
identity/trust vector family.

## Accepting protocols awaiting client rollout

### `awid-controller-request-v2.json`

Controller HTTP envelopes bind the configured registry audience, protocol type,
method, external path/query and exact body, retaining the operation discriminator.
The real AWID route consumes this vector, including wrong-audience and team-auth
purpose refusals. Legacy forms remain accepted and measured until the operator's
cutoff; clients emit this shape only after the accepting registry is deployed.
See [AWID controller requests](../awid-controller-requests.md).

## Current protocol fixtures

These fixtures govern shipped non-A2A protocol behavior.

### `team-certificate-status-v1.json`

Anonymous status response for one published certificate, public or private team:
exactly the team ID, current team key, active/revoked status, and revocation time.
Unknown team and unknown/mismatched certificate share one 404 response. The AWID
real-route tests consume these bytes; active status does not authenticate an
old-key certificate after rotation. See [the team contract](../awid-sot.md#teams).

### `team-server-record-v1.json`

`aweb.team-server/1` records: a team-key-signed binding of a team to its
coordination server URL. Signing bytes are the `aweb.team-server/1` domain
prefix and a newline, followed by canonical JSON of the record. Valid cases
carry their exact signing bytes; refused cases carry the stable refusal code
and AWID status (missing prefix, non-current key, team mismatch, far-future
`issued_at`, `issued_at` with non-ASCII digits or an impossible date, not newer
than the stored record, plain http outside loopback).
Seeds are public test material. The AWID real-route tests consume these
bytes. See [the team contract](../awid-sot.md#teams).

### `principal-attestation-v1.json`

Signed bytes and signatures of the team-key-signed `aweb.team-custodian/1`,
`aweb.member-custody/1` and `aweb.member-person/1` records, record refusals, the
`aweb.principal-attestation/1` header, and the verification cases of
[principal attestation](../principal-attestation.md) §4 with their refusal
codes. Keys are fixed seeds, so every signature can be recomputed. The AWID
codec, the `aweb_naapp` verifier and aw's Go record codec
(`attestation_records_test.go`) consume these bytes.

### `secrets-runner-protocol-v1.json`

The secrets runner protocol of
[secrets-runner-protocol.md](../secrets-runner-protocol.md): signed
`aweb.secrets.runner-request/1` headers and `aweb.secrets.runner-assignment/1`
bodies with their exact signing bytes, credentials sealed with HPKE
(X25519, HKDF-SHA256, ChaCha20-Poly1305, `dispatch_id` as `info`), and a
refusal case for every verification step on either side. Signing keys are
fixed seeds; sealed values were generated once and are checked by opening them.
Credential plaintexts are fixtures. secrets' `test_runner_protocol_vectors.py`
consumes every case.

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
includes a neutral OSS task request, the same request carrying a signed
`trace_id` member (an additive case: extra signed members are signed and
ignored by the auth layer, which is how aw-hooks carries its trace), and a
hosted-route interoperability case; negative cases cover cross-endpoint/origin replay, body tampering, and a missing
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

## Agreed fixtures ahead of implementation

### `page-format-v1.json`

The frozen `aweb.page/1` page format (aweb-acgg.7): the host limits, named base
pages, and positive and negative cases, each given as a base page plus a small
patch, raw bytes, or a generated tree. Every case expects a verdict and, when
invalid, at least the listed errors, each a layer (`limits`, `schema`, `lint`),
a stable code and a JSON pointer. Limits run before the schema and the schema
before lint, so a case reports only its first failing layer. Hostile-corpus
cases that are structurally valid carry a `render` expectation for the shared
renderer, which this file names but does not test. `bundle_hash` pins the
bundle decision-card digest across languages. The reference consumer is
`aweb_naapp.pages` in `naapp-lib/tests/pages/`. See
[the page format](../page-format.md).

### `app-task-authorization-v1.json`

The member-signed `aweb.app-task-authorization/1` (aweb-acgg.8): task body
digests, domain-prefixed signing bytes and base64url signatures under fixed
test keys, verification cases at a pinned clock with the bindings each is
checked against and its expected refusal code, strict-JSON refusals, and task
body bounds. The reference consumers are `aweb_naapp.runtime.task_requests` in
`naapp-lib/tests/runtime/` and `aw`'s signer in `cli/go/awid/`. See [app task requests](../app-task-requests.md).

### `app-request-credential-v1.json`

The `app-request` purpose of the app credential family (aweb-acgg.8): one
request's signed payload, canonical bytes, signature and headers, plus
request-level refusals for the task service's verifier. The reference consumer
is `aweb_naapp.runtime.task_requests`. See
[app task requests](../app-task-requests.md) §2.

### `task-answer-v1.json`

Conditional task answers (aweb-acgg.8): answer text digests, the app's stage
receipt with its refusals, and ordered steps for a decision task (eligible
answerers, stage-gate refusals, replay, reopen and conflicts) and a plain
task, with the expected result of each. The answer digests are checked by `aweb_naapp.runtime.task_requests`; the
sequence is for the task service. See
[app task requests](../app-task-requests.md) §4.

### `page-action-prepare-v1.json`

Intent preparation (aweb-acgg.8): prepare responses with their task digests and
authorization bindings, the member's completed and signed payload, the
signer's pre-signing checks with their refusals, and ordered prepare, submit,
replay and renewal steps with the expected result of each. The responses and
checks are checked by `aweb_naapp.runtime.task_requests`; the sequence is for a
pages naapp. See [page actions](../page-actions.md) §3.

### `page-proposal-v1.json`

`proposal_sha256` for page proposals (aweb-acgg.8): canonical bytes and
digests over a record's collection, id and value, a bundle built from item
digests, and value refusals. The reference consumers are `aweb_naapp.pages` in
`naapp-lib/tests/pages/` and `cli/go/awid/`. See
[the page format](../page-format.md) §5.

### `decision-display-v1.json`

What a decision card shows (aweb-acgg.8): the host's evidence carries the
task's signed `options` and `fields`, and each case gives a card's options and
a record value with the expected display, in bound order with bound labels and
formats, or the reason the card is refused (options differ, a bound field is
missing, a money field has no ISO 4217 currency). It is for the shared
renderer and its host. See [page actions](../page-actions.md) §5.

### `approval-request-v1.json`

The approval primitive's `request_sha256` and challenge binding
(aweb-acgg.8, aweb-acgh.4): the covered canonical bytes with the policy
wrapper, digests for page decisions and a generic request, challenge bindings
with and without a task answer and per candidate, the requester rule at mint
and decide each way, and refusals. Its consumer is the approval primitive in
`aweb_naapp`. See [page actions](../page-actions.md) §6.

### `agent-status-v1.json`

The signed agent status document a status host publishes for an agent
(aweb-acah.3, `PUT /v1/agents/{alias}/status`). It pins the canonical bytes,
the base64url `signed_payload`, and the Ed25519 signature (raw standard base64
without padding) for a fixed test key. Positive cases cover each `reachable`
value, the byte caps measured after UTF-8 encoding, the 15-minute validity
ceiling, and a local identity named by its `did:key`. Each negative carries its
evaluation time and one expected refusal code. They cover unknown top-level and
nested fields, missing fields, enums, a seq that is not a safe positive integer,
the text caps, control characters, the validity window, clock skew, expiry, a
stale seq, a publisher that is not the signer, a wrong signature, oversize and
non-canonical bytes, and a mail payload offered as a status. A cross-type entry
is a producer construction check: message bytes built with `canonical_payload`
never equal status bytes. Its description overstates this as message
verification; ingress separation is the required `type` at every route. The server and
the OATS publisher agreed these bytes at `1aadc0914` before either
implemented them; changing them needs a new version.

### `agent-activity-v1.json`

The signed agent activity event an agent's host publishes during a turn
(aweb-acah.2, `POST /v1/agents/me/activity`; contract in
[`agent-activity.md`](../agent-activity.md)). It pins the canonical bytes, the
base64url `signed_payload`, and the Ed25519 signature (raw standard base64
without padding) for fixed agent, other and grant-session test keys. Each case
carries its evaluation time and, where it differs from the default, the
authenticated caller the event binds to. Positive cases cover each phase, an
unattributed session, a tool without a summary, the byte caps measured after
UTF-8 encoding, the 60-second validity edge, the clock-skew edge, a local
identity without a stable id, and a grant session signer. Each negative has one
expected refusal code and, apart from the structural oversize and wrong-type
cases, exactly one fault: oversize and non-canonical
bytes, a wrong signature, a chat message and a status offered as activity,
unknown and missing fields, each shape rule, the server-only `busy_elsewhere`
and `cleared` phases, signer, team and stable-id bindings, the validity window, clock skew and
expiry. Two route refusals pin the shared 404 for an absent session and a
session the caller is not in. A cross-type entry is a producer construction
check: message bytes built with `canonical_payload` never equal activity bytes.
Ingress separation is the required `type` at every route. Athena and the
protocol reviewer ACKed these bytes at `4502edac0` before either side
implemented them; changing them needs a new version.

### `hook-catalog-v1.json`

The `aweb.hooks` catalog, version 1 (aweb-acgh.16.1; contract in
[`hook-events.md`](../hook-events.md)). It names the five hooks with their
firing class, producer kinds, audit-critical rule and precedence. It holds each
hook's flat payload allowlist: value types with patterns and bounds, required
fields, enums (including the 32 `post-secret-use-hook` refusal codes), the
conditional rules, each `post-governance-hook` act's fixed direction, every
`post-mutation-hook` type with its own fields, and the `post-command-hook`
command classes with their local effects. Positive cases validate. Each
negative case has one fault and its expected error and field: an unknown hook
or field, a missing field, a bad value, a float, a nested object, free text in a
reference, a rule violation, a direction that differs from the catalog's, and an
effect outside its command class. A payload that this file may not hold, such
as a float, is given as JSON text in `payload_json`. The strict reader in
`aweb_naapp.hooks.catalog` refuses the whole file on any unknown key, duplicate
key, float or unresolved reference. Any payload change, including an addition,
is a new catalog version. secrets' `test_hook_actions_vector.py` checks its
transition-to-action table against it.

Decision 73 deliberately re-freezes the pre-deployment secret-use shape in
place: `request_sha256` and `params_sha256` have HMAC-SHA-256 meaning, and
`completed`/`stored_as_secret` requires `derived_secret_id` and
`derived_grant_id` together, forbidden elsewhere. The paired creation case and
single-fault negatives are part of this vector. Its managed package copy and
secrets' transition examples change in the same stack. The envelope vector's
old plain-SHA demonstration is removed without changing signed cases;
producer MAC input/lifecycle proofs belong to K4/S13. There is no parallel
catalog version because no deployed producer or consumer uses this hook.

### `hook-binding-cases-v1.json`

Owner-activated hook bindings (aweb-acgh.16.1; contract in
[`hook-events.md`](../hook-events.md)). The scheme states the binding states and
transitions, the 60-second `active_from` pad, when an event is owed to a
binding, the audit-critical gate and what revocation does. The cases cover an
admin install that leaves bindings pending, an admin signer refused, owner
activation and the pad, an unknown catalog or hook, a new generation that
supersedes and never inherits activation, revocation's final entry and
cancelled backlog, uninstall, and the order for switching targets. A model of
the scheme in the naapp-lib tests replays every case, and the core binding
registry consumes the same cases.

## Shared naapp library fixtures

### `egress-address-v1.json`

The egress guard's address rules (`aweb_naapp.egress`, secrets lane S1). Every
address a name resolves to is checked. A floor (loopback, link-local and cloud
metadata, unspecified, multicast) is refused for every destination, internal
ones included. A public destination's IPv6 address must be global unicast or
NAT64, and IPv4 addresses embedded in NAT64, 6to4 and Teredo forms are checked
as IPv4. Internal destinations need the deploy-level `internal_destinations`
switch and an exact CIDR of bounded width that overlaps no floor range.

### `egress-url-v2.json`

The egress guard's URL contract (`aweb_naapp.egress`, secrets lane S1), used by
every naapp that calls an external service with its own credential. It pins URL
canonicalization (https only, IDNA2008 A-labels, the refused path and query
encodings, the ambiguous IPv4 host forms), destination definition (single-label
wildcards never over a public suffix of the pinned Public Suffix List, private
section included; typed `{param}` and trailing `**` path segments; methods;
query rules; internal destinations behind the deploy-level
`internal_destinations` switch), destination matching, and the request-header
allowlist with its always-rejected names, including the guard's own `Accept-Encoding:
identity`, and the rules for the headers a caller's credential handling injects
(declared names only, never a guard-set one). Each refusal carries a code from the
hook catalog's `refusal_code` enum and the rule that fired. The pinned list
version is updated in the egress extra, this vector and the module together.
### `hook-event-envelope-v1.json`

The signed `aweb.hook-event/1` envelope (aweb-acgh.16.2; contract in
[`hook-events.md`](../hook-events.md)). Positive cases pin, for fixed seeds,
the envelope, its signing bytes (the prefix and canonical JSON) and the
detached Ed25519 signature: a core mutation, a core registry fact with a system
actor, an app secret use by an identity-grant actor, and a client command
signed by its own actor. Each negative carries its signing bytes and signature
and one expected refusal. The `envelope` layer covers a wrong prefix,
non-canonical bytes (including `-0`), a float, a duplicate key (plain or
escaped), a leading zero or plus sign, an out-of-range integer, an integer
too long to parse, nesting deeper
than eight, a non-ASCII string, null, unknown and missing fields, an impossible
or imprecise time, more than four or non-strict attestations, a client
producer with a `seq`, a non-Ed25519 `did:key`, three respellings of the
signature (padded, URL alphabet, nonzero trailing bits), an unknown catalog or hook, a zero trace id, a
fired time before the occurred time, the actor rules, a nested payload value, a
producer kind the hook does not allow, a client actor that is not its signer, a
team mismatch and a wrong signature. The `catalog` layer passes the envelope
checks and is refused by the catalog reader. A digest construction case shows
`request_sha256` taken before credential injection. The Go authority in
`cli/go/hookevent` regenerates every case byte for byte.

### `hook-delivery-credential-v1.json`

The `AWEB-Hook DIDKey` request credential that carries an event to one binding
(aweb-acgh.16.2; contract in [`hook-events.md`](../hook-events.md)). Positive
cases pin the headers, the canonical signed payload and the body for a core
producer and for a client producer carrying its team certificate. Negatives
refuse a client delivery without its certificate or with one for another key,
team or certificate id, or not signed by the team's current key; three
respellings of the credential signature; a padded signed payload; an empty
team id; a timestamp with a fraction; an app-event or `hook-resolve` credential at
a hook target, either purpose's payload under the hook scheme, a payload altered
after signing, a cross-audience or cross-endpoint request, a tampered body, a
stale or future timestamp, a wrong binding, a credential naming another event
or team, and a signer that is not the event's producer. Each negative is a full
request with the receiver's own options and one expected refusal.

### `logs-chain-v1.json`

The bytes logs commits to and signs (aweb-acgh.16.21; contract in
[`logs-chain.md`](../logs-chain.md)): two epoch geneses, three content
commitments over real core, app and client envelopes, and the
`aweb.logs-receipt/1` and `aweb.logs-checkpoint/1` artefacts. Artefact
negatives refuse one artefact's bytes presented as the other, a signature by
another key, bytes altered after signing, a padded signature, non-canonical
bytes, an unknown or missing field, a receipt for sequence zero, a time in
seconds, a wrong type, a float and an uppercase digest. Chain cases give the
stored events, receipts and checkpoints with the keys the verifier knows, and
the report `verify` must return: an intact chain, an empty epoch, a second
epoch recording the first, a purged stub that still verifies, altered content,
an altered skeleton, a reorder, a rehashed reorder that its receipts and
checkpoint contradict, a gap, a rewritten envelope and wrong key evidence
failing provenance, content gone without an act, a duplicate sequence, an
event of another team, forged checkpoints, a receipt for another team, and
receipts naming another event or receipt time at their sequence number (only
the time is bound once the event is purged), a skeleton that disagrees with its
envelope, and the normative break order pinned pair by pair: each of those
cases puts two adjacent faults on one event (a duplicate of another team, an
event of another team with a broken link, a wrong event hash with its content
gone, a wrong event hash with its content altered, wrong key evidence with a
changed skeleton) and expects the earlier. The
Python implementation in `naapp/logs` regenerates it byte for byte, and the Go
verifier in `cli/go/logschain` passes it.

### `owner-act-v1.json`

The `aweb.owner-act/1` artifact, signed by a team's current controller key
(aweb-acgh.16.3; contract in [`owner-act.md`](../owner-act.md)). Positive cases
cover every act in the three vocabularies (core, app and logs) with their
subjects, including registration and production bindings. Each case carries the
verifier's own facts: its team, the current team key, its audience and
vocabulary, its clock, the stored subject and the nonce state. Negatives refuse
an admin signer and a rotated-out team key (`owner_required`), a claimed team
key that an admin signed, expiry, an act issued in the future, a lifetime over
ten minutes, a reused nonce, a subject whose generation or digest differs, a
designation for another contact or naming a subject, an act
outside the verifier's vocabulary or audience, another team, a team
certificate presented as an owner act, an unknown act, kind-specific subject
fields on the wrong kind, a missing conditional field, a reversed erase range,
a duplicate key, a float, null, a non-ASCII string, a wrong version or type,
an impossible date, an act that expires when issued, a malformed nonce, three
respellings of the signature, non-canonical bytes, and binding `scopes` or
`reads` out of order or repeated. Positives pin the inclusive 60-second lead
and a binding with more than one scope in order. The Go authority in
`cli/go/awid/owneract.go` regenerates the vector byte for byte.

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
| `e2ee-v2-cross-language.json` | Python aweb `test_e2ee_crypto_helpers.py` and pre-activation federation harness; Go AWID `e2ee_cross_language_test.go`; TypeScript channel-core `encrypted_dispatch.test.ts` |
| `egress-address-v1.json` | naapp-lib `test_addresses.py` |
| `egress-url-v2.json` | naapp-lib `test_url_vectors.py` |
| `identity-log-negative-v1.json` | Python AWID `test_identity_log_verify.py`; Go shared `identity_log_negative_test.go`; TypeScript channel-core `registry.test.ts` |
| `identity-log-raw-wire-v1.json` | Python AWID `test_identity_log_verify.py`; Go shared `identity_log_raw_wire_test.go`; TypeScript channel-core `registry.test.ts` |
| `identity-log-v1.json` | Python AWID `test_conformance_vectors.py`, `test_did.py`, `test_external_registry.py`, and `test_identity_log_verify.py`; Python aweb `test_identity_conformance_vectors.py` and pre-activation federation harness; Go AWID `registry_register_test.go`, `federation_authority_test.go`, and `federation_external_registry_test.go`; Go shared `conformance_test.go`; TypeScript channel-core `registry.test.ts`, `log_rollback.test.ts`, and `received_sender_trust.test.ts` |
| `message-signing-v1.json` | Python AWID and aweb conformance tests, including the pre-activation federation harness; Go shared `conformance_test.go` |
| `mutation-hook-call-sites-v1.json` | Build guard `scripts/check-extension-docs.py` |
| `pin-store-raw-wire-v1.json` | Go shared `pin_store_raw_wire_test.go`; TypeScript channel-core `pin_store_raw_wire.test.ts` |
| `rotation-announcements-v1.json` | Python AWID and aweb conformance tests; Go shared `conformance_test.go` |
| `stable-id-v1.json` | Python AWID and aweb conformance tests; Go shared `conformance_test.go` |
| `secrets-runner-protocol-v1.json` | secrets `test_runner_protocol_vectors.py` |
| `team-auth-envelope-v2.json` | Python aweb `test_team_auth_envelope.py`; folio `test_auth_v2_envelope.py`; naapp-lib `test_team_auth_vectors.py`; Go shared `conformance_test.go`, including its root-equality check for the managed embedded copy |
| `federation-origin-ip-v1.json` | Python AWID `test_federation_authority_vectors.py` and `test_external_authority.py`; Python aweb pre-activation federation harness; Go AWID `federation_authority_test.go`; Go shared `federation_authority_vectors_test.go` |
| `federation-discovery-v1.json` | Python AWID `test_federation_authority_vectors.py` and `test_external_authority.py`; Python aweb pre-activation federation harness; Go AWID `federation_authority_test.go`; Go shared `federation_authority_vectors_test.go` |
| `federation-authority-state-v1.json` | Python AWID `test_federation_authority_vectors.py`; Python aweb `test_federation_authority_core.py`, `test_federation_authority_schema.py`, and pre-activation federation harness; Go AWID `federation_authority_test.go`; Go shared `federation_authority_vectors_test.go`; generated `federation-error-reference.md` response-shape cross-check through `generate_federation_error_reference.py` (reason/status/retryability source is `awid/src/awid/federation_errors.py`); federation SOT/support coverage in `check-extension-docs.py` |

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
