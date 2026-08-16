# E2E Messaging Contract

Status: **canonical shipped advanced protocol** for encrypted message version 2.
It defines canonical payload bytes, associated data, nonce policy, key wrapping,
message schemas, downgrade handling, and server-readable exceptions.

E2E is optional advanced messaging, not a prerequisite for the basic mail/chat
round trip. Current `aw` sends server-readable plaintext by default; `--e2ee`
explicitly selects encrypted v2 and then fails closed rather than falling back.
The shipped protocol covers self-custodial mail/chat, sender archive copies,
small groups, local/team identities, federation transport, and generic hosted
custody boundaries.

## Goals

- E2E message plaintext, including subject and body, never crosses the routing
  service for self-custodial encrypted v2 messages.
- The server routes, stores, indexes, bills, and audits only metadata and
  ciphertext.
- The sender signs the encrypted envelope. The server can verify routing and
  delivery integrity without decrypting.
- Recipients decrypt locally before showing content, notifying with content, or
  injecting content into a prompt.
- After E2E intent is selected, missing, stale, unsupported, mismatched, or
  downgraded encryption state fails closed. There is no silent plaintext
  fallback for that send.

## Non-Goals

- Hosted custodial tools or any server-side surface that receives plaintext are
  not E2E. They may use the encrypted-v2 wire format as server-readable hosted
  managed encryption, but must not be described as E2E.
- The server cannot recover lost encryption keys and cannot decrypt historical
  encrypted messages for support.
- This contract does not introduce a Signal or MLS-style ratchet. Group chat is
  per-message content encryption with per-recipient key wraps.
- Federated group chat is not enabled in the current implementation. Federation
  v2 chat supports one-to-one remote delivery; mixed local/remote encrypted
  groups fail closed until a reviewed federation group model exists.
- Encrypted attachments are not implemented. They must use this
  same envelope and metadata model when added.

## Threat Model

### Assumptions

- Routing services are honest-but-curious for E2E content: they may faithfully
  route and store messages while attempting to inspect anything visible to them.
- A relay or compromised server may attempt key substitution, downgrade,
  replay, metadata tampering, recipient substitution, or ciphertext mutation.
- Hosted custodial identities, hosted MCP clients, dashboard plaintext tools,
  and other server-readable modes are outside E2E because plaintext or
  decryption capability enters the service boundary.
- If a client loses its local encryption private key or archived decryption
  keys, the server cannot recover encrypted history.
- Metadata leakage listed in this contract is accepted by design.

### Defended Properties

- The server cannot read `subject`, `body`, or decrypted chat content for v2 E2E
  messages.
- A relay cannot replace a recipient encryption key without invalidating the
  identity-authorized key assertion or sender signature.
- A relay cannot convert an intended v2 send to plaintext; plaintext is a
  separate user-selected mode.
- A relay cannot replay a fresh delivery outside the server/federation ingestion
  window. Already-accepted stored mail remains readable later.
- A ciphertext or key-wrap mutation is rejected by the AEAD tag, signed
  ciphertext hash, signed key-wrap hash, or inner-header check.

### Not Defended

- The server learns accepted metadata: sender/recipient identifiers, delivery
  routes, timestamps, ciphertext size, key ids, message/conversation ids,
  read/ack state, delivery result, and routing policy inputs.
- A compromised sender endpoint can disclose plaintext before encryption.
- A compromised recipient endpoint can disclose plaintext after decryption.
- A hosted server-readable mode can disclose plaintext to the service by design.

## Authority Boundaries

| Authority | May do | Must not do |
| --- | --- | --- |
| Identity signing key | Authorize the identity encryption public key, sign message envelopes, sign rotation/revocation assertions. | Decrypt messages unless it also controls the encryption private key. |
| Identity encryption key | Decrypt content-key wraps addressed to that key. | Sign identity, team, namespace, or routing authority. |
| AWID / namespace / team authority | Publish or distribute identity-authorized encryption-key facts and team membership facts. | Substitute a member encryption key, decrypt messages, or authorize plaintext downgrade. |
| aweb server | Verify signatures, route ciphertext, store metadata, enforce delivery policy, expose metadata events. | Read, search, preview, summarize, or support-debug plaintext for E2E messages. |
| Local client | Generate encryption keys, encrypt, decrypt, show plaintext, inject plaintext into local prompts, warn about key loss. | Send plaintext to server for E2E messages or silently downgrade. |

Team controller keys authorize team membership. They do not decrypt member
conversations and cannot substitute member encryption keys. There is one
canonical identity encryption-key authority per identity key assertion: the
identity signing key.

## Cryptographic Suite

The current suite id is:

`aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519`

The suite has these exact primitives:

- Identity signing: Ed25519 over canonical JSON bytes.
- Recipient encryption public key: X25519 public key, 32 bytes.
- Per-message content encryption key, `cek`: 32 random bytes from the OS CSPRNG.
- Content encryption: AES-256-GCM.
- Content nonce: 12 random bytes from the OS CSPRNG, unique per `cek`.
- Content AAD: canonical JSON bytes of the outer protected header with
  `signature`, `ciphertext`, and `crypto.ciphertext_hash` omitted. The sender
  computes `ciphertext_hash` after encryption and the Ed25519 signature then
  covers both the AAD-bound metadata and the final ciphertext hash. If
  `sender_encryption_key` is present, it is part of the protected header and
  therefore part of the AAD and final signature.
- Ciphertext hash: SHA-256 over the exact AES-GCM ciphertext bytes, including
  the authentication tag.
- Key wrapping: HPKE base mode using X25519, HKDF-SHA256, and AES-256-GCM.
- HPKE info bytes: UTF-8 string
  `aweb-e2ee-v2 key-wrap\n` followed by the canonical JSON bytes of the
  key-wrap binding object defined below.
- Hash encoding: RFC 4648 raw standard base64, no padding.
- Binary field encoding: RFC 4648 raw standard base64, no padding.

The content nonce must never be reused with the same `cek`. Because each message
uses a fresh random `cek`, a fresh random nonce is sufficient. Send APIs must not
expose a caller-provided nonce for normal sends. The protocol requires an
all-zero nonce to be rejected. Current Python and Go senders generate the nonce
internally and reject the all-zero result; current server ingestion validates the
12-byte shape but does not yet independently reject a correctly signed all-zero
nonce. Treat receiver-side all-zero rejection as a known verifier-hardening gap,
not as shipped enforcement.

## Canonical JSON

All signed and hashed JSON in this contract uses the shared aweb canonical JSON
form:

- UTF-8 JSON object or array.
- Object keys sorted lexicographically by Unicode code point.
- No insignificant whitespace.
- No trailing newline.
- HTML escaping disabled: `<`, `>`, and `&` remain literal UTF-8 characters.
- Non-ASCII characters remain UTF-8 unless JSON escaping is required.
- Strings use JSON escaping for quote, backslash, and control characters.
- Arrays preserve order.
- Optional fields are omitted when absent; they are not encoded as `null`.
- Numbers are integers only unless a field explicitly says otherwise.

This is the same canonicalization family as `awid.CanonicalJSONValue` and the
Python verifier's `json.dumps(..., ensure_ascii=False, separators=(",", ":"))`.

## Identity Encryption Key Assertion

Each decrypting identity publishes an identity-authorized encryption key
assertion before it can receive E2E messages.

Canonical assertion payload:

```json
{
  "operation": "publish_encryption_key",
  "version": "aweb-e2ee-key-v1",
  "identity_did": "did:key:z...",
  "identity_stable_id": "did:aw:...",
  "custody": "self",
  "encryption_key_id": "sha256:...",
  "encryption_public_key": "base64...",
  "algorithm": "x25519",
  "created_at": "2026-05-26T00:00:00Z",
  "not_before": "2026-05-26T00:00:00Z",
  "expires_at": "2026-08-24T00:00:00Z",
  "previous_encryption_key_id": "sha256:..."
}
```

`previous_encryption_key_id` is omitted for the first key. The assertion is
signed by the current identity Ed25519 signing key. A namespace controller, team
controller, hosted service, or relay may distribute this assertion but must not
alter it or replace the key.

`custody` is the sender-visible trust-model signal for the decrypting identity.
Allowed values are `self` and `hosted_custodial`. New assertions MUST include
`custody`. Assertions created before this field existed may omit it; upgraded
senders MAY treat an omitted value as `self` only for existing self-custodial
assertions that otherwise verify. Hosted custodial assertions MUST include
`custody: "hosted_custodial"`; omission is invalid. The signed field gives
clients an authoritative signal for disclosing that the custody operator can
decrypt for that recipient. Registry, service, team, or namespace metadata may
repeat custody for UI filtering, but it must not contradict the signed
assertion.

Publication invariant: the client must generate and durably store the
encryption private key before publishing the public assertion. A public key must
not be published if the private counterpart is missing on the identity home
device.

`encryption_key_id` is:

`sha256:` plus raw-standard-base64-no-padding SHA-256 over:

`aweb-e2ee-v2 encryption-key\n` + raw 32-byte X25519 public key.

### Discovery, trust, pinning, and rotation

Signing-key continuity and encryption-key selection are separate checks:

1. verify the identity/signing key through the normal AWID and TOFU/DID-log
   trust path;
2. verify that the current Ed25519 identity key signed the X25519 assertion;
3. verify identity/stable-id binding, `custody`, algorithm, derived key id, and
   validity window;
4. use the asserted X25519 key only for wrapping/decrypting message content.

There is no separate TOFU pin for an X25519 encryption key. Global addressed
identities publish assertions through AWID. Local/team identities publish them
through the service-local team roster. Addressless reply continuity may use the
signed sender assertion embedded in a previously verified envelope, but never
as bare `did:aw` first-contact authority.

Rotation publishes a new assertion with `previous_encryption_key_id`; it does
not change the identity signing key. New sends use the newest valid discovered
assertion. Clients keep old private encryption keys in their local archive and
select them by the key id in the wrap. Losing an archived private key makes only
history wrapped to that key unrecoverable.

### Hosted-custody interoperability

A hosted custody operator may hold an identity's Ed25519 signing key and X25519
private-key archive. It may produce the same identity-signed assertion and the
same encrypted-v2 envelope as a self-custodial client. This is wire-compatible
**hosted managed encryption**, not E2E: the operator can decrypt through the
recipient's wrap and sees plaintext at hosted compose/read boundaries.

Public interoperability requirements are:

- the private key is stored durably before its public assertion is published;
- the identity key, not a service/team/namespace key, signs the assertion;
- `custody: "hosted_custodial"` is present, signed, and preserved for policy and
  disclosure surfaces;
- global keys use AWID discovery; local/team-only keys use service-local
  discovery with no AWID fallback;
- active keys are used for new sends while archived keys remain available for
  historical wraps;
- decrypt authority is scoped to the authenticated custodial identity, not
  granted implicitly to workspace admins or support tooling;
- a mixed-custody group has the confidentiality floor of its least-private
  participant: a hosted recipient wrap lets that operator decrypt that message.

Storage schema, key-encryption-key configuration, backfill jobs, dashboard
procedure, and production rollout are operator implementation details, not part
of the public wire contract. Current public validators preserve and verify the
custody value, but the CLI does not yet emit a dedicated send-time hosted-custody
or mixed-group confidentiality-floor warning; do not claim that disclosure UX is
shipped.

## Outer Encrypted Envelope

The server-visible v2 envelope has this shape:

```json
{
  "message_version": 2,
  "envelope_type": "aweb.e2ee.message",
  "kind": "mail",
  "message_id": "uuid",
  "conversation_id": "uuid",
  "reply_to_message_id": "uuid",
  "created_at": "2026-05-26T00:00:00Z",
  "expires_at": "2026-05-26T00:05:00Z",
  "from": {
    "address": "example.com/alice",
    "did": "did:key:z...",
    "stable_id": "did:aw:...",
    "team_id": "team:example.com",
    "encryption_key_id": "sha256:..."
  },
  "sender_encryption_key": {
    "operation": "publish_encryption_key",
    "version": "aweb-e2ee-key-v1",
    "identity_did": "did:key:z...",
    "identity_stable_id": "did:aw:...",
    "custody": "self",
    "encryption_key_id": "sha256:...",
    "encryption_public_key": "base64...",
    "algorithm": "x25519",
    "created_at": "2026-05-26T00:00:00Z",
    "not_before": "2026-05-26T00:00:00Z",
    "expires_at": "2026-08-24T00:00:00Z",
    "signature": "base64..."
  },
  "recipients": [
    {
      "address": "example.com/bob",
      "did": "did:key:z...",
      "stable_id": "did:aw:...",
      "team_id": "team:example.com",
      "encryption_key_id": "sha256:...",
      "wrap_id": "sha256:..."
    }
  ],
  "routing": {
    "to": "example.com/bob",
    "to_did": "did:key:z...",
    "to_stable_id": "did:aw:...",
    "delivery_origin": "https://example-service.invalid",
    "sender_observed_inbound_mode": "team_and_contacts"
  },
  "policy": {
    "requires_e2ee": true,
    "legacy_plaintext_allowed": false
  },
  "crypto": {
    "suite": "aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519",
    "content_nonce": "base64...",
    "ciphertext_hash": "sha256:...",
    "ciphertext_size": 1234,
    "inner_header_hash": "sha256:...",
    "key_wraps_hash": "sha256:..."
  },
  "key_wraps": [
    {
      "wrap_id": "sha256:...",
      "recipient_stable_id": "did:aw:...",
      "recipient_did": "did:key:z...",
      "recipient_address": "example.com/bob",
      "recipient_encryption_key_id": "sha256:...",
      "sender_encryption_key_id": "sha256:...",
      "wrap_purpose": "delivery",
      "algorithm": "hpke-base-x25519-hkdf-sha256-aes256gcm",
      "encapsulated_key": "base64...",
      "wrapped_cek": "base64..."
    }
  ],
  "ciphertext": "base64...",
  "signature": "base64...",
  "signing_key_id": "did:key:z..."
}
```

Rules:

- `kind` is `mail` or `chat`.
- `subject`, `body`, and chat plaintext are absent from the outer envelope.
- `reply_to_message_id` is omitted when absent.
- `expires_at` is required and must be no more than
  five minutes after `created_at`.
- `signature` is omitted from the signed payload and present on the transmitted
  envelope.
- `sender_encryption_key` is optional and omitted when absent. It is a public
  identity-signed encryption-key assertion for the sender. It is included only
  for conversation-local reply continuity whenever the sender has no
  address-based AWID/global key-discovery path. A local/team-scoped sender may
  still carry a stable id in its local team certificate; the embedded assertion
  is still only conversation-local and is not a global directory entry. It must
  not be used for bare `did:aw` first contact.
- When `sender_encryption_key` is present, the server validates it at envelope
  `created_at`, inside the normal ingestion window. Clients validate it at
  reply-send time before using it to encrypt a future reply. If it is missing,
  expired, not yet valid, invalidly signed, or mismatched, a local-only E2E
  reply fails closed with no plaintext fallback.
- `sender_encryption_key.identity_did` must equal `from.did`;
  `identity_stable_id` must equal `from.stable_id` when `from.stable_id` is
  present and must be omitted when `from.stable_id` is absent;
  `encryption_key_id` must equal `from.encryption_key_id`; algorithm,
  key-id/public-key derivation, signature, and time validity must pass.
- For addressable global senders or recipients, current AWID/service authority
  remains the source for first contact and same-service alias resolution. The
  learned sender assertion is used only as conversation-local reply continuity
  for no-address local/team-scoped senders.
- `signing_key_id` must match `from.did`.
- The sender signs the canonical JSON bytes of the full outer envelope with
  `signature` omitted.
- The server must verify the signature before storage, routing, or event
  emission.
- The server must recompute `crypto.ciphertext_hash` from transmitted
  ciphertext bytes, `crypto.ciphertext_size` from transmitted ciphertext bytes,
  and `crypto.key_wraps_hash` from transmitted `key_wraps` before accepting the
  envelope. It must reject any mismatch even if the signature verifies.
- The server must reject unknown `message_version`, unknown `suite`, missing
  required fields, stale timestamps, duplicate `message_id` replay outside an
  idempotent same-envelope retry, malformed key wraps, and `policy.requires_e2ee`
  false for an E2E route.
- Routing fields in the envelope are not delivery-policy authority. In
  particular, `routing.sender_observed_inbound_mode` is only a sender-observed
  snapshot for debugging and signed-context binding. The server must recompute
  delivery authorization from trusted server, auth, database, AWID, team,
  contact, and recipient policy state. A sender-declared policy field must never
  widen authorization.

## Local Identity Field Optionality

Global identities may have `stable_id` (`did:aw`) and address fields. Local or
team-scoped identities may have only `did:key` plus team/workspace context, or
may carry a stable id in a local team certificate without being addressable
through AWID first-contact discovery.

Omission rules:

- Optional identity fields are omitted when absent. They are never encoded as
  empty strings.
- In encryption-key assertions, `identity_stable_id` is omitted when the local
  identity has no stable id and included when the local team certificate carries
  one.
- In encryption-key assertions, `custody` is included for all new assertions.
  Legacy self-custodial assertions may omit it; hosted custodial assertions must
  include `hosted_custodial`.
- In outer envelope `from`, `recipients`, routing objects, inner headers, and
  key-wrap binding objects, `stable_id` fields are omitted only when absent.
- Address fields are omitted when the identity has no address or when the route
  is a stored local/team route that is not address-based.
- `team_id` is included only when it is part of the sender or recipient routing
  context.
- For local recipients, `routing.to_did` and recipient `did` carry the recipient
  binding; `routing.to_stable_id`, address, and recipient stable id are omitted.

The inner-header mirror check compares only fields present in the signed outer
metadata. A field omitted in the outer metadata must also be omitted in the
inner header for that identity.

## Inner Encrypted Payload

The AES-GCM plaintext before encryption is canonical JSON with this shape:

```json
{
  "inner_version": 2,
  "kind": "mail",
  "message_id": "uuid",
  "conversation_id": "uuid",
  "reply_to_message_id": "uuid",
  "created_at": "2026-05-26T00:00:00Z",
  "from": {
    "address": "example.com/alice",
    "did": "did:key:z...",
    "stable_id": "did:aw:..."
  },
  "recipients": [
    {
      "address": "example.com/bob",
      "did": "did:key:z...",
      "stable_id": "did:aw:..."
    }
  ],
  "subject": "Subject text",
  "body": "Body text"
}
```

For chat, `subject` is omitted and `body` contains the chat message text.

The recipient must decrypt, canonicalize the inner header subset, and verify it
matches the signed outer metadata for:

- `kind`
- `message_id`
- `conversation_id`
- `reply_to_message_id` when present
- `created_at`
- sender `address`, `did`, and `stable_id`
- each recipient `address`, `did`, and `stable_id`

Any mismatch fails closed. The client must not display partial plaintext from a
payload that fails the inner-header check.

`inner_header_hash` is `sha256:` plus SHA-256 over the canonical JSON bytes of
the inner payload with `subject` and `body` omitted.

After decrypting, the recipient must recompute `inner_header_hash` from the
decrypted inner payload and compare it to `crypto.inner_header_hash`. It must
reject any mismatch before displaying plaintext.

## Key-Wrap Binding

Each delivery recipient gets one key wrap. The sender self-copy also gets one
key wrap and is mandatory so sent mail can be read from the sender's local
archive and so tests can assert sender/recipient plaintext equality.

The HPKE info uses this canonical key-wrap binding object:

```json
{
  "version": "aweb-e2ee-wrap-v1",
  "message_id": "uuid",
  "conversation_id": "uuid",
  "recipient_stable_id": "did:aw:...",
  "recipient_did": "did:key:z...",
  "recipient_address": "example.com/bob",
  "recipient_encryption_key_id": "sha256:...",
  "sender_did": "did:key:z...",
  "sender_stable_id": "did:aw:...",
  "sender_encryption_key_id": "sha256:...",
  "wrap_purpose": "delivery",
  "suite": "aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519"
}
```

`wrap_id` is:

`sha256:` plus SHA-256 over canonical JSON bytes of the binding object.

`wrap_id` is deterministic for identical binding inputs. Test fixtures and
idempotency checks may assert the same `wrap_id` when message id,
conversation id, sender identity/key id, recipient identity/key id, and suite
are unchanged.

The recipient must choose the wrap whose `recipient_encryption_key_id` matches a
local private key and whose recipient identity fields match the local identity.
If no matching wrap exists, decryption fails with a structured "not a recipient"
error and no information about other wraps beyond visible metadata.

`key_wraps_hash` is `sha256:` plus SHA-256 over the canonical JSON bytes of the
`key_wraps` array exactly as transmitted, excluding no fields.

The `recipients` array lists delivery recipients. The mandatory sender self-copy
wrap is included in `key_wraps` even when the sender is not a delivery recipient
and is therefore absent from `recipients`. A sender self-copy wrap has
`wrap_purpose` set to `sender_copy`, recipient identity fields matching the
sender identity, and `recipient_encryption_key_id` set to the sender encryption
key id used for local archive decryption. Clients identify the self-copy wrap by
`wrap_purpose = "sender_copy"` plus matching local sender identity and key id.

Delivery wraps have `wrap_purpose = "delivery"` and must correspond to one
delivery recipient entry. Sender-copy wraps must not be used to route or deliver
the message to another participant.

## Associated Data

AES-GCM content AAD is the canonical JSON bytes of the outer envelope with:

- `signature` omitted,
- `ciphertext` omitted,
- `crypto.ciphertext_hash` omitted to avoid circular dependency,
- all `key_wraps` included,
- `sender_encryption_key` included when present and omitted when absent,
- all routing, policy, sender, recipient, nonce, and algorithm fields included.

This binds ciphertext to routing metadata, recipient list, key ids, key wraps,
algorithm suite, timestamp, message id, conversation id, and downgrade policy
through the AEAD tag. After encryption, the sender computes `ciphertext_hash`
over the final ciphertext and signs the full outer envelope with `signature`
omitted, so the signature also commits to the exact ciphertext bytes.

## Capability And No-Downgrade

Current `aw` behavior is explicit opt-in. Without `--e2ee`, mail/chat remains
server-readable plaintext; `--plaintext` makes that choice explicit and
`--legacy-plaintext` is a deprecated compatibility alias. Once `--e2ee` is
selected, missing or invalid key state fails closed with no automatic plaintext
retry.

The shipped sender verifies recipient key authority before encryption and relies
on the target service accepting or rejecting encrypted v2. A complete separate
route-capability preflight is not yet shipped for every route. The capability
list below is the interoperability condition a sender must establish before
E2E-required policy or broader automatic enablement can treat the route as
ready.

Before sending v2 E2E, the sender must know the recipient supports:

- a valid identity-authorized encryption key assertion,
- the `aweb-e2ee-v2.x25519-hkdf-sha256-aes256gcm-ed25519` suite,
- v2 encrypted mail or chat for the requested `kind`,
- a server route that accepts `message_version = 2`.

Recipient encryption keys and recipient E2E capability must be anchored in an
identity-authorized assertion, such as the identity-signed encryption-key
assertion in this contract or an equivalent identity-authorized capability. A
service signature may assert only service route support, such as "this route
accepts `message_version = 2`." A service signature must not substitute for
recipient E2E capability and must not replace recipient encryption-key
authority.

If capability or key discovery is missing, stale, contradictory, or unsigned,
the send fails closed with a diagnostic naming the missing capability. The
client must not retry as plaintext automatically.

For an **intended E2E send**, the only plaintext alternative is a separate,
explicit user choice such as `--plaintext`; an error path must never select it.
That mode must be visually and textually distinct from E2E and must not be
enabled by policy fallback, old-client fallback, or server hint. This rule does
not change the current default mode: users who never select `--e2ee` are using
ordinary server-readable messaging.

Mixed-version behavior after E2E intent:

- E2E sender to v2 recipient/service: send encrypted v2.
- E2E sender to unknown or old recipient: fail closed; a later plaintext send is
  a separate explicit action.
- old sender to v2 recipient: the recipient may receive legacy plaintext only
  if the user or team policy still allows legacy plaintext. Otherwise reject.
- v2 server receiving v1 plaintext on an E2E-only route: reject.
- v1 server receiving v2 encrypted envelope: fail clearly; do not ask the sender
  to downgrade silently.

Any change to the protected envelope surface, including adding optional fields
such as `sender_encryption_key`, requires a coordinated package bump for every
client and server component that signs, verifies, canonicalizes, routes, or
decrypts v2 envelopes. Old clients that do not include a newly required
protected field, or old servers that do not canonicalize a protected field that
is present, must fail clearly. They must not strip the field, retry as
plaintext, or silently downgrade the envelope version.

### Cross-registry authority ordering

Encrypted-v2 federation uses the same strict Ed25519 sender authority as
plaintext before evaluating recipient X25519 assertions. The external registry
is selected from protected, signed `from.address`; a wrapper address, when
present, must match it. The receiver's home registry, general cache, bare
`did:aw`, and wrapper registry hints are not external sender authority.

After strict address/DID/current-key/origin and genesis-anchored log authority
commits its PostgreSQL checkpoint/cohort, encrypted verification continues with
the existing protected-envelope hash/AAD/inner-header checks and recipient
assertion authority. Missing recipient assertion returns
`recipient_encryption_assertion_missing`; invalid or stale assertion returns
`recipient_encryption_assertion_invalid_or_stale`. Neither branch retries or
stores plaintext. Same-registry encrypted delivery keeps the same bindings, and
a local `did:key` continuation still requires its valid embedded
identity-signed sender assertion plus the existing learned route.

The external authority cohort has a 60-second maximum receiver reuse interval,
configurable only shorter. It is not an end-to-end freshness SLA: a DNS or
registry source can suppress an unseen transition while serving old valid
evidence. PostgreSQL coordination failure fails closed with no Redis or
process-local authorization fallback. Stable response details are in the
[federation error reference](federation-error-reference.md).

## Replay And Idempotency

`created_at` must be RFC3339 or RFC3339Nano UTC. Current ingestion accepts a
five-minute skew window for server/federation ingestion. `expires_at` must be
inside that ingestion window.

The server stores one receiver-wide receipt keyed solely by `message_id` for
every local or federated mail/chat message, across plaintext and encrypted
content. An exact federated retry must match the complete canonical
signed/protected envelope and canonical metadata, including kind, sender,
target, and conversation/session. It returns the stored established result
without another message, route, contact, or event effect. Any changed protected
bytes, signed payload, signature, sender, target, kind, conversation/session, or
cross-type reuse returns `federation_message_replay_conflict`.

Local-path and backfilled historical receipts are `legacy_unreplayable`: they
never authorize federation/cross-kind replay and block a later insert after the
message row is deleted. Existing local API idempotency may still return its row
before attempting an insert. Receipts are security history and survive ordinary
message garbage collection. Receipt, encrypted message, participant,
route/contact, and durable event-outbox effects commit in one transaction;
rollback leaves none and permits a later attempt to claim the UUID normally.

Clients must not reject already-accepted stored mail solely because its
`created_at` is old. Async mail may be first read hours or days after server
delivery. Clients should de-duplicate by `message_id` and signed envelope hash,
verify signatures, recompute hashes, decrypt, display the original timestamp,
and reject only actual mutation, duplicate-with-different-envelope, failed
verification, or policy errors. The freshness window is an ingestion rule, not a
history-read/display rule.

## Group Chat Model

Group chat uses the same envelope:

- one random `cek` per message,
- one AES-GCM ciphertext for the payload,
- one key wrap per current recipient encryption key,
- one mandatory sender self-copy wrap.

Adding a participant affects future messages only. Historical re-share is a
separate explicit operation and is not currently implemented. Removing a participant means future sends omit that participant's key wrap; it
cannot make already-delivered ciphertext unreadable
to a participant who kept the old `cek` or plaintext.

Participant removal is durable membership state, not chat turn-completion.
`sender_leaving=true` means the sender ended its current wait/turn and remains
eligible for future wraps. A group member is removed only by an explicit
participant-removal operation recorded on the session participant state, such as
`chat_participants.left_at`; future send validation and continuation target
discovery must use that active participant set.

Federated group chat is not currently enabled. A v2 chat envelope that would
require delivery to more than one remote federation target,
or to a mixed local/remote group, must be rejected before delivery. One-to-one
federated chat still uses the same `kind="chat"` envelope and per-message
sender-copy model.

## Server Storage And Metadata

The server may store and expose:

- `message_version`
- `kind`
- `message_id`
- `conversation_id`
- sender and recipient identity metadata
- routing metadata
- timestamps
- ciphertext bytes and size
- ciphertext hash
- algorithm suite
- recipient encryption key ids
- key wraps
- delivery state, read state, ack state, and error state

The server must not store or derive plaintext subject/body, plaintext previews,
plaintext search vectors, plaintext embeddings, plaintext summaries, or
plaintext support dumps for v2 E2E messages.

Server-side content search over E2E subject/body is forbidden. Search must be
metadata-only or local-client-side after decryption.

## Hosted Surfaces, Notifications, Channel, Pi, And `aw run`

Hosted dashboards and server-side support surfaces must remove, hide, or
downgrade plaintext mail/chat views for self-custodial v2 E2E content. They may
show metadata-only conversation lists, unread counts, delivery status,
participants, and key health.

Server notifications and SSE events may say that an encrypted message arrived,
who it is from, which conversation it belongs to, and whether action is needed.
They must not include plaintext subject/body previews.

Local clients such as the channel, Pi, and `aw run` may decrypt locally before
showing plaintext or injecting it into a prompt. The decryption boundary must be
local to the user's workspace or client process, not the routing service.

## Key Loss And Rotation

Clients must keep archived encryption private keys needed for historical
messages. Losing archived keys makes old encrypted messages unrecoverable. The
server cannot repair this.

`aw doctor`, key setup, key rotation, and docs/skills must distinguish:

- missing identity signing key,
- missing local encryption private key,
- missing published encryption key assertion,
- stale or mismatched published encryption key,
- missing archived encryption key for historical messages.

Rotation publishes a new identity-signed encryption-key assertion and keeps old
private keys locally for old messages. New sends use the newest valid key.
Recipients should attempt decryption with the key id named by the matching wrap,
not by trying every key silently.

## Support, Billing, Abuse, And Retention

Usage, billing, abuse detection, retention, and support for v2 E2E must use
metadata-only signals unless the customer explicitly exports decrypted content
from a local client and supplies it to support. The operational allowance is
specified in [`e2e-operational-metadata.md`](e2e-operational-metadata.md).

Any support endpoint that returns self-custodial v2 content must return
ciphertext and metadata only, or be removed/blocked. Support tooling must not ask
the routing service to decrypt.

## Implementation And Conformance Gates

Current public implementations are anchored in:

- `awid/src/awid/e2ee_keys.py` and `awid/src/awid_service/routes/did.py` for
  identity-signed assertion validation and global discovery;
- `server/src/aweb/e2ee_messages.py` and the encrypted-message migrations for
  envelope verification, opaque storage, replay/idempotency, and crypto helpers;
- `cli/go/awid/e2ee_keys.go`, `cli/go/awid/e2ee_messages.go`, and
  `cli/go/cmd/aw/id_encryption_key.go` for self-custodial key lifecycle and
  local encryption/decryption;
- `docs/vectors/e2ee-v2-cross-language.json` for Python↔Go interoperability.

Every implementation change must include tests or review evidence for the parts
of this contract it touches. Minimum conformance and release controls include:

- known plaintext strings do not appear in server DB rows, logs, SSE events, or
  dashboard/API responses for v2 E2E messages,
- valid recipient decrypts successfully,
- sender self-copy decrypts to byte-for-byte identical plaintext,
- non-recipient decrypt attempt fails cleanly,
- stale timestamp or replay after skew window fails closed,
- one receiver-wide `message_id` receipt returns the exact stored result only
  for an identical federated envelope and rejects changed/cross-kind reuse,
- `legacy_unreplayable` local/historical receipts never become federation replay
  authority or permit UUID reuse after message deletion,
- recipient key substitution fails closed,
- algorithm-suite downgrade fails closed,
- malformed ciphertext and malformed key wraps return structured errors rather
  than panics,
- inner-header mismatch fails closed,
- mutation, removal, or replacement of `sender_encryption_key` after encryption
  breaks signature/AAD verification,
- a valid embedded sender assertion enables local-only stored-route replies,
  while a missing or invalid assertion on such a reply target fails closed,
- strict sender Ed25519 authority precedes recipient X25519 assertion checks,
  and missing/invalid assertion errors remain distinct,
- external registry selection comes from the protected signed address rather
  than home-registry or wrapper hints,
- source suppression is not mislabeled as a 60-second freshness guarantee, and
- after E2E intent is selected, legacy plaintext is never chosen as fallback.
