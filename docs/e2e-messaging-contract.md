# E2E Messaging Contract

This document is the normative contract for encrypted message version 2. It is
the authority for all implementation tasks under `aweb-aapv`. Downstream code
must cite this document when implementing canonical payload bytes, associated
data, nonce policy, key wrapping, message schemas, downgrade handling, and
server-readable exceptions.

The first implementation target is self-custodial one-to-one mail. The contract
also defines the group-chat key-wrap model so the v2 envelope does not need a
second incompatible design later.

## Goals

- E2E message plaintext, including subject and body, never crosses AC/aweb
  servers for encrypted v2 messages.
- The server routes, stores, indexes, bills, and audits only metadata and
  ciphertext.
- The sender signs the encrypted envelope. The server can verify routing and
  delivery integrity without decrypting.
- Recipients decrypt locally before showing content, notifying with content, or
  injecting content into a prompt.
- Missing, stale, unsupported, mismatched, or downgraded encryption state fails
  closed. There is no silent plaintext fallback.

## Non-Goals

- Hosted custodial MCP, dashboard-side send/read, or any server-side tool that
  receives plaintext is not E2E. It may be supported as server-readable hosted
  messaging, but it must not be described as E2E.
- The server cannot recover lost encryption keys and cannot decrypt historical
  encrypted messages for support.
- This contract does not introduce a Signal or MLS-style ratchet. Group chat is
  per-message content encryption with per-recipient key wraps.
- Federated group chat is out of scope for the first implementation. Federation
  v2 chat starts as one-to-one remote delivery; mixed local/remote encrypted
  groups must fail closed until a reviewed federation group model exists.
- Attachments are out of scope for the first implementation. They must use this
  same envelope and metadata model when added.

## Threat Model

### Assumptions

- AC/aweb servers are honest-but-curious for E2E content: they may faithfully
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
- A relay cannot downgrade a v2-capable sender/recipient pair to plaintext
  unless the user explicitly chooses `--plaintext`.
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

The initial suite id is:

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
  covers both the AAD-bound metadata and the final ciphertext hash.
- Ciphertext hash: SHA-256 over the exact AES-GCM ciphertext bytes, including
  the authentication tag.
- Key wrapping: HPKE base mode using X25519, HKDF-SHA256, and AES-256-GCM.
- HPKE info bytes: UTF-8 string
  `aweb-e2ee-v2 key-wrap\n` followed by the canonical JSON bytes of the
  key-wrap binding object defined below.
- Hash encoding: RFC 4648 raw standard base64, no padding.
- Binary field encoding: RFC 4648 raw standard base64, no padding.

The content nonce must never be reused with the same `cek`. Because each message
uses a fresh random `cek`, a fresh random nonce is sufficient. Implementations
must still reject all-zero nonces and must not expose a caller-provided nonce
for normal sends.

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
controller, hosted service, relay, or AC server may distribute this assertion
but must not alter it or replace the key.

Publication invariant: the client must generate and durably store the
encryption private key before publishing the public assertion. A public key must
not be published if the private counterpart is missing on the identity home
device.

`encryption_key_id` is:

`sha256:` plus raw-standard-base64-no-padding SHA-256 over:

`aweb-e2ee-v2 encryption-key\n` + raw 32-byte X25519 public key.

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
- `expires_at` is required for first implementation and must be no more than
  five minutes after `created_at`.
- `signature` is omitted from the signed payload and present on the transmitted
  envelope.
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
team-scoped identities may have only `did:key` plus team/workspace context.

Omission rules:

- Optional identity fields are omitted when absent. They are never encoded as
  empty strings.
- In encryption-key assertions, `identity_stable_id` is omitted for local
  identities without a `did:aw`.
- In outer envelope `from`, `recipients`, routing objects, inner headers, and
  key-wrap binding objects, `stable_id` fields are omitted for local identities.
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
- all routing, policy, sender, recipient, nonce, and algorithm fields included.

This binds ciphertext to routing metadata, recipient list, key ids, key wraps,
algorithm suite, timestamp, message id, conversation id, and downgrade policy
through the AEAD tag. After encryption, the sender computes `ciphertext_hash`
over the final ciphertext and signs the full outer envelope with `signature`
omitted, so the signature also commits to the exact ciphertext bytes.

## Capability And No-Downgrade

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

The only allowed plaintext escape hatch is an explicit user command or flag
named `--plaintext`. That mode must be visually and textually distinct from E2E
and must not be enabled by policy fallback, old-client fallback, or server hint.

Mixed-version behavior:

- v2 sender to v2 recipient: send encrypted v2.
- v2 sender to unknown or old recipient: fail closed unless the user explicitly
  selects legacy plaintext.
- old sender to v2 recipient: the recipient may receive legacy plaintext only
  if the user or team policy still allows legacy plaintext. Otherwise reject.
- v2 server receiving v1 plaintext on an E2E-only route: reject.
- v1 server receiving v2 encrypted envelope: fail clearly; do not ask the sender
  to downgrade silently.

## Replay And Idempotency

`created_at` must be RFC3339 or RFC3339Nano UTC. First implementation accepts a
five-minute skew window for server/federation ingestion. `expires_at` must be
inside that ingestion window.

The server stores `message_id` and the signed envelope hash. A repeated delivery
of the exact same signed envelope may be treated as idempotent. A repeated
`message_id` with any different signed payload is rejected as replay or
mutation.

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
separate explicit operation and is out of scope for the first group-chat
implementation. Removing a participant means future sends omit that
participant's key wrap; it cannot make already-delivered ciphertext unreadable
to a participant who kept the old `cek` or plaintext.

Participant removal is durable membership state, not chat turn-completion.
`sender_leaving=true` means the sender ended its current wait/turn and remains
eligible for future wraps. A group member is removed only by an explicit
participant-removal operation recorded on the session participant state, such as
`chat_participants.left_at`; future send validation and continuation target
discovery must use that active participant set.

Federated group chat is not enabled in the first implementation. A v2 chat
envelope that would require delivery to more than one remote federation target,
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

## Dashboard, Notifications, Channel, Pi, And `aw run`

AC dashboard and server-side support surfaces must remove, hide, or downgrade
plaintext mail/chat views for v2 E2E content. They may show metadata-only
conversation lists, unread counts, delivery status, participants, and key health.

Server notifications and SSE events may say that an encrypted message arrived,
who it is from, which conversation it belongs to, and whether action is needed.
They must not include plaintext subject/body previews.

Local clients such as the channel, Pi, and `aw run` may decrypt locally before
showing plaintext or injecting it into a prompt. The decryption boundary must be
local to the user's workspace or client process, not AC/aweb server-side.

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

Any support endpoint that returns v2 content must return ciphertext and metadata
only, or be removed/blocked. Support tooling must not ask AC/aweb to decrypt.

## Implementation Gates

No `.2+` implementation slice may proceed until Athena signs off this contract.

Every implementation slice must include tests or review evidence for the parts
of this contract it touches. Minimum release-blocking tests include:

- known plaintext strings do not appear in server DB rows, logs, SSE events, or
  dashboard/API responses for v2 E2E messages,
- valid recipient decrypts successfully,
- sender self-copy decrypts to byte-for-byte identical plaintext,
- non-recipient decrypt attempt fails cleanly,
- stale timestamp or replay after skew window fails closed,
- recipient key substitution fails closed,
- algorithm-suite downgrade fails closed,
- malformed ciphertext and malformed key wraps return structured errors rather
  than panics,
- inner-header mismatch fails closed,
- legacy plaintext is never selected without explicit user intent.
