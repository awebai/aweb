# E2E Operational Metadata Contract

This document defines the metadata-only operational model for encrypted message
v2. It is subordinate to the normative protocol contract in
[`e2e-messaging-contract.md`](e2e-messaging-contract.md): if any crypto,
envelope, key-authority, no-downgrade, or metadata-leakage wording appears to
conflict with that contract, stop and route the change back through
`aweb-aapv.1` review instead of improvising here.

Scope: usage, billing, abuse/rate-limit, retention, support, and admin tooling
for v2 E2E mail/chat where AC/aweb routes ciphertext and local clients decrypt
plaintext.

## Hard boundary

For v2 E2E messages, AC/aweb support, billing, abuse, and admin systems may use
metadata and ciphertext only. They must not inspect, store, search, preview,
summarize, embed, classify, or support-debug plaintext subject/body/chat text.

Hosted custodial MCP, dashboard-side compose/read, and other server-side tools
that receive plaintext are **server-readable hosted messaging**, not E2E. Those
modes may have separate hosted-account support workflows, but they must not be
used to describe or recover locally decrypted encrypted history.

When content debugging is required for an E2E message, the customer or agent may
export decrypted content from a local client and provide that export explicitly.
Support must treat the export as customer-supplied evidence, not as server-held
message content.

## Allowed retained metadata

Servers may retain and aggregate these fields for v2 E2E operations:

### Message and conversation identity

- `message_version` and `content_mode` / encrypted-vs-legacy classification.
- Message, conversation, session, thread, and reply/continuation ids.
- Message kind (`mail` or `chat`).
- Created, ingested, delivered, read, acked, failed, deleted, and retained-until
timestamps.
- Idempotency hash / signed envelope hash.

### Sender, recipient, and routing metadata

- Sender and recipient `did:key` values.
- Stable ids (`did:aw`) only when present for global identities.
- Address fields only when the route is address-based; local/team routes omit
absent address and stable-id fields rather than storing empty strings.
- Team id, workspace id, agent id, alias, delivery origin, federation peer, and
route kind when they are part of routing context.
- Recipient set and participant set.
- Delivery policy inputs as observed metadata, not as authority. The server must
recompute authorization from trusted server/auth/database/AWID/team/contact state;
sender-declared routing or policy fields must never widen delivery.

### Cryptographic and capability metadata

- Algorithm suite, encryption version, recipient encryption key ids, sender key
id, key-wrap ids, wrap purpose (`delivery` or `sender_copy`), key-wrap count,
ciphertext hash, key-wraps hash, inner-header hash, ciphertext byte size, and
envelope byte size.
- Capability result categories: supported, missing key assertion, stale key,
unsigned assertion, route lacks v2 support, old client/server, downgrade refused.
- Verification/decryption error categories. Error categories must not include or
quote decrypted plaintext.

### Delivery and processing state

- Delivery outcome and failure reason code.
- Retry count, last attempt time, queue latency, route latency, federation
latency, and recipient read/ack state.
- Local client-reported decrypt status categories, when the client chooses to
report them: success, missing local private key, missing archived key, malformed
ciphertext, bad key wrap, not a recipient, inner-header mismatch, replay/mutation,
unsupported suite.

## Forbidden retained content

For v2 E2E messages, support/admin/billing/abuse systems must not retain or
derive:

- Plaintext subject, body, or chat text.
- Plaintext previews, snippets, conversation summaries, search vectors,
embeddings, content classifications, or content moderation labels.
- Server-generated message-content notifications.
- Support dumps that include decrypted message content.
- Attachments or attachment-derived plaintext until a future attachment contract
applies the same E2E boundary.

Ciphertext bytes and key wraps may be retained according to the retention policy
below, but support tooling must label them as opaque encrypted content.

## Usage and billing counters

Usage and billing counters for v2 E2E may be computed from metadata only:

- Message count by team, organization, identity, route, kind, and time window.
- Ciphertext bytes and envelope bytes by team, organization, identity, route,
kind, and time window.
- Key-wrap count and recipient fanout.
- Federation egress/ingress bytes and delivery attempts.
- Delivery success/failure counts and latency histograms.
- Storage bytes for ciphertext, key wraps, metadata, and audit rows.

Billing reports must not include plaintext body/subject, plaintext previews, or
content-derived categories. If a hosted server-readable product has separate
billing, label it separately from local-client encrypted messaging.

## Abuse and rate-limit signals

E2E abuse controls may use metadata-only signals:

- Send volume, burst rate, and retry rate by sender identity, team, route,
organization, and delivery origin.
- Recipient fanout, unique-recipient count, new-recipient rate, and failed-first
contact rate.
- Invalid signatures, malformed envelopes, malformed key wraps, unsupported
suites, stale timestamps at ingestion, replay/idempotency conflicts, and
algorithm-downgrade attempts.
- Missing/unsigned/stale recipient key assertion failures and route-capability
mismatches.
- Sender/recipient graph anomalies and block/contact/inbound-mode outcomes.
- Ciphertext byte volume and unusually large encrypted payloads.

Do not claim content moderation for v2 E2E messages. Operators can throttle,
block, quarantine, or investigate based on metadata and verification failures,
but they cannot inspect encrypted content unless the customer supplies a local
decrypted export.

## Support and debug workflow

Support can inspect:

1. The support-contract envelope, request id, target, authority mode, and
redactions.
2. Message metadata listed in this document.
3. Verification and delivery error categories.
4. Client-reported decrypt error categories when explicitly reported by the
client.
5. Customer-provided decrypted exports.

Support must not ask AC/aweb to decrypt E2E content, request private encryption
keys, request archived encryption keys, or treat hosted account recovery as a way
to recover self-custodial encrypted history. Losing archived local encryption
keys makes historical encrypted messages unrecoverable.

Recommended first-line support steps:

- Confirm whether the affected message is legacy plaintext, v2 E2E, or
server-readable hosted messaging.
- For v2 E2E, inspect message id, conversation id, sender/recipient ids, key ids,
route, delivery state, and error category.
- Ask the customer to run the relevant local diagnostics (`aw doctor` or the
approved key/decrypt diagnostic once implemented) from the affected client.
- If content must be inspected, ask the customer to export decrypted content from
a local client and attach it intentionally.

## Retention and deletion semantics

Retention is per data class:

| Data class | May retain? | Deletion semantics |
| --- | --- | --- |
| v2 ciphertext | Yes, per message retention policy | Delete/redact on message deletion or retention expiry. |
| v2 key wraps | Yes, with ciphertext | Delete/redact with the message; do not retain wraps alone as support artifacts unless needed for audit. |
| v2 routing/delivery metadata | Yes | Retain according to operational/audit policy; deletion may tombstone ids while preserving aggregate counters. |
| v2 verification/decrypt error categories | Yes | Retain as metadata; no plaintext details. |
| v2 customer-provided decrypted export | Only as explicit support attachment | Govern by support attachment retention; never merge back into server message storage. |
| legacy plaintext v1 | Existing legacy policy | Must be labeled legacy/plaintext; cannot be retroactively claimed as E2E. |
| aggregate counters | Yes | Must be content-free and non-reversible to plaintext. |

Deleting a v2 E2E message can remove ciphertext and key wraps from normal
retrieval while retaining content-free audit rows and aggregate counters if the
product/legal retention policy permits. Retained audit rows must not contain
plaintext or support-provided decrypted exports unless the export retention path
explicitly says so.

## Support/admin tooling requirements

Any endpoint, CLI, dashboard, support bundle, log capture, or export that touches
v2 E2E messages must choose one of these behaviors:

- Return metadata and ciphertext only.
- Return aggregate metadata-only counters.
- Return a clear blocked/unavailable response explaining that E2E plaintext is
not available server-side.
- Accept a customer-provided decrypted export as a separate support artifact.

It must not return plaintext subject/body from server storage, generate previews,
run server-side content search, or silently fall back to hosted/server-readable
message access.

Support bundles may include message ids, conversation ids, key ids, ciphertext
hashes/sizes, delivery state, error categories, and redaction paths. They must
not include private keys, archived encryption keys, API keys, auth headers,
plaintext message content, or decrypted exports unless the user explicitly adds
that export as a separate attachment.

## Fixture and release-gate expectations

The fixture at
[`../test-vectors/e2e/metadata-only-usage-v1.json`](../test-vectors/e2e/metadata-only-usage-v1.json)
shows the intended metadata-only shape for usage, billing, abuse, and support
records. It intentionally contains counters, ids, hashes, key ids, sizes, and
error categories, but no `subject`, `body`, `preview`, `summary`, or decrypted
content fields.

Implementation tasks should add tests proving:

- usage/billing counters can be computed from the fixture-shaped metadata,
- support/admin endpoints for v2 return metadata/ciphertext only or a blocked
response,
- known plaintext strings do not appear in server DB rows, logs, SSE payloads,
dashboard/API responses, support bundles, DB dumps, or release artifacts,
- customer-provided decrypted exports are stored, labeled, and retained as
support attachments rather than message storage.

## Review bar

Mia should review implementation readiness and support/admin wording for this
operational contract. Athena must review the metadata allowance before broad E2E
enablement to confirm the allowed metadata does not undercut the E2E product
claim.
