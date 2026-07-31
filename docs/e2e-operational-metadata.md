# E2E Operational Metadata Contract

Status: **public supporting contract** for encrypted-v2 operations. It is
subordinate to the normative
[E2E messaging contract](e2e-messaging-contract.md). If crypto, envelope,
key-authority, no-downgrade, or metadata-leakage wording conflicts, the canonical
protocol wins.

E2E is an optional advanced mode. This contract applies only to
self-custodial `encrypted_v2` mail/chat. Ordinary server-readable messaging and
hosted managed encryption have different plaintext boundaries and must be
labeled separately.

## Hard boundary

For self-custodial encrypted v2, routing, support, billing, abuse, and admin
systems may use metadata and ciphertext only. They must not inspect, store,
search, preview, summarize, embed, classify, or support-debug plaintext
subject/body/chat text.

A hosted custody operator may decrypt for an identity whose signed assertion
says `custody: "hosted_custodial"`. That is server-readable hosted managed
encryption, not E2E. It does not grant the operator access to self-custodial
private keys or plaintext.

When content debugging is required for E2E, a customer or agent may export
plaintext from a local client and provide it intentionally. The export is a
support attachment, not server-held message content.

## Allowed retained metadata

### Message and conversation identity

- `message_version=2` and `content_mode=encrypted_v2`.
- Message, conversation, session, thread, and reply/continuation ids.
- Kind (`mail` or `chat`).
- Created, ingested, delivered, read, acknowledged, failed, deleted, and
  retained-until timestamps.
- Signed-envelope/idempotency hash.

### Sender, recipient, and routing metadata

- Sender and recipient `did:key` values.
- `did:aw` only when present for global identities.
- Addresses only for address-based routes; absent local fields stay omitted.
- Team, workspace, agent, member-name, route-kind, delivery-origin, and
  federation-peer identifiers when used for routing.
- Recipient and active participant sets.
- Sender-observed policy fields as signed diagnostics, never delivery authority.
  The service recomputes authorization from trusted identity, team, contact, and
  recipient-policy state.

### Cryptographic metadata

- Suite and envelope version.
- Sender/recipient encryption key ids.
- Wrap ids, purpose (`delivery` or `sender_copy`), and count.
- Ciphertext, key-wraps, and inner-header hashes.
- Ciphertext and envelope byte sizes.
- Capability/failure categories such as missing, stale, unsigned, mismatched,
  unsupported route, downgrade refused, or malformed envelope.

### Delivery and client-reported state

- Delivery outcome, safe failure code, retry count, queue/route/federation
  latency, and read/ack state.
- Optional content-free decrypt result: success, missing local/archived key,
  malformed ciphertext, bad wrap, not a recipient, inner-header mismatch,
  replay/mutation, or unsupported suite.

## Forbidden retained content

For self-custodial encrypted v2, services must not retain or derive:

- plaintext subject, body, or chat text;
- previews, snippets, summaries, embeddings, search vectors, content
  classifications, or moderation labels;
- content-bearing server notifications;
- decrypted support dumps;
- private signing/encryption keys, archived encryption keys, CEKs, or HPKE
  secrets;
- attachment-derived plaintext until a future attachment contract applies the
  same boundary.

Ciphertext and wraps may be retained according to policy but must be labeled
opaque encrypted content.

## Usage, billing, and abuse

Content-free counters may include:

- message/envelope/ciphertext bytes and counts by team, identity, route, kind,
  and time window;
- wrap count, recipient fanout, storage bytes, federation egress/ingress, and
  delivery attempts;
- success/failure counts and latency histograms;
- send bursts, retries, new-recipient rate, failed first contact, recipient
  graph anomalies, block/contact outcomes, invalid signatures, malformed
  envelopes/wraps, stale timestamps, replay conflicts, and downgrade attempts.

Do not claim server-side content moderation for E2E. Metadata may justify
throttle, block, quarantine, or investigation, but not a conclusion about
plaintext content.

## Support workflow

Support may inspect:

1. request/support ids, target, authority mode, and redactions;
2. allowed metadata above;
3. verification, delivery, and client-reported decrypt categories;
4. an explicitly customer-provided decrypted export.

Support must not ask the service to decrypt self-custodial content, request
private or archived keys, or treat hosted account recovery as recovery of
self-custodial history. A useful first response distinguishes
`legacy_plaintext_v1`, self-custodial `encrypted_v2`, and hosted managed
messaging, then checks ids, key ids, route, delivery state, and safe error code.

## Retention and deletion

| Data class | Retention rule |
| --- | --- |
| v2 ciphertext and wraps | Retain per message policy; delete/redact together on deletion or expiry. |
| routing/delivery metadata | Retain per operational/audit policy; ids may be tombstoned while aggregate counters remain. |
| verification/decrypt categories | Retain as metadata without plaintext details. |
| customer-provided decrypted export | Separate explicit support attachment with its own retention. |
| `legacy_plaintext_v1` | Existing legacy policy; always labeled server-readable. |
| aggregate counters | Content-free and non-reversible to plaintext. |

Deleting an encrypted message does not require decryption. A content-free audit
row may remain when policy permits.

## Tooling requirements

An endpoint, CLI, dashboard, support bundle, log capture, or export touching
self-custodial encrypted v2 must do one of the following:

- return metadata and ciphertext only;
- return aggregate content-free counters;
- return a clear blocked response explaining plaintext is unavailable;
- accept a user-provided decrypted export as a separate artifact.

Support bundles may include ids, key ids, hashes/sizes, delivery state, safe
error categories, and redaction paths. They must not include private keys, auth
headers, API keys, plaintext, or a decrypted export unless the user attaches it
separately.

## Conformance fixture

[`../test-vectors/e2e/metadata-only-usage-v1.json`](../test-vectors/e2e/metadata-only-usage-v1.json)
pins the current `encrypted_v2` metadata shape. Its consumer rejects forbidden
plaintext field names recursively and verifies the stored content-mode value.
Implementation/release tests must additionally prove known plaintext does not
appear in server rows, logs, events, API responses, support bundles, or dumps.
