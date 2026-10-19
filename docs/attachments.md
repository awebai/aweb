# Managed attachments in mail and chat

Attachments in this release have the conversation's existing managed protection:
TLS in transit, encryption at rest in the embedding application's store, and
participant checks on every fetch. They are server-readable. They are **not
end-to-end encrypted attachments**. Browser/device-held file keys and opaque
self-custodial encrypted-file transfer are outside this release.

The embedding application owns bounded upload/storage, quota, retention and
purge. The aweb library owns message binding and authenticated download. No
operator's private schema, hostname, credential or deployment defines this wire.

## Descriptor and message authentication

A descriptor is immutable authenticated message content:

```json
{
  "id": "11111111-1111-4111-8111-111111111111",
  "filename": "report.pdf",
  "media_type": "application/pdf",
  "size": 1234,
  "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "expires_at": "2026-11-18T00:00:00Z"
}
```

IDs are canonical UUID strings. `size` is the actual plaintext byte count,
1–5 MiB. There are at most four distinct IDs, hence at most 20 MiB, per message.
The hash is lowercase hexadecimal SHA-256 of the exact downloadable bytes.
`expires_at` is the UTC attached-retention deadline, assigned before encryption;
it is separate from a staged-upload cleanup deadline. Retrying never extends or
rewrites signed content. Mutable deletion/availability is separate from this
object. A descriptor contains no URL, credential, path or file key.

Filename validation preserves accepted spelling. Refuse empty names, `.` and
`..`, leading/trailing whitespace, either path separator, C0/C1 controls,
surrogates, line/paragraph separators, bidi controls/marks, zero-width space,
word joiner and BOM. The cap is 255 UTF-8 bytes. ZWNJ, ZWJ and emoji tag characters
remain supported, following the shown-name/terminal-text policy. A filename is a
display label; clients never derive a download path from it. Terminal clients
escape labels even if an upstream value bypasses validation.

MVP media types are `text/plain`, `text/markdown`, `text/csv`, `application/json`,
`application/pdf`, `image/png`, `image/jpeg`, and `image/webp`. There is no archive
extraction, executable/HTML/SVG handling, remote import or active rendering.

Only `encrypted_v2` carries attachments in this release. The encrypted inner
content has an optional `attachments: [descriptor, ...]` beside subject/body.
Existing ciphertext authentication and its signed hash protect the whole list.
The outer envelope and inner-header hash have no new fields. Existing envelopes
and conformance vectors retain their bytes; older readers can still verify and
read text. The managed custody boundary remains server-readable even though the
message uses the encrypted-v2 wire format.

A legacy-signed send with nonempty `attachments` or `attachment_refs` is refused
with `request_invalid`. No field is added to the legacy canonical signer, and
no encryption-policy fallback is introduced for attachments. Attachment-free
legacy and v2 messages keep their existing behavior. An unsupported managed
backend or undecryptable envelope fails closed; a self-custodial file operation
is never silently replaced by a server-readable one.

## Storage coordination and transaction boundary

The send request carries optional operational metadata separately from the v2
envelope:

```json
{
  "attachment_refs": [{
    "id": "11111111-1111-4111-8111-111111111111",
    "size": 1234,
    "descriptor_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  }]
}
```

`descriptor_sha256` hashes the full descriptor with aweb's canonical sorted-key
UTF-8 JSON. Refs are authenticated transport metadata, **not message authority**.
The managed backend must decrypt the already-verified envelope through its
existing authorized custody material and require exact ordered equality between
inner descriptors, refs and staged immutable commitments. Possession of an ID,
a ref hash, team visibility, or an operator token does not authorize a file.

Register an `AttachmentBackend` through `create_app(attachment_backend=...)` or
`app.state.attachment_backend`. The public types live in `aweb.attachments`.
`AttachmentDescriptor.ref()` computes the transport commitment;
`descriptors(raw)` validates an entire list without partial results or reflection
of unsafe values in errors.

The two provider operations are:

```python
async def bind(tx, *, binding, refs, message) -> None: ...
async def read(db, *, binding, participant, ref) -> tuple[AttachmentDescriptor, bytes]: ...
```

`tx` is the pgdbm transaction manager, including `.connection`, `execute`,
`fetch_one` and `fetch_all`. An embedding schema view must use that same physical
connection/savepoint. `binding` carries message kind/ID, conversation ID, sender
DID, participant DIDs, sender agent ID and team ID. `message` contains the parsed
send request and its verified encrypted envelope. `participant` carries the
fetching identity's routing DIDs, agent ID and team ID; for a grant these are the
subject's identities, not the session signing key.

There is one bind/charge authority: aweb invokes `backend.bind` in the same
transaction as message insertion and generic attachment bindings. Backend
exceptions propagate and roll back its writes and the message. A best-effort
mutation callback is unsuitable. Validate uploader/actor, recipient,
conversation, staging expiry/deletion and descriptor equality; lock staged rows
and bind each ID once. Do no AWID/network discovery under bind locks. Prepare
needed custody/key material before the transaction or fail closed. Embeddings
with a larger send/idempotency transaction must retain that outer transaction;
they must not independently bind or charge again in a post-send callback.

An identical authenticated message/envelope/ref retry returns the existing
result and does not call bind/charge again. A changed ref/envelope or attachment
already used by another message conflicts. Generic bindings contain IDs,
sizes and commitments, never filenames, plaintext or file keys. Application
storage/custody enforcement remains the embedding backend's responsibility;
there is no insecure default blob store.

This release supports attachments on the same serving origin. A send with
attachment refs refuses before federated transport. No descriptor supplies a
foreign fetch origin or bearer link.

## Participant-scoped fetch and safe failures

```text
GET /v1/messages/{message_id}/attachments/{attachment_id}
GET /v1/chat/messages/{message_id}/attachments/{attachment_id}
```

Authenticate with the normal messaging identity, team certificate or session
grant. The existing `mail.read` or `chat.read` scope applies. Aweb first resolves
the message/binding and applies the same participant authority as content reads;
only then does it call the provider. A shared 404 hides unknown, nonparticipant,
staged and cross-message IDs without provider access. No team/admin visibility
shortcut exists. A provider repeats content authority through the published
mail/chat reads, checks lifecycle, and enforces a bounded configurable
per-participant fetch budget. A managed operator may use 60 fetches/minute across
files; its configuration belongs to that operator, not this protocol.

Providers raise only safe `AttachmentError` codes: `not_found` (404),
`attachment_expired`/`attachment_deleted` (authorized 410),
`attachment_conflict` (409), `attachment_unavailable` (503),
`attachment_rate_limited` (429 with optional bounded `Retry-After`) or
`request_invalid` (422). Raw provider exceptions and filenames never enter API
errors. IDs/sizes and an error type may be logged; content, filenames and keys
must not appear in logs or notification/event attachment metadata.

A successful response verifies the descriptor commitment, byte count, SHA-256,
MIME and expiry, then sends exact bounded bytes with `Content-Disposition:
attachment`, safely encoded filename, `X-Content-Type-Options: nosniff`, and
`Cache-Control: private, no-store`. It never redirects or renders. Deletion
revokes future fetches; downloaded copies cannot be revoked, and backup removal
must not be presented as immediate. The embedding application's staged/attached
retention and lifecycle purge remain explicit responsibilities.

## Reading and CLI retrieval

Authorized decrypted mail/chat models expose validated `attachments` and
`attachments_available`. A failed or invalid descriptor list is withheld as a
whole and marked unavailable; independently decryptable text remains readable.
Decryption failure never invents metadata. Hosted MCP uses the additive
`HostedMessageDecryptionResult.attachments`/`attachments_available` fields; its
original positional constructor fields remain compatible. V2 outer HTTP reads
carry only encrypted content and operational refs, without a filename.

`aw mail show` exposes descriptors in JSON and escaped human output. Fetch with
an explicit new output path:

```text
aw mail attachment fetch <id> --message-id <message-id> --output <new-path>
aw chat attachment fetch <id> --message-id <message-id> --session-id <session-id> --output <new-path>
```

The command reads the authenticated message first, selects its validated
immutable descriptor, fetches as that participant, and checks size/hash before
creating a file. Exclusive creation refuses existing files and symlinks. There
is no binary stdout, auto-open, filename-derived path or cross-origin redirect.
Even HTTP tracing suppresses attachment content and filename headers.

Cloud/browser integration must prove drop/button upload through real staging,
message and provider transactions, then real `aw` retrieval of the exact bytes
and a visible agent reply. OSS tests independently cover its auth, crypto,
transaction, descriptor and CLI boundaries; those are not a substitute for the
embedding's quota/lifecycle/browser acceptance.
