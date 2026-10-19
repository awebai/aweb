# Human channels: signed provenance and team human addressing

Status: design proposal, no code or implementation approval. Task: aweb-acft.5.
Evidence baseline: `786b67f799777fc411028bbc7af2eda1d2cabf57`.
This proposal replaces the per-external-account-principal approach; that earlier
unmerged memo is background, not authority. Source anchors below use this baseline.

## Model and phase-1 boundary

An external channel is a human endpoint, never a new aweb participant. The hosted
custodian signs as the human's existing actor in the agent's team. Identity-key
custody, team-controller authorization and the receiving client's verification
retain their current meaning (`docs/identity-messaging-contract.md:21`, `:286`;
`cli/go/awid/received_identity.go:48`). An external account link authorizes Cloud
intake under its consent policy; it does not give aweb or Telegram authority to
sign for a self-custodial/BYOT human. Phase 1 is hosted-authority human messaging
through Telegram and MS Teams; Slack follows them.

Cloud owns account links, authenticated platform intake, agent presences,
conversation bindings, endpoints, defaults, consent, revocation and delivery
outbox. Its bindings explicitly distinguish **mail** from **chat**: the dashboard
pair-chat UI currently uses wire mail, so its label cannot select the protocol.
External account IDs, chat IDs, workspace IDs and tokens never enter the fields
below. OSS defines signed content, read projection and participant addressing;
application settings remain with their owner (`docs/oss-boundary.md:37`, `:61`).

Phase 1 needs two OSS changes: optional authenticated provenance and an additive
same-team human alias path. It needs no new principal/trust class, global human
address, endpoint route, federation transport, room contract or registry custody
classification. The alias change is a prerequisite for an agent to initiate mail
to its human; provenance alone does not fix it. Attachments remain their separate
contract. Chasing and rooms are later phases. External-channel traffic is
server-readable; generic encrypted-v2 support below does not make a channel E2EE.

## Optional signed `via`

`via` is an optional JSON string naming **only a platform kind**. Phase-1 producers
emit `telegram` or `msteams`, displayed as “Telegram” and “MS Teams” respectively.
Slack follows phase 1 with the token `slack`; later kinds such as `whatsapp` and
`discord` use the same shape after their adapters are approved. Grammar: ASCII
`[a-z][a-z0-9_]{0,31}`; no whitespace, account suffix, locator or nested object.
Absence is encoded by omission, never `null` or `""`. It means dashboard/native
presentation, not proof of dashboard authentication or absence of a channel.
Unknown well-formed kinds are retained and safely displayed as an unfamiliar
channel kind; they grant no authority or routing behavior. A producer must never
encode an external identifier as a purported platform kind.

The signer asserts provenance. A valid signature does not independently attest
Telegram or identify a person beyond the existing actor. Any native signer can
claim a platform string; it does not acquire hosted-human privileges. Cloud's
chat-only restrictions must be enforced at authenticated channel intake, never
by interpreting absent `via` as permission to issue admin/grant/console actions.
A custodian can sign fresh bytes omitting the label; no cryptography detects
that omission. Changing/removing `via` on an already signed message does fail
verification. No permanent classification or higher/lower verified class follows.

| Format | Canonical placement and coverage |
| --- | --- |
| Plaintext mail and chat | Optional top-level `via` in the existing canonical `signed_payload` object alongside `body`. Include it when present in lexicographic key order; sign those exact bytes. Existing unsigned transport/body projections cannot supply authoritative provenance. |
| Encrypted-v2 mail and chat | Optional top-level `via` in the canonical **inner encrypted content**, alongside `body`/`subject`. AES-GCM protects it and the signed outer `ciphertext_hash` commits to it. No `via` in the outer envelope, AAD, routing or metadata-only events. |

Use the existing canonical JSON rules: UTF-8, sorted keys, no insignificant
whitespace/trailing newline, no HTML escaping, absent optionals omitted
(`docs/e2e-messaging-contract.md:134`; `cli/go/awid/signing.go:440`).
For example, this is the complete byte sequence of an illustrative plaintext
chat signing object (DIDs/UUIDs are placeholders, not a positive crypto vector):

```json
{"body":"hello","conversation_id":"SESSION","from":"did:aw:HUMAN","from_did":"did:key:HUMAN","message_id":"MESSAGE","subject":"","timestamp":"2026-10-19T00:00:00Z","to":"alice","to_did":"did:key:ALICE","type":"chat","via":"telegram"}
```

The MS Teams case uses `"via":"msteams"` in that same position and is signed
over its own resulting bytes; the human display label is never the wire value.

Mail uses its ordinary `type`, subject and priority rules. All existing identity,
recipient, timestamp and conversation bindings remain; adding `via` is not a
replacement for any of them (`server/src/aweb/routes/messages.py:510`). Requests
can carry it solely inside `signed_payload`; no redundant unsigned top-level
request property is needed. Compose/signing APIs gain an optional content field;
servers validate the signed value and derive read projections from protected
content, preserving the exact signature bytes through persistence/federation.
Untrusted outer `via` is never substituted for missing signed content.

For v2, explicitly define `inner_header_hash` as the canonical fixed header
subset: `inner_version`, `kind`, `message_id`, `conversation_id`, `created_at`,
`from`, `recipients`, and optional `reply_to_message_id`. **Exclude content fields
`subject`, `body`, `via`, and any future explicitly admitted delivery hint.** This
clarifies/amends the current “inner payload with subject/body omitted” wording
in `docs/e2e-messaging-contract.md:504`; it does not change existing header bytes.
Go already reconstructs that fixed subset (`cli/go/awid/e2ee_messages.go:690`),
as does Python (`server/src/aweb/e2ee_messages.py:218`). New encryptors include
`via` only when constructing content, and new decryptors preserve it through
read projection. The existing signed envelope, ciphertext hash, AES-GCM, key-wrap
and header-mirror checks all pass before content is displayed
(`cli/go/awid/e2ee_messages.go:432`). No outer/header mirror field is added.

For either format, a newly supplied malformed `via` is a content-validation
error; fail the compose/receive operation without stripping/re-signing or
retrying plaintext. Signature/key/recipient failures retain their existing
failure status and never expose a trusted provenance projection. Preserve
existing accepted no-`via` message shapes, including historical legacy messages;
there is no new requirement to retrofit them or synthesize signed metadata.

## Readers, old clients and vectors

New CLI JSON exposes `via` only from verified signed plaintext or successfully
verified/decrypted v2 content; omit it if absent. Text output may say “Juan via
Telegram” or “Juan via MS Teams”. Keep `verification_status`, `trust_status` and
`verified` unchanged.
Provenance is an authenticated content attribute, not a new authentication mode.
Channel-core, Claude channel, pi and wake carry that same optional field into
model-visible metadata after their normal verification. Encrypted SSE events
remain metadata-only; obtain `via` by local decrypt, never server inference.
Hermes must pass the trusted read field into model-visible context; retaining it
only in `raw_message` is insufficient (`packages/hermes-aweb-platform/adapter.py:235`,
`:274`). Older custody/decryption RPCs may also lose a new field: update their
content projection without granting a worker new signing/decryption authority.

Old plaintext readers that verify exact `signed_payload` bytes still verify the
signature but may omit the label (`cli/go/awid/signing.go:365`;
`channel-core/src/identity/signing.ts:186`). Old v2 Go readers ignore the new
inner field and reconstruct the same fixed header; they can verify/decrypt but
lose its projection (`cli/go/awid/e2ee_messages.go:480`, `:907`). A reader that
reconstructs incompatible bytes may reject. It must fail visibly, never remove
`via`, retry plaintext or downgrade versions to force a success. Omission in an
old UI does not upgrade authority; no policy may depend on recognizing the label.

Published-artifact inspection: npm `@awebai/claude-channel@1.8.0` and
`@awebai/pi@0.4.0` tarballs both verify the exact `signedPayload` in their bundled
`dist/index.js` mail/chat paths; these are shipped bundles, not a source-only
assumption. The `aw-v1.36.41` release tag retains exact-payload verification and
the fixed v2 inner map described above. This is code inspection, not an executed
new-field mixed-version E2E proof. Before emission, run the cases below against
published sender/receiver/custody artifacts, including older supported releases;
upgrade each projection consumer independently. Never assume atomic CLI/pi/channel
upgrades (`.claude/skills/cross-repo-change/SKILL.md:8`). Missing fields remain
accepted forever until a separately measured removal decision; old clients are
not required to send `via`.

Add vectors, retaining old vectors byte-for-byte:

- Mail/chat × plaintext/v2 × absent/telegram/msteams; exact canonical bytes,
  positive signature/decrypt, identical old fixed-header hash for added content.
- Tamper/remove/replace `via` without re-signing/re-encrypting: fail. Unsigned
  outer injection cannot create the projection; valid newly signed omission is
  ordinary absence, never higher authority.
- Null/empty/wrong-type/invalid token refused by new producers/receivers;
  unfamiliar valid kind preserved safely (including the later `slack` kind in a
  phase-1 reader); no external identifiers in fixtures.
- Native and addressless custodial dashboard neighbors retain verified behavior;
  failed signature/recipient/key proofs cannot be promoted by a provenance label.
- Cross-language Go/Python/TS and old/new published clients, custody RPC and every
  runtime display path: verify, preserve or explicitly document an old-reader
  label omission. No silent encryption fallback. Replay uses existing message IDs.

## Later outbound chase hint: shape reservation only

Reserve optional `delivery_hint={"platform":"telegram"}` in signed plaintext
content or encrypted inner content under the same rules. It names no account,
endpoint, presence, deadline or bypass. Phase 1 does not emit or act on it.
The future consumer treats it as advisory: human consent, org policy, default
and conversation binding, quiet hours and rate limits decide delivery. Ignoring
it is valid. It never overrides sender/recipient identity, wire mail/chat kind
or native-presence suppression. An E2EE server cannot read a concealed hint;
no automatic decrypt/export is authorized. Future consent to readable channel
export must be explicit. Exact hint validation/vectors belong to that later slice.

## Agent to human by team alias: current failure and minimal extension

`aw mail send --to juan` is **not reliable/supported for first contact to an
addressless human today**. The governing shipped limitation says so explicitly
(`docs/mail-and-chat.md:188`), and the code has two independent barriers:

1. Humans are absent from `/v1/agents`; the CLI falls back to the live team
   registry member reference (`cli/go/cmd/aw/mail.go:524`). `identityTarget()`
   prefers `DIDAW`, losing the alias/team selector (`cli/go/cmd/aw/helpers.go:560`).
   Signing upgrades that value to `to_stable_id` and attempts global resolution
   (`cli/go/awid/client.go:103`, `:129`). The registry correctly rejects bare
   `did:aw` first contact (`cli/go/awid/registry_resolver.go:175`). Chat has the
   same fallback (`cli/go/cmd/aw/chat.go:41`).
2. Simply keeping `to_alias=juan` is insufficient: both server alias lookup
   helpers exclude `agent_type=human` (`server/src/aweb/messaging/chat.py:91`,
   `:106`). HTTP mail/chat call them (`server/src/aweb/routes/messages.py:93`,
   `:1697`; `server/src/aweb/routes/chat.py:932`), as do MCP send paths
   (`server/src/aweb/mcp/tools/mail.py:500`; `server/src/aweb/mcp/tools/chat.py:389`).
   The current parity test changes its human fixture into an agent for the alias
   case (`server/tests/test_mcp_mail_conversation_parity.py:114`).

Minimal contract-consistent **additive extension**, not implemented here:
allow a human actor to be selected by alias **inside the authenticated sender's
selected team on the same service**. Retain the exact `to_alias`/`to_aliases`
selector in CLI/library sends; do not replace it with a bare global DID or
invent a global human address. Add messaging-specific participant resolution
including active human actors; do not broadly remove human filtering from the
agent roster or shared non-messaging lookups. The selected team, exact alias,
current active membership/certificate projection and service-local actor binding
must agree. Reject missing, deleted, inactive, revoked, mismatched or ambiguous
actors; unavailable required authority fails retryably. Apply existing inbound
policy and recipient/signature checks. An alias cannot switch teams implicitly
when resolving a human; duplicate human labels in another team are irrelevant.

This service-authorized local selector is not a public/global route and does
not make team certificates global routing authority
(`docs/identity-messaging-contract.md:45`, `:78`, `:153`). Preserve current global
address resolution and existing stored-participant continuations, including
exact message replies. Do not weaken the registry's bare-DID refusal or narrow
already accepted local-DID/address/continuation shapes. No general “my human”
magic alias is added: v1 callers use the human's actual alias in an explicitly
selected team. Cloud resolves its per-(team,user) actor and owns any user-to-alias
presentation, not a platform-account namespace.

Phase-1 alias delivery is server-readable. E2EE alias key discovery currently
also depends on agent lookup (`cli/go/awid/mail.go:342`, `:379`); the extension
must either add participant-authorized key discovery using identity-signed keys,
or retain a clear unsupported-encrypted-first-contact refusal. It must never
silently fall back. Existing supported encrypted dashboard replies remain valid.

Acceptance: a real CLI in a selected team first-contacts that team's active
addressless human by alias through real HTTP and MCP mail/chat surfaces; the
neighboring native agent alias still works. Test two teams with the same human
label, missing/deleted/revoked actor, explicit conflicting bindings, unknown
external bare DID, current inbound policy, and existing plaintext/encrypted
replies. No cross-team actor or global route is inferred. Tests assert delivery
and refusal behavior, not wording; no fake `aw` or mocked server in E2E.

## Review and evidence

This is a short proposal; implementation must update identity/messaging and E2EE
contracts, canonical types/signers/readers, vectors and matching runtime consumers
together. Protocol/crypto and Go/server reviewers own canonicalization and the
alias extension; channel/pi/wake/Hermes reviewers own projections. Cloud owns the
consent/ingress/binding design and consumes this contract. Coordinate releases;
any schema change uses a new ordered migration. Identity-path implementation
requires Juan's explicit approval recorded in its commit; this memo is not it.

Three existing focused Go tests passed: mail live-roster fallback, chat fallback
and addressless local-member DID selection. They exercise HTTP fixtures, not a
real-server human-first-contact E2E or a failing proposed-feature harness. The
human failure conclusion comes from the governing restriction plus the concrete
CLI/server paths above; no production send was attempted. Published-bundle and
release-tag inspection supports the stated compatibility model, with rollout
E2E still required. No executable behavior or accepted vectors changed.
