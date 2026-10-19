# Full human channels: OSS identity, rooms and presence contract proposal

Status: design proposal for Juan, task **aweb-acft.11**. No implementation approval.
Builds on `d1d2dcd4`; the full-scope direction supersedes its private-pair release
boundary and the old model's exclusion of unlinked room speakers. Nothing in
shared, dedicated, native presences or rooms is removed by this proposal.
Juan's decision (2026-10-19): platform rooms are aweb group chat sessions.
This revision replaces the earlier separate room protocol with group-chat work.

Existing provenance/alias source anchors retain baseline `786b67f79977` unless
marked otherwise. New full-scope gap anchors use `c6235708808b` (2026-10-19).
New artifact names and shapes below are proposals, not current APIs. Cloud owns
the single user-facing architecture document; this is its public protocol input.

## Plain-language text for Juan

An aweb identity and a platform bot are different things. Alice keeps her aweb
key. Her human attaches a bot that appears as Alice in Telegram or MS Teams;
aweb can operate that bot without taking Alice's aweb key. Shared, dedicated
and agent-operated native presences use the same explicit identity binding.
This works for self-custodial and local identities as well as hosted agents.
The bot account is her transport/presence, not a new agent created for her.

A person with a linked Cloud account speaks through their existing human actor
in the relevant team when Cloud has custody authority for it. In a room, its
explicit identity context selects one author for the human, even if agents from
several teams participate. Someone else in the room still gets a real participant
record and replies: they are a **bridged guest**. Recommend identifying that guest by a stable opaque reference under the
bridge's identity, with the bridge signing its platform observation. The agent
sees “Sam via Telegram — platform-attested, not a verified aweb author”. The
bridge's valid signature authenticates that assertion; it is not Sam's signature.
No external account ID is shown to agents. Joining a room never joins the team.

A platform room is an aweb group chat session, using its existing session ID,
participants and messages. We finish group chat with explicit membership
management, history rules and stable bindings. Telegram groups/topics, Teams
chats/channels and Slack channels/threads are audience endpoints for that session. Each event resolves its
speaker independently. A room owner authorizes the bridge to admit observed
external speakers as guests; nobody must create a Cloud account simply to talk
in that approved room. The owner also accepts the entire external audience,
including observers who never speak. Adding an agent still requires its inbound
policy/consent; membership ownership cannot override a refusal. Adding a bridge
makes the entire session not E2EE from that membership epoch, visibly for every
participant. Private messages never turn into room history because a bot was added.

All agents consume ordinary platform-independent aweb events through upgraded
`aw`/channel integrations. In native mode, the agent's existing platform adapter
and aweb share durable input ownership and reply records to deduplicate input
dispatch and committed replies. An uncertain crash outcome is reconciled before
retry; exactly-once model/tool execution is not promised. Native output carries
the agent's own aweb signature; merely seeing its bot post is not enough. This interoperation, rooms and unlinked
participants are required build work, not features assumed to exist already.

Telegram and MS Teams must both support the complete agreed functionality.
Slack, WhatsApp and chasing fit the same architecture. The sequence of delivery
below is a recommendation for Juan; it does not authorize dropping any part.
Channels are readable by the platform and the bridge; no end-to-end encryption
promise crosses that boundary.

## Architecture and authority

| Concept | Proposed authority and boundary |
| --- | --- |
| Native principal | Existing local `did:key` or global `did:aw`/current key; ordinary identity and membership verification. Linked human actors remain this class. |
| Bridged guest | `(bridge did:aw, opaque subject)`; bridge-signed observation, chat-session ACL and stored reply route. No personal signing-key proof and no ordinary team membership. |
| Presence | An explicitly authorized mapping from a principal to shared, dedicated or native platform transport. Bot credentials remain with that transport operator. |
| Platform room | Existing aweb group chat session, with session membership/history management and explicit external bindings. Session membership is separate from team membership. |
| External binding | Private platform/container/thread locator plus approved audience and presence generations. It is not public identity or a new global address. |
| Chat message | Existing session/message IDs, preserved author/content proof and group membership context; fanout, durable receipt and export identity. No separate room event type. |

Current authority remains binding: servers do not acquire member keys, namespace
address authority or global delivery authority from a credential/domain string
(`docs/identity-messaging-contract.md:25`, `:45`, `:60`, `:153`). Team certificate
issuance/revocation remains controller-only (`awid/src/awid_service/routes/teams.py:812`,
`:1157`, baseline 786b67f79977). Room participation is an additional narrow
messaging grant, never a substitute team certificate or a task/admin permission.
A public protocol cannot depend on a hosted schema or runbook
(`docs/oss-boundary.md:10`, `:37`, `:61`).

## Unlinked people and external-only agents: A versus B

| Choice | What the receiver verifies | Cost and consequence |
| --- | --- | --- |
| A — bridge-custodied native identities | Each guest has a real DID/key signed by the bridge holding that guest key. Permanent authoritative custody classification must survive omitted provenance, expiry, revocation and key rotation. | Reuses native address/key machinery but creates a key/log/recovery lifecycle per guest. Must keep these identities out of ordinary team membership and native-author assurance. Merely adding `via` is insufficient. |
| B — bridge signs with a display sender | Only the bridge DID; a name is text. | Fails full functionality: no stable guest ACL, contact, per-speaker history or unambiguous replies. Do not build this shortcut. |
| **B with first-class bridged subjects (recommended)** | Bridge DID/key plus a stable typed guest reference in the signed event and an authorized room/direct-conversation binding. | Guests are real messaging participants without pretend personal key custody. Requires typed participant, contact/reply, authorization and consumer changes; rooms need these distinctions anyway. |
| Guest brings an aweb key | Guest explicitly proves an existing native identity. | Native mode becomes available by consent, without rewriting earlier platform-attested statements. Not a prerequisite for unlinked room participation. |

A guest reference is public protocol identity, for example
`{"kind":"bridged","bridge":"did:aw:BRIDGE","subject":"p7m2"}`. It contains
no Telegram user ID, Entra object/tenant ID, Slack workspace ID or account handle.
The bridge derives the subject deterministically as base64url of an HMAC-SHA256
keyed digest over a domain-separated, versioned canonical tuple of platform,
platform account scope and account ID (plus room context if Juan chooses pairwise
subjects). This private derivation uses an independent bridge-held subject key;
no raw ID or unkeyed account hash is public. Scope and account components use
adapter-defined exact identifiers, never display names. The private map retains
the derivation generation and observed subject kind. The reference is stable
across bots in the chosen scope; cross-room correlation versus pairwise subjects
is an explicit decision below, not a silent remapping.

Subject-key loss starts a fresh generation with new subjects; never guess,
reassign or reuse old subjects, merge their history, or reconstruct identity from
names. Key rotation needs the retained authorized mappings or likewise starts new
subjects. Two accounts or independent bridges are not automatically one person.
Bot and human subjects are distinct. Anonymous-admin/`sender_chat` posts are
refused at intake, never attributed to a guessed human or admitted as a guest
bypass. Telegram describes those non-person sender cases in the
[Message contract](https://core.telegram.org/bots/api#message).

The session membership authority authorizes specific bridge DIDs/platforms and a bounded
admission policy. After authenticated platform intake, a permitted new external
speaker can acquire a guest reference and session membership grant, without a Cloud account or
team certificate. Missing session delegation, invalid sender evidence or uncertain
room state quarantines the event with a visible reason; observation alone grants
no team/admin access. Reuse exact mappings; never key identity by display name.
Bridge private state loss must not silently assign old subjects to new accounts.
An unlinked person can decline/leave through their authenticated external
identity; retain the opt-out tombstone so the next observed post does not
automatically recreate authorization. Subject read/send operations are signed
by the bridge for that exact authorized subject/context, not exposed as a
general impersonation API. Bot-token revocation does not revoke the bridge
signing key. On bridge compromise, session membership authorities revoke its admission/send
delegations and the bridge identity follows its authorized key-recovery path;
team controllers alone revoke any separately issued team certificates.

Linked users use the existing team human actor only where the linking consent,
team access and actual custody authorize signing for it. For a self-custodial or
BYOT human whose key Cloud does not hold, use the bridged-subject path unless
they explicitly supply their own signed aweb content. A Cloud login/domain string
never authorizes signing as that native identity. Private linked DMs keep their
existing owner checks; unlinked room participation is not a DM account link.
For every linked-human room post, before signing as that actor, enforce the same
activation fence/current binding generation, current unrevoked account link,
agent-hosting org channel switch, current team/room access and custody checks as
private intake. Resolve the actual speaker per message, not the room creator.
Delayed/replayed updates cannot revive pre-activation or revoked links. Missing
or anonymous speaker proof refuses visibly; it cannot select the creator's actor.
Cloud's room ingress must state and test these checks explicitly.

For a multi-team room, choose one explicit native actor or guest binding per
human in that room, not one author per destination agent. The same canonical
statement has the same author for every recipient. Existing per-(team,user)
selection remains correct for private pairs; session membership grants permit cross-team
participation without silently enrolling people in those teams. Native author
proof still requires actual identity authority: retain a verified registry/current-
key or local-context binding learned at admission, not a sender-chosen registry.
Session-authority signatures cannot replace that independent identity proof.

Linking a guest later creates an explicit future association under both account
and native-identity authority. It does not rewrite old signatures, combine two
people's contacts or transfer historical room rights. Prior guest posts remain
platform-attested. Future native posts may use the team actor; room admission
and visibility must be checked again. Retiring a link can disable that association
without deleting the guest's already delivered room statements.

### Required verification surface

Extend existing chat sessions with negotiated typed-participant support
(`bridged-participants-v1`, proposed capability), not a new room transport.
A participant reference is a tagged union: `native` with its DID, or `bridged`
with bridge DID and opaque subject. Native chat author verification stays intact.
Guest chat messages require a protected author reference plus the authorized
bridge's signature over the exact subject, session, recipient scope, content,
`via`, membership epoch and message ID. A random valid bridge key is not session
membership authority. An omitted author never comes from a display name.

| Received proof | Model-visible result |
| --- | --- |
| Native author signature plus current identity, recipient and session checks | Existing native `verified` semantics, with optional `via`; no downgrade for linked dashboard humans. |
| Authorized bridge signature plus matching guest/session membership | `author_assurance=platform_attested`, `trust_status=external_untrusted`, external-author `verified=false`; separate `signer_verified=true` identifies the bridge's actual proof. |
| Missing/changed guest subject, wrong bridge, unsigned wrapper, revoked membership or wrong session/epoch | Refuse delivery with the real reason; do not promote into native assurance. |
| Required authority/capability unavailable | Pause/refuse visibly; no native-shape or plaintext fallback. |

A bridge can send a native message as itself; that does not authenticate a guest.
A guest-author reference cannot be omitted to promote that guest, and a native
Alice reference signed only by the bridge fails. Display names/presence bindings
do not replace content signatures. B requires a protected typed-chat extension,
not unsigned sidecar attribution or bridge custody of a fake native guest key.

New group capabilities attach to existing chat/session APIs and message storage.
Only explicit creation/upgrade enables typed participants; existing native
sessions, native accepted messages and reads retain their contract. An in-place
upgrade must establish compatibility of every affected CLI/library/channel/pi/
wake/Hermes consumer; otherwise create a new chat session and keep the old one
readable. Owner consent alone does not establish released-client compatibility. Capability
negotiation and read/wake projection must prevent an incapable client receiving
a guest post as an ordinary verified native message. Enabling guests cannot
silently reinterpret a legacy session or its signed bytes; clients lacking the
required capability get a visible unsupported-session result for newly enabled
functionality. Publish compatible CLI/channel/pi/wake/Hermes artifacts before
enabling it, and test old/native neighboring sessions unchanged. These are
chat compatibility requirements, not a separate room protocol.

Typed guest replies use stored session/participant routes. A guest private
exchange is a two-participant chat session with the same narrow membership,
not group mail or arbitrary bare-DID first contact. Mail remains two-party with
its existing native-recipient contract. Unsolicited contact with arbitrary
external accounts is not implied. Channel-core, Claude channel, pi, wake and
Hermes expose guest `trust_status` and assurance in model-visible metadata and
readback; a verified bridge signer never becomes a verified team-member author.
Raw transport fields or display text alone are insufficient.

## Optional signed `via`

This retained wire placement covers native mail/chat, including native group
chat messages. Guest chat messages carry the same platform-kind attribute under
the negotiated typed-author proof; never project them as legacy native authors.

`via` is an optional JSON string naming **only a platform kind**. Defined producer tokens
are `telegram`, `msteams` (display “MS Teams”), `slack`, `whatsapp` and `discord`.
Telegram and MS Teams are the full initial platform target; delivery order for
the others is a recommendation for Juan, not an implicit scope cut. Grammar: ASCII
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
`subject`, `body`, `attachments`, `via`, and any future explicitly admitted delivery hint.** This
clarifies/amends the current “inner payload with subject/body omitted” wording
in `docs/e2e-messaging-contract.md:504`; it does not change existing header bytes.
The original Go implementation reconstructed that fixed subset (`cli/go/awid/e2ee_messages.go:690`),
as did Python (`server/src/aweb/e2ee_messages.py:218`). At full-scope baseline
`c6235708808b`, attachments are explicitly content-only too
(`cli/go/awid/e2ee_messages.go:703`). New encryptors include
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

For existing native mail/chat, new CLI JSON exposes `via` only from verified signed plaintext or successfully
verified/decrypted v2 content; omit it if absent. Text output may say “Juan via
Telegram” or “Juan via MS Teams”. For native authors keep `verification_status`, `trust_status` and
`verified` unchanged. Bridged-subject messages use the distinct negotiated
participant surface specified below, not this native verified path.
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
  reader without that adapter); no external identifiers in fixtures.
- Native and addressless custodial dashboard neighbors retain verified behavior;
  failed signature/recipient/key proofs cannot be promoted by a provenance label.
- Cross-language Go/Python/TS and old/new published clients, custody RPC and every
  runtime display path: verify, preserve or explicitly document an old-reader
  label omission. No silent encryption fallback. Replay uses existing message IDs.


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

Ordinary alias delivery to linked humans can be server-readable. E2EE alias key discovery currently
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


## Platform rooms are aweb group chat sessions

Juan's decision is to finish existing group chat. Reuse `chat_sessions`,
`chat_participants`, `session_id`, chat message IDs and chat read/history/events;
Cloud binds an external platform/container/thread to that session. There is no
additional room ID, room message log or parallel event/federation protocol.
Mail stays pairwise; multiple mail recipients/threads are not the room solution.

### Existing support and specific gaps

These anchors use `c6235708808b`; coordinator source locations at another main
revision may differ.

- Local chat already accepts multiple participants (`server/src/aweb/messaging/chat.py:271`,
  `:351`; `server/src/aweb/routes/chat.py:1152`). Same-server cross-team alias
  resolution exists (`server/src/aweb/routes/chat.py:944`), and sends target the
  non-left participant set (`server/src/aweb/routes/chat.py:1096`). Reuse these.
- Membership removal storage exists in migration 006
  (`server/src/aweb/migrations/aweb/006_chat_participants_left_at.sql:6`), but
  public add/remove management is missing. `sender_leaving` ends a wait/turn,
  not membership (`docs/e2e-messaging-contract.md:715`). Pending/read authorization
  is not a membership fence (`server/src/aweb/messaging/chat.py:506`).
- History currently checks participation without admission-time visibility
  (`server/src/aweb/messaging/chat.py:631`; `server/src/aweb/routes/chat.py:1882`).
  Group E2EE already uses one ciphertext and per-recipient key wraps; historical
  re-share is explicitly separate and unimplemented
  (`docs/e2e-messaging-contract.md:701`).
- The CLI passes a singleton target (`cli/go/cmd/aw/chat.go:57`), although the
  library accepts a target list (`cli/go/chat/chat.go:1232`). Group creation and
  explicit membership operations need CLI/library/runtime support.
- A session UUID already exists and can be supplied to creation/continuation
  (`server/src/aweb/messaging/chat.py:306`). Pair lookup can reuse a session
  (`:322`): a binding must retain an explicit session handle, never rediscover a
  platform room from its current participant list or a private pair lookup.
- Federation currently refuses multiple/mixed remote targets
  (`server/src/aweb/routes/chat.py:1442`, `:2694`;
  `docs/e2e-messaging-contract.md:722`). Complete group federation in chat;
  do not weaken the pairwise checks or pretend same-server support proves it.

### Membership, stable handle and history

The session ID is the stable handle across membership changes, native/shared/
dedicated transports and delivery restarts. Cloud stores it with its exact
private external locator and conversation kind `chat`. Adding a bot or matching
titles/participants never merges sessions or imports a private pair's history.
Multiple external bindings form a union audience only after explicit approval.
`aw chat` gains additive group-create/recipient-list, membership add/remove/list,
and existing-session send/history selectors; old single-recipient forms keep
their accepted behavior. Group replies target the session, not an arbitrary peer.

Session creation records a membership-management authority/owner and initial
policy through authenticated participant consent. It can delegate bounded guest
admission to a bridge; it cannot issue team certificates or forge native authors.
Native participants use current identity proof; bridged participants use their
typed subject and bridge authorization. Guest admission creates chat membership,
not an agent row, global human address or team/task/console permission. Current
DID-only participant stores/resolvers need explicit typed-reference support.

For an encrypted group, creation and every add/remove/delegation/ownership or
epoch change are canonical records signed by the owner's identity key or an
explicitly delegated participant identity key. Bind session ID, epoch, previous
record hash, exact operation/subjects, resulting membership/history policy and
signer/delegation to the signature. Anchor creation in the independently verified
creator identity and participant consent; a server-supplied root key is not
sufficient. Verify operation-time signing authority, identity-key continuity and
current management-authority revocation/freshness before new effects. A valid
prior transfer remains historical proof after the former owner retires; it does
not authorize new operations by that former owner. Every sender verifies
the complete signed chain from creation (or its already verified prefix plus
all subsequent records), pins its head and derives recipients before wrapping;
a server's current member list alone cannot authorize a new encryption recipient.
Missing records, forks, invalid delegation or stale/revoked authority block send.
All members receive every membership addition/change, with guest refs and
confidentiality consequences visible before new-epoch content, including through
platform projections; no external account IDs are disclosed. Server-only
membership authority is permitted solely in an explicitly server-readable,
labelled session mode; it cannot silently replace identity-signed membership in
an encrypted session claiming E2EE.

Adding a native identity, including cross-team same-server or federated targets,
must pass that identity's current inbound policy and applicable explicit consent
just as first contact does. A pending invitation confers no message delivery,
key wrap, unread item or runtime wake. Only policy-authorized acceptance admits
the participant; refusal has no membership/delivery side effects. A team
certificate, owner signature or bridge delegation never overrides a recipient's
refused inbound policy. Guest admission likewise checks the exact subject's
current scoped consent/admission policy and opt-out tombstone; it does not create
a new account-link requirement for approved external-room speakers.

Membership-owner succession is explicit: transfer to a consenting, currently
admitted identity by a valid owner-signed chain operation before the old owner
leaves or is removed. No implicit successor or server-appointed owner exists.
If the owner leaves/is removed without that transfer, or its authority is revoked
or unavailable, freeze membership changes and new sends/wraps/exports visibly.
Retain authorized history reads; turn completion does not trigger succession.
An already frozen session cannot be rescued by a signature from the revoked
owner or an unrelated team/admin key. Without a prior valid transfer, participants
may explicitly create a new session under fresh consent; old history and grants
are not silently transferred. This chooses freeze as the safe default rather
than inventing authority for the last remaining participant.

Add authenticated participant add/remove/leave operations and membership listing
on chat sessions. Owner/delegated admission is checked separately from sender
membership; only that subject may voluntarily leave itself. Serialize changes
with a monotonically increasing membership epoch and durable admission/removal
boundaries. Send/recipient-wrap validation, continuation lookup, pending/unread,
history-by-message-ID, SSE/wake, attachment reads and external export all check
those boundaries; do not rely on `sender_leaving` or one filtered list endpoint.
Concurrent send/removal commits against one epoch; stale epochs retry/refuse
before fanout. Removed participants receive no future messages or pending
exports. Rejoin creates a new admission interval and does not expose the gap.

For newly managed groups, history defaults to join-forward. An explicit older-
history grant names its authorized range and subject; ordinary join does not
rewrap old ciphertext. Removal cannot erase plaintext or keys already received.
Re-share requires a currently authorized holder of the old content/key, an
explicit audience grant and separately signed re-share record; a server without
keys cannot rewrap, rewrite the old sender's signed envelope or pretend the new
member was an original recipient. Future encrypted messages use fresh per-message
keys and current-recipient wraps, preserving the sender self-copy. Existing
native groups retain their accepted history contract until explicitly adopting
the new membership/history mode; no retroactive narrowing of released clients.

External audience includes silent and unlinked observers; owner approval covers
the whole audience and affected org export policies. Do not claim an incomplete
platform roster proves everyone linked. External platforms may retain or expose
copies independently of aweb admission/history controls. Loss of observation or
uncertain membership freezes unsafe exports visibly. Linked group intake still
applies the activation/link/org/access/custody and anonymous-sender checks above.

### Protected group context and group federation

Native chat keeps existing signed plaintext and encrypted-v2 contracts. The
negotiated group/typed-participant extension protects, structurally:

```json
{"session_id":"EXISTING-CHAT-UUID","membership_epoch":4,"membership_hash":"sha256:...","author_ref":{"kind":"bridged","bridge":"did:aw:BRIDGE","subject":"p7m2"},"message_id":"UUID"}
```

This is chat message context, not a new event kind. Content, `via`, reply linkage
and full recipient scope remain signature-bound. Canonical JSON follows existing
rules. Plaintext includes this context inside signed chat bytes. For encryption,
the negotiated profile binds group context in the sender-signed outer envelope
and mirrors it in protected inner headers, including the header hash; typed
recipient-to-bridge-key bindings are protected, not unsigned routing hints.
Existing v2 validators do not automatically accept such new header semantics:
freeze an explicitly negotiated/versioned extension and old/new vectors before
implementation, preserving current native-v2 bytes. Do not retrofit it as the
content-only optional `via` change or silently permit an unknown version.

Native recipients retain their identity-signed encryption-key assertions. Guest
recipients use the authorized bridge's encryption key and explicit subject scope;
that bridge can read and export their content. Multiple subjects sharing a bridge
key do not share authorization. Guest-signed-as-bridge inputs retain guest author
assurance; no E2EE-to-the-human or platform claim follows. No missing capability,
key or authority triggers plaintext fallback.

Bridge admission changes confidentiality for the **whole session from that
epoch**, not just for guest messages. Enabling external relay requires explicit
bridge admission, never an undeclared exporter. While that bridge membership is
active, every group message includes a wrap for its authorized key (or its sender
self-copy when the bridge sends),
even when native participants are addressing one another. A sender cannot omit
the bridge to create a hidden private sub-audience in that session. Every
participant's CLI, channel/pi/wake/Hermes context, session readback and Cloud/
platform display identifies that epoch as **not E2EE / bridge-readable** before
sending or displaying new-epoch content. Derive that status from verified
membership/confidentiality policy, never from presence or absence of `via`.
Encrypted wire format is then managed
transport encryption, not an E2EE claim. This applies the existing mixed-custody
confidentiality floor (`docs/e2e-messaging-contract.md:268`, `:288`, baseline
`c6235708808b`) to the whole bridge-bound session. A legacy consumer unable to
show/enforce this mode cannot silently participate in that transition. Removing
the bridge cannot restore confidentiality of earlier messages; any later
confidentiality transition requires explicit policy/consent and fresh wraps,
never retrospective relabelling of bridge-readable epochs.

Extend existing chat federation with a negotiated group profile. A session's
membership authority serializes changes and authenticates its route and epoch;
its attestation never replaces the original native/bridge message signature.
Creation/invitation binds the existing session ID to that authority and peer
participation, not a sender-chosen delivery URL. Each authorized peer receives
the same canonical chat message once and fans out only to its eligible local
participants. Record per-peer/participant receipts and full recipient scope;
changed bytes under one message ID conflict. Do not generate distinct pairwise
signed messages under a reused UUID or hide other group participants from the
signed recipient set. Preserve existing receiver-wide replay protection.

Group creation/join, membership updates and message acceptance require current
identity, session-authority and local recipient authorization. Failed/unknown
remote membership changes remain pending; do not report a member removed while
continuing delivery on an unconfirmed replica. Unavailable authority fails closed
with retry. Recovery/migration needs an authorized checkpoint, not a new host
asserting ownership of a session. Existing pair federation remains accepted and
retains its own capability/refusal boundary. Group federation remains designed
in full scope; Juan decides delivery order.

External outbox intent is per chat message, approved binding and chosen sender
presence, not per guest. Capture routing/audience/presence epochs at source
commit so later settings cannot export old unclassified content. API acceptance,
aweb read state and runtime completion are separate receipts; unknown effects
follow the recovery section below. Cloud owns endpoint maps and arrival metadata;
OSS owns these group-chat extensions and complete participant-authorized public
reads. Dashboard/session UI support is Cloud work, not a second hidden protocol.

Platform capability is a real constraint: Telegram bot-to-bot visibility is
conditional on mode/admin/privacy settings
([official features](https://core.telegram.org/bots/features#bot-to-bot-communication));
Teams can receive room messages without mentions through resource-specific
consent where installed
([official group/channel contract](https://learn.microsoft.com/en-us/microsoftteams/platform/bots/how-to/conversations/channel-and-group-conversations)).
Cloud owns exact app permission, credential, install and platform-limit evidence.
Neither aweb membership nor an attached token fabricates missing platform access.
If a platform cannot support a requested operation, report the precise capability
and options to Juan; do not relabel a narrower mode as full functionality.

## Dedicated and native presences for any identity

A dedicated bot is a presence **of** an identity. It does not replace that
identity, confer team membership or require Cloud to hold that identity's key.
Global self-custodial, local, hosted/custodial identities and bridged subjects
all have explicit binding paths. For a local identity, room/team/service context
is part of the binding; copying its display alias to another service is not
continuity. A guest-subject bot remains platform-attested unless a native key
is separately proved. “Any identity gets its own bot” does not authorize one
person to attach a bot to somebody else's identity.

The human attaches credentials through their authorized owner session plus an
identity-bound proof/authorization. The service validates actual bot ownership
and installation/reachability; the public binding stores only an opaque provider
registration reference, subject, platform, mode, scope and generation. Tokens,
tenant/object IDs, bot account locators and refresh secrets stay provider-private.
A nonce proof from the actor's current key, or an authenticated owner operation
under a configured ownership authority, is required. Team-controller status alone
is not a universal human ownership proof. A hosted service can sign for actors
it actually holds; for a self-custodial/BYOT identity it verifies that actor's
proof/delegation and operates transport without acquiring its key.

The aweb message already bears its author's signature. Export verifies it, then
selects the registered bot for that same author/principal. Text labels never
choose credentials. Other observers of the dedicated bot resolve its proved
principal binding, not a newly minted guest each time. Observing a bot post
without the matching aweb content proof is still only platform observation.
For an externally owned identity with no Cloud team, the presence/room resource's
hosting org supplies service/consent policy; it cannot pretend to be that
identity's team controller. Authorized non-Cloud self-hosters consume the same
public interfaces, not private hosted operations.

### Native registration and ownership changes

Proposed canonical intent fields: `version=aweb-presence-intent-v1`, operation,
subject reference, platform, explicit scope, `mode=native`, service audience,
expected generation, unique request ID, issued/expiry timestamps. Sign canonical
JSON with the acting identity's key; verify request/body and signer binding,
current global key/log or local authorized context, audience, freshness, replay
and compare-and-swap generation. An unrelated member cannot suppress Alice.
Existing mail-send grants do not implicitly grant presence administration.

Two authorization lanes: (1) subject's own valid signature; (2) owner's signed
intent plus the configured service's independently verified ownership/delegation
binding for that exact subject. A Cloud browser operation must authenticate its
real owner and use its existing custody path to sign; a request claiming an
`owner_did` is not proof. Public consumers trust only the configured ownership
provider for that service, not an arbitrary issuer URL in the request. For a
bridged subject, its authorized bridge can prove control only within the room/
provider policy; it cannot act as the owner of a native identity merely by mapping
an external account. Owner transfer/revocation invalidates old management rights.

Scope supports platform-wide suppression and explicit room/conversation grants.
The earlier platform-wide native registration is the wildcard case: it disables
all Cloud relay for that actor/platform. A scoped declaration permits mixed
native and dedicated operation in different rooms only if Juan chooses that
policy; it is never inferred from online status or a bot seen in a room. Resolve
overlap deterministically with native suppression winning; do not reenable
relay because native health/lease information becomes stale. Removal/replacement
requires authorized generation change and cancels old pending work. Bound bots
still require explicit owner rebind; old replies cannot select the new bot.
If the native adapter is down or cannot acknowledge delivery, expose pending or
failed native delivery to the sender (proposed reason `native_unavailable`),
with retry/recovery state. Retaining the aweb message does not mean it reached
the native runtime. Never silently drop it or enable bridge fallback; only an
authorized ownership change can select a different transport.

### Native room interoperation and loops

Registration alone is not enough. Required generic `native-chat-receipts-v1`
interoperation allocates one input-processing owner per `(agent,session_id)` and
canonical source/event identity. Native and aweb adapters exchange private
transport correlation/acknowledgments with the gateway. If the native adapter
owns the human input, aweb retains the chat message for history/other participants
but does not wake that same agent again. Other agents still receive it normally.
Native output submits that agent's own signed aweb chat message, then its native
transport publishes/records the correlated external result; bridge export is
suppressed for that owner. Merely importing observed text under the agent DID
would forge authorship and is forbidden.

Bridge-operated shared/dedicated agents need no runtime Telegram/Teams knowledge.
A native adapter already knows its platform and must implement this generic
correlation interface for complete cross-room operation. Hermes specifically
needs source-ID/proof correlation, generic room context, durable seen/route state,
model-visible author assurance and a room reply that does not unconditionally
leave (`packages/hermes-aweb-platform/adapter.py:114`, `:216`, `:283`, `:328`,
baseline 786b67f79977). Existing unsupported native integrations may keep their
old isolated behavior; the full build must supply the adapter work before
claiming interoperable native rooms. It is not accomplished by registration UI.

One gateway ingestion owner consolidates all bot deliveries for a bound room.
Use authenticated platform logical message IDs across bots only when the
platform supplies a stable shared identity. For Telegram supergroups, use the
chat-wide `message_id` with the chat binding; for basic groups and private chats,
message IDs are account-relative, so select one content intake owner instead.
Never use `update_id` as cross-bot identity. See Telegram's
[message ID sequences](https://core.telegram.org/api/updates) and
[Update contract](https://core.telegram.org/bots/api#update). Other registrations'
observations cannot trigger a second import or runtime execution; no text/time
heuristic deduplication. Intake ownership remains bot-wide, not two consumers of
one bot's queue split by room. Persist inbound event -> canonical chat message
and outbound event/part -> transport result; discard owned-bot echoes and known
native exports before subject creation. Stable IDs do not stop novel bot loops:
retain per-room/pair rate budgets, interaction depth/timeouts and circuit breakers.
Native/bot transitions preserve tombstones; restart never resets loop protection.

### Durable ownership and unknown outcomes

The guarantee is one authorized input owner and deduplicated committed logical
replies, **not exactly-once model/tool execution**. Existing read state is not an
action transaction (`docs/receiving-events.md:293`, baseline `c6235708808b`);
message acceptance receipts cover messaging effects, not arbitrary runtime tools
(`docs/identity-messaging-contract.md:169`, same baseline).

Before dispatch, persist one operation keyed by `(agent, context, canonical input
ID)`, its immutable input digest, selected native/aweb owner and generation.
Acquire it with compare-and-swap, an increasing fencing token and a renewable
lease. Both adapters must consult this same durable authority; local seen caches
are insufficient. Record `claimed`, then durably `started` before model/tool
work; commit reply records and their outbox intents durably before acknowledging
completion. A claimed operation known not to have started can be reassigned by
advancing its fence. Replays with another digest conflict.

All reply commits, completion updates and adapter-owned exports check the current
fence; a stale owner cannot publish a late reply. Before each external tool call,
check the fence and journal its immutable intent and stable effect ID durably;
record the result before advancing the checkpoint. Each logical reply has a stable
operation/reply-slot ID and fixed signed message bytes, atomically recorded with
its outbox intent. Retries reuse that record, not a fresh model response or new
message UUID; conflicting bytes for an occupied slot refuse. Transport receipts
are separate from runtime completion. Durable native output records carry the
original author's signature, not a signature fabricated by the bridge.

A lease expiring after `started`, or a crash after a tool acts but before its
receipt is stored, yields **`outcome_unknown`**, never automatic fresh execution.
Quarantine the operation and show the sender that processing is unresolved.
Fence the old worker's writes; also stop/quiesce it or establish external effect
fencing before resuming work. Lease expiry alone cannot stop a tool already in
flight. Recovery first reads durable runtime checkpoints, reply/outbox records
and tool/provider receipts using stable effect IDs derived from the operation.
Reuse a committed reply; reconcile a known effect or resume after a proved safe
checkpoint. An external operation with a genuine idempotency/query contract can
be retried/reconciled with the same effect ID. Absence of a local receipt is not
proof that the effect did not happen.

If an effect or platform send cannot be reconciled or safely retried, keep it
blocked for explicit owner/operator resolution, recording evidence and the
chosen outcome. A deliberate retry with duplicate-effect risk requires an
explicit decision and an auditable new attempt; do not describe it as exactly
once. A platform send with unknown acceptance is not blindly resent just because
its outbox lacks a completion mark. Native/aweb ownership transfer cannot bypass
these unresolved operations. Runtime execution can repeat only where recovery
establishes safety or an authorized decision accepts that risk; committed reply
deduplication does not claim to deduplicate every model call or external effect.

## Chasing and delivery sequence: designed into the full architecture

Reserve `delivery_hint={"platform":"telegram"}` (or another defined kind) in
signed native plaintext or encrypted inner content; keep it advisory and
account-free. Cloud selects an exact endpoint only within human consent, org
policy, quiet hours, rate budget, binding and native-ownership rules. A chase is
another delivery attempt for the same aweb message, not a fresh author message
or a second usage count. Persist attempt identity per endpoint; do not replay old
messages after consent/settings changes. A room hint cannot escape the room's
audience into an unrelated DM; any permitted notification/export must preserve
its approved audience/content policy. No automatic decrypt or E2EE-to-readable
fallback follows from a hint. An encrypted server cannot read a concealed hint.

Proposed delivery order for Juan: settle the identity/room/presence contracts
and vectors, build their complete generic path, then prove full Telegram and
MS Teams (shared/dedicated/native, private exchanges and rooms) against it;
activate Slack, WhatsApp and chasing in an explicitly agreed sequence on the
same architecture. This is a sequencing recommendation, not an authorized
scope reduction or a separate half-featured architecture. If Juan wants their
activation together, the common model already includes them and the platform
adapters/consent evidence must be completed accordingly.

## Decisions for Juan and acceptance

| Decision | Recommendation | Consequence |
| --- | --- | --- |
| Unlinked room identity | Bridge-signed first-class guest subjects (B with stable participant refs) | Honest assurance without per-guest native keys; requires typed ACL/reply/runtime support. A remains an alternative with key/log/custody-classification cost. |
| External room admission and history | Owner-approved guest admission, join-forward aweb history, explicit whole external audience acceptance | No mandatory Cloud signup, no team membership, and no claim that platform copies can be revoked. Stricter all-linked rooms require proved evidence. |
| Guest correlation scope (Cloud J1) | Recommend pairwise/session-scoped guest subjects; cross-room correlation requires Juan's explicit choice | Stable within a session and across its intake bots, with session context in derivation; cross-session association/history requires explicit authority, never an automatic merge. Bridge/platform-wide subjects remain a designed alternative. |
| Compromised bridge key | One tested, independently authorized “revoke bridge” operation orchestrates disabling ingress/dispatch, canceling pending work, revoking all bridge admission/send delegations and starting authorized key recovery | Bot-token rotation alone is insufficient. Report incomplete revocation scopes and keep them blocked; remote consumers apply authoritative revocation/freshness checks, with no claim of instantaneous global propagation. Test a freshly signed old-key guest event after revocation. |
| Membership-owner succession | Explicit signed transfer to an admitted consenting successor before departure; otherwise freeze | Owner removal/revocation cannot appoint the server or last participant as successor; frozen sessions retain permitted history, with fresh-session consent as the safe restart. |
| Native scope (Cloud J4) | Recommend explicit platform-wide suppression per identity initially; per-session mixed transport requires Juan's explicit approval and the same fenced input ownership/native-signature interop | Never infer an exception from activity or health. Both modes remain designed in; choosing scoped operation adds ownership/configuration complexity, with native suppression winning on overlap. |
| Identity linkage | Future association by account/key/session authority, no historical rewrite or silent contact transfer | Prior guest posts stay platform-attested; native identity requires its actual key authority. |
| Delivery order | Complete common core plus full Teams/Telegram, sequence remaining adapters/chasing by explicit decision | No feature is silently cut. Platform impossibilities/permission denials are raised as decisions, not hidden behind “v1”. |

Required behavior coverage for the full implementation:

1. Native linked author remains verified; guest shows platform-attested and
   unverified author with verified bridge signer and distinct external/untrusted
   model-visible trust status in channel/pi/Hermes and readback. Forged
   subject/bridge/epoch, fresh omitted guest author, wrong signature and
   unavailable authority refuse.
   Old native messages still work; incapable consumers cannot receive guest
   events as native messages. Local/global/self-custodial/grant cases distinguish
   identity proof from room and presence authority.
2. Unlinked human and external-only agent enter only their authorized room as
   guests; no team/task access. Two same-name people stay separate, one subject
   across bots is deterministic within the chosen scope; subject-key loss yields
   new subjects without reassignment, and later linking cannot seize history/contacts.
   Linked room posts recheck activation, link, org switch, access and custody;
   anonymous-admin/`sender_chat` posts refuse without actor or guest fallback.
3. Join/remove/rejoin, concurrent send/removal, audience/room-binding change,
   history boundaries and loss of observation all enforce current grants. Native
   and multi-platform peers see one canonical chat message; replay/conflict and
   offline authority preserve signatures and recipient scope. Exercise three-plus
   participants through CLI/session APIs, cross-team same-server membership,
   direct history/message/attachment reads before and after join/remove/rejoin,
   and explicit encrypted re-share with no fabricated original-sender signature.
   Group federation covers mixed local/remote participants, receipt replay and
   stale membership epochs; existing pair mail/chat and native-group reads remain
   valid. A stable session handle survives roster changes without pair lookup.
   Forged server-only adds, truncated/forked membership chains and stale owner
   keys cannot induce wraps; every sender checks signed membership from creation
   and every member sees additions. Refused same-team/cross-team/federated adds
   produce no messages, unread state or wakes. Valid owner transfer continues;
   departure/removal/revocation without transfer freezes visibly. Bridge admission
   includes its wrap on every later message and marks the whole session not E2EE
   for all consumers; removal never relabels earlier bridge-readable history.
4. Dedicated bot for hosted, self-custodial and local identities exports only
   messages authorized by that identity; wrong owner/token/alias binding refuses.
   Native registration is subject/owner authorized, replay-fenced and scoped;
   unauthorized registration cannot deny delivery. Health expiry never enables
   an unintended fallback; native downtime is visible non-delivery, never a
   silent drop; bot changes require rebind. The single compromised-bridge
   revocation operation rejects fresh old-key posts in every affected scope and
   exposes incomplete/unavailable revocation rather than reporting success.
5. Two bots observe one room: Telegram supergroup IDs deduplicate across bots;
   basic groups/private chats use one intake owner, never cross-bot `update_id`.
   Mixed native Hermes/aweb input and immediate fresh-ID bot replies preserve
   one input owner, bounded interaction, no guest echo and deduplicated committed
   replies. Crash probes cover before start, after a tool effect but before its
   receipt, after reply/outbox commit and during unknown platform acceptance.
   Expired owners cannot commit; unresolved effects stay visibly blocked until
   reconciled or explicitly resolved. No exactly-once execution claim.
6. Same-team human first contact and typed guest replies work through real `aw`
   and real servers; unknown external bare DIDs still refuse. Complete public
   list/history/receipt and dashboard fallback covers native pair, guest direct
   and rooms. Attachments follow `docs/attachments.md`; no public-link shortcut.
7. Full Telegram groups/topics and Teams chats/channels plus private exchanges,
   all three presence kinds, are exercised with real approved platform test
   resources, real native runtimes and published consumers. No mock provider or
   fake `aw` satisfies that final acceptance. Platform consent/permission failures
   and no-E2EE disclosure remain explicit; no production resources are created
   by this design task.

This proposal changes no executable behavior or accepted vectors. Prior acft.5
focused fixture tests and released-bundle inspection remain evidence only for
the retained native provenance/alias analysis, not proof of these new contracts.
Implementation must update public contracts, canonical vectors and consumers
with ordered migrations where needed. Review is the assigned independent
protocol reviewer, plus Athena for correctness/security. Scope decisions belong
to Juan. Identity-path implementation still needs Juan's explicit approval in
its commit. Cloud's single document must name these protocol prerequisites and
link its exact reviewed proposal SHA, rather than invent a second public grammar.
