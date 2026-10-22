# P3: typed chat participant readiness

A native participant has an aweb DID. A guest has the existing P0 tagged
reference `{kind: bridged, bridge: did:aw:…, subject: …}`. The bridge holds its
own signing key and private account mapping; it does not create a key, agent,
team certificate or native address for the guest. Only a session's signed
membership authority can admit that guest. P3 supplies storage and identity
helpers; P4/P5 supply that authority and its activation.

This implements the [decided guest model](human-channels-contract-proposal.md#unlinked-people-and-external-only-agents-a-versus-b)
and [P3 plan row](human-channels-oss-build-plan.md#p3--typed-session-participant-storage-and-authorization-identity).
No P0 DTO, signed message, native encryption profile or released vector changes.

## Storage and activation

Migration `033_typed_chat_participants.sql` extends both existing
`chat_participants` and `conversation_participants`. Each row has a
`participant_id`, `participant_kind`, and optional `bridge_did`, `guest_subject`
and `guest_opted_out_at`. Existing rows and inserts default to `native`, retaining
their original DID/alias/route/key/agent values. Native DID uniqueness and
`ON CONFLICT (session_id, did)` / `(conversation_id, did)` keep working. The
exact native read-receipt foreign key and cascade are reattached within the same
migration transaction, without dropping unrelated constraints.

The physical DID column becomes nullable; a tagged-reference CHECK still
requires a native DID and forbids native rows from carrying guest fields.
Bridged rows have no DID, agent ID, native address, key or delivery origin.
Their unique lookup is **session/conversation ID + bridge DID + subject**, never
display name. Conversation guest rows use the chat transport and participant
role. P4/P5 must additionally enforce the chat-session parent, signed membership,
current bridge delegation, admission policy and message/history authority.

Both tables have a named `*_p5_gate` CHECK that permits only native rows. **P3
does not activate guest storage through a public service or advertise a managed
capability.** P4 can build its policy/verifier storage while this gate stays in
place. P5 must remove the gates in a new reviewed migration only with its J9
consent, bridge-readable session label, membership/history fences and published
consumer activation/refusal tests. There is no runtime flag bypass.

The future typed-storage test removes the gates only in its isolated disposable
database to verify the prepared schema. It proves separate same-name guest
rows, exact-context uniqueness, absent agent rows and opt-out retention. It is
not a public create/list journey; that acceptance remains at P5.

The existing native `ensure_session` and conversation embedding inputs also
refuse an explicit bridged tag/reference before writes, even if a caller supplies
the bridge's native DID alongside it. They cannot discard the tag and admit that
guest as the bridge. This adds no managed service entry point.

Native create-session responses and internal conversation participant views gain
an optional `participant_ref`. The old fields retain their values. Historical
native strings that are not P0 references keep their old projection, with the
new optional reference omitted/null; no migration reinterprets them as guests.
Go's native `ChatParticipant` remains its existing DID/alias/address DTO and
ignores the additive projection field, like released native clients. It does
not decode a bridged union or introduce a new response-decoding error after a
send has committed. Managed participants belong to P0's separate negotiated
SessionView surface. P5 must refuse an unsupported managed operation before
any send/commit; P3's database gates and closed native requests already refuse
guest admission before effects.

## Pairwise identity and private mapping

Python `derive_guest_reference` and Go `DeriveHumanChannelsGuestReference`
implement the same bridge-private deterministic construction:

1. Hold an independent subject key of at least 32 random bytes. Do not use a bot
   token or identity signing key. The bridge owns the key and its generation.
2. Canonicalize the UTF-8 JSON object with keys `version`, `bridge`, `platform`,
   `account_scope`, `account_id`, `subject_kind`, `generation`, `session_id`.
   `version` is `aweb-guest-subject-v1`; canonicalization is the existing sorted,
   compact JSON convention. `subject_kind` is `human` or `bot`.
3. Compute HMAC-SHA256 under that key and encode base64url without padding.
   Return the P0 bridged reference containing only the bridge DID and digest.

Scope/account values are exact adapter identifiers, not display names. Each
private text input is nonempty and at most 4096 UTF-8 bytes. No intake bot ID
appears in the tuple: bots of this bridge share the same subject key/generation,
so the same account in one session has the same subject across bots. Another
session, account, scope, subject kind, key or generation yields another subject.
The derivation is not a new public wire record; none of its private inputs,
generation or key enters message content, provenance or agent-visible routing.

Key loss requires a new key/generation and new subjects. The helper supplies no
history/contact recovery or reassignment from names. Cloud/bridge storage must
retain private account opt-out tombstones independently across subject-key
changes; inability to establish current consent refuses automatic admission.
The per-reference timestamp preserves a known guest's opt-out in OSS storage;
observing another post must not clear it. Re-admission needs P4/P5's explicit
consent and authority checks, not a new hash or a recreated row.

A later explicit link to a native human identity creates a distinct reference.
It never rewrites old platform-attested authors, reassigns old guest history,
clears the opt-out or implicitly grants cross-session continuity. Any explicit
association/history grant needs its own authorized consent path. P3 introduces
no association or native-impersonation endpoint.

## Context and assurance

`scoped_participant_key` / `HumanChannelsScopedParticipantKey` bind the existing
session UUID to the complete tagged reference. They are local exact lookup keys,
not public addresses. A guest reference cannot match the bridge's native DID,
another guest, another bridge or another session.

`project_session_author` / `ProjectHumanChannelsSessionAuthor` consume P0
GroupContext and independently verified signer facts. They check the exact
expected session/reference and bind native authors to their resolved signer
principal, or guest authors to their bridge. An invalid/unverified signer or
wrong context refuses. A verified bridge signature produces
`signer_verified=true`, **`verified=false`, `trust_status=external_untrusted`,
`author_assurance=platform_attested`** for its guest. Guests cannot receive an
E2EE label. Native and hosted-custodial neighbors retain their separate assurance.

For a native author, the caller must also supply `native_trust_status` (Python)
or `nativeTrustStatus` (Go) from independently verified metadata for that exact
author: `verified` or `verified_custodial`. Missing/unknown native status refuses
as `authority_unavailable`. The status is retained across session confidentiality
labels; a bridge-readable session does not turn a custodial native author into
a self-custodial one. See [native trust outcomes](trust-model.md#tofu-pins-and-durable-continuity).
This fact is not inferred from `via`, a session label or an unverified submitted
claim. Guest projection ignores this native-only fact (normally None/empty for
guests) and always retains `external_untrusted`. Current policy still determines
the separately supplied confidentiality label before calling this helper.

These projection helpers do not perform cryptography, resolve current keys,
verify a membership chain/epoch or authorize a history interval. P4/P5 must
establish all those facts before calling them in a managed-message read/send
path. A successful projection is not a grant. P3 does not change what an existing
message verifier calls `verified`.

The typed metadata lookup `lookup_participant_identity_metadata` never looks up
a guest using the bridge's DID as the human. Guest metadata cannot produce a
native alias/address fallback; replies require the stored typed session route.
Native DID metadata lookup remains unchanged.

## Evidence and remaining activation

Shared root vectors exercise pairwise derivation and native/guest projections
in Python and Go, including independent custody neighbors under the same
session label, missing native metadata, wrong bridge, subject, context, invalid
signer and link-promotion refusals. PostgreSQL tests cover fresh migrations, an actual
populated pre-P3 upgrade, retained native values/read-receipt cascade, old
conflict targets and the P5 gates. Native schema/service neighbors remain valid.
The live local OSS HTTP/AWID/PostgreSQL/Redis journey creates an ordinary native
chat with typed projection, then refuses a managed/guest request without a new
message, participant, agent or mutation-hook effect.

Public guest admission/listing, opt-out mutation, authorized association,
membership/history reads, managed message fanout and runtime guest display
remain gated P4/P5/P6 work. No private Cloud SQL, new room log or principal
registry is introduced.
