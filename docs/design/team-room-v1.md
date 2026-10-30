# Team room v1

Status: **approved contract; implementation awaiting release**. Task: `aweb-acpi`. This advances goal 1,
“Make aweb.ai a significant business”, by allowing a team announcement without
manual recipient fan-out. Identity/auth review accepted the original contract
at `960c13f371397d3af9229cf4644b51a62715ecb9` (Athena, mail
`62c65bc5-090b-438e-a425-b4bbb886ae2c`). Juan approved full history on
2026-10-30 (coordinator relay `351408ad-b317-4af3-ab13-696e856892f9`).
This feature ships separately from the current identity-tree release candidate.

## Model and authority

There is one append-only room per team at the selected messaging service. It is
server-readable. Every current member may read retained history and post.
**Posts are visible to current and future team members and to the service
operator.** Joining exposes existing room history. Removal or certificate
revocation ends subsequent service access within the existing team-auth cache
bound; it cannot erase a copy previously fetched. Juan approved this history
policy on 2026-10-30.

Custody and controller authority remain separate. Fully Hosted teams use their
existing hosted controller; BYOT teams use their existing customer controller.
The team controller authorizes membership, not a new room identity or a
member's signing key. A local member signs as its `did:key`; a global member
signs as its current `did:key` with its verified `did:aw`. A custodial actor
uses that actor's existing hosted signing operation. There is no room address,
room key, shared team signer, or new authority to enroll members.

The governing separation of membership, signing and routing authority is in
[identity and messaging](../identity-messaging-contract.md#authority-boundaries).
Existing conversation IDs are not authority and existing signed messages are
never moved into a room.

## Admission on every request

HTTP read and post use the existing
`team_identity_with_grant_scope("chat.read")` and
`team_identity_with_grant_scope("chat.send")` dependencies respectively. These
reuse current certificate verification, member resolution and grant validation;
there is no room ACL cache or room membership projection. Metadata and exact
message reads require `chat.read`. A grant's actor is its subject, never its
session key. A mail-only grant is refused. The room adds no grant scope or
change to the existing path-to-scope mapper.

The CLI discovers the room through metadata before signing a post, so
`aw room post` requires both `chat.read` and `chat.send`. A `chat.send`-only
grant can submit an already signed post directly to the HTTP post endpoint
when it already knows the room ID; it cannot discover that ID through metadata.

The production entry points being reused are
`server/src/aweb/team_auth_deps.py:305-335,351-361` and
`server/src/aweb/identity_grant_auth.py:203-258`. Their current registry/cache
rules remain authoritative; room-specific TTLs or outage fallbacks are absent.

For hosted MCP, ordinary trusted-proxy authentication remains responsible for
binding the actor and team. The new room adapter additionally checks current
membership through the existing certificate-revocation enforcement before
each operation. It refuses missing/ambiguous team context, inactive/deleted
actors and a stripped membership. It does not accept a caller-supplied actor
or team as authority. Use the production check in
`server/src/aweb/identity_auth_deps.py:179-236`, not a copied revocation check.
If existing trusted-proxy evidence cannot establish current membership, refuse
room access rather than changing existing MCP authentication.

“Team-local” means access through a verified membership in this team at this
service. An identity with an external address and a valid local membership is
still a member. A foreign principal without that membership, a remote
conversation participant, public team visibility and a federation delivery
envelope confer no room access. No federation room endpoint exists.

## Additive HTTP surface

All endpoints resolve the team from authenticated context. The room's UUID is
a service-created identifier, stable across process restarts and never reused
for another team. An authorized metadata read may lazily provision the empty
room metadata row; this creates no message, event or recipient delivery.

| Operation | Request | Result |
| --- | --- | --- |
| Metadata | `GET /v1/room` | `team_id`, `room_id`, `confidentiality: "server_readable"`, `history_visibility: "current_and_future_members"` |
| History | `GET /v1/room/messages?after=<cursor>&limit=<n>` | `messages`, `next_cursor`, `has_more` |
| Exact read | `GET /v1/room/messages/{message_id}` | One original post in the caller's room |
| Post | `POST /v1/room/messages` | Original stored post, including IDs and server receipt time |

History is oldest-first, using a server-assigned monotonic sequence and keyset
pagination. Default limit is 50, maximum 200. A cursor binds its team and room
and is validated on every read; it is never an access token. A cross-room or
malformed cursor is refused. A page of exactly `limit` entries is not evidence
of completeness; clients follow `has_more` and `next_cursor`.

Missing authentication is 401; ordinary revoked-certificate refusals retain
the production team-auth 401 (`server/src/aweb/team_auth_deps.py:239-247`).
Missing membership or grant scope is 403;
unavailable authoritative membership evidence is 503; a message outside the
selected room is 404. Invalid envelope shape, timestamp or binding is 422;
an invalid post signature is 403; conflicting message ID reuse is 409. These
are room statuses, not changes to existing mail/chat statuses. Record
the underlying authorization/verification error through the existing logging
path, without logging post bodies or private key material.

## Existing signed-message envelope

Reuse the existing plaintext message envelope and canonical signing bytes
(`cli/go/awid/signing.go:88-122,448-490`) with `type: "chat"`. No new signing
family, message type, existing mail/chat validator or envelope is introduced.
An illustrative signed payload is:

```json
{
  "body": "The announcement",
  "conversation_id": "<room UUID>",
  "from": "<authenticated address or member alias>",
  "from_did": "<authenticated member did:key>",
  "from_stable_id": "<verified did:aw, omitted for local members>",
  "message_id": "<sender UUID>",
  "subject": "Release update",
  "timestamp": "<RFC3339 timestamp>",
  "to": "team-room:<exact authenticated team_id>",
  "to_did": "",
  "type": "chat"
}
```

The post request carries `room_id`, `signature`, `signing_key_id` and the
original `signed_payload` string. The server derives content and sender from
those signed bytes. It verifies the Ed25519 signature, authenticated sender
key/stable ID, exact signed team target, `conversation_id == room_id` and
the selected room's ownership before storage. A room target is a typed team
selector, not a DID or routable address; `to_did` is empty. The signed
`team-room:` target and exact room/team bindings distinguish this from
recipient-addressed chat and prevent cross-room replay. That target is outside
the ordinary alias, address and DID namespaces, and the existing chat validator
requires its signed target to match its actual recipients
(`server/src/aweb/routes/chat.py:194-218`). No existing resolver gains a
room-target interpretation. Extra delivery/wait/attachment
semantics are not accepted by this new surface.

Preserve the original signed payload and signature without normalization.
Readers verify those bytes and require displayed content, sender, message ID,
room ID and team target to match. Signature validity alone does not prove
current membership, global key continuity, or a human attribution.

All room posts have a unique `message_id`. After authenticating and checking
the signed bindings, an exact replay returns the original stored post without
changing its sequence, receipt time or carrier. Reusing an ID for different
signed bytes is 409, including a cross-room collision; no foreign post is
returned. Fresh ingestion applies the shared timestamp-skew rule. Reading or
retrying an already accepted exact post does not expire it; request
authentication still has its ordinary fresh timestamp requirement. Signature,
binding and timestamp failures have no post effects.

## Accountability carrier

Reuse `X-AWID-ID-Chain`, authenticated after ordinary sender authentication by
`server/src/aweb/id_chain_auth.py:30-70`. Store the admitted chain in a JSONB
column beside the message, outside the signed bytes, following migration 042.
Return it unchanged on history and exact reads. Grant admission binds it to
the subject as in `server/src/aweb/identity_grant_auth.py:212-217`.

Readers re-verify the stored chain against the post's `from_did` and verified
stable ID using the existing verifier/current evidence. A carrier is neither
a new sender identity nor independent proof of responsibility. Extend
`aw who --message-id` to find an exact room post through the room read API
and pass it through that same verifier; do not add room-specific attribution
fields or alter existing mail/chat results. Existing mail lookup errors must
not be disguised as a room lookup or a missing message.
`aw who --room --message-id` selects the room directly, so a chat-only grant
needs no mail scope and IDs that also occur in mail remain unambiguous.

## CLI, channel/Pi and hosted MCP

Expose `aw room read` and `aw room post --subject ... --body-file ...`, with
normal identity-home/team selection and JSON output. Before a post, disclose:
“Team room posts are readable by the service operator and all current and
future team members.” Put the same disclosure in the new MCP `room_post`
tool description and result metadata; `room_read` returns the same signed
records and history policy. The disclosure is present on every post surface,
so no hidden first-use tracking or additional consent store is required.
CLI post disclosure goes to stderr before sending, keeping JSON stdout a
single document. Direct self-custodial MCP callers supply `signed_post` in
the same HTTP post shape; the service never signs on their behalf.

Terminal, channel and Pi agents explicitly invoke these CLI commands; no
push adapter or wake loop is needed. Hosted MCP signs as its authenticated
custodial actor through the existing hosted signer, then calls the shared
room service. No direct unsigned MCP insert is accepted. Existing MCP tool
names, descriptions, outputs and authentication behavior remain unchanged.
Cloud adoption and its migration mirror belong to the assigned Cloud owner.

V1 rejects explicit E2E intent before a post request: `--e2ee` or equivalent
tool/request intent returns `room_e2ee_unsupported`; there is no plaintext
retry. Do not claim confidentiality from the operator. The existing E2E
contract uses per-recipient wraps, rejects unsupported federated groups, and
gives a mixed-custody group its least-private participant's confidentiality
floor ([E2E contract](../e2e-messaging-contract.md), lines 35-39, 268-289).
V1 adds no encrypted room key distribution or historical rewrapping.

## Compatibility and validation

Use a new ordered migration for room metadata and posts. No existing migration
or mail/chat storage schema changes. Keep room posts out of existing inboxes,
chat pending, conversation indexes, SSE and read acknowledgements. There are
no wakes, broadcasts, edits, deletes, attachments, federation or expiration
policy additions in this feature. Older clients continue using their existing
APIs. An upgraded room client refuses unsupported room APIs without falling
back to manual mail fan-out.

Room posts count as activity under the existing operator-controlled inactive
team cleanup. Existing hard deletion of a team also removes its room and posts;
the new tables must not block that operation. This introduces no individual
room-post expiration or deletion API.

Implementation starts with behavioral tests, including real production
authorization paths: local/global/self-custodial/hosted members, BYOT/hosted
certificate authority, grant subject and scope, revocation/removal and
unavailable evidence, nonmember versus valid externally addressed member,
cross-team IDs/cursors, signed content/target tampering, idempotent versus
conflicting retries, timestamp skew, exact reads and page boundaries,
carrier verification, mixed actor room exchange and unchanged old mail/chat
and MCP responses. Run checks and complete affected test packages on each
implementation head; record what the harness establishes. The implementation
reviewer reads the protocol/server change. Identity/auth review accepts this
contract first; any actual change to an identity path needs Juan's explicit
approval through the coordinator and recorded in its commit.
