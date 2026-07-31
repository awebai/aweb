# Messaging Contract Matrix

Status: **subordinate maintainer conformance inventory**. These cases identify
what tests and release evidence must prove. They do not override the current
user, event, identity-routing, or E2E authorities listed in
[`messaging.md`](messaging.md).

## Authority controls

- AWID owns global identity/address bindings, current keys, address-route
  origins, team public keys, and revocation records. Active same-team delivery
  authority comes from a presented controller-signed certificate verified
  against the current team key and non-revocation, not registry row existence.
- Aweb owns durable mail/chat, conversations, participant routes, recipient
  delivery policy, read state, and wake events.
- First-contact routing uses a concrete global address or valid same-team alias.
  A conversation/session continuation uses stored participant route state but
  still evaluates the recipient's current delivery policy.
- `conversation_id` and chat `session_id` select existing state; neither is
  routing or participant authority by itself.
- Self-custodial clients own private keys and local plaintext presentation.
  Hosted custodial tools are server-readable hosted messaging.
- A verified local-alias sender requires a valid message signature and recipient
  binding plus a no-cache, team-certificate-authenticated current-roster row
  whose exact alias has a non-empty local DID equal to the signed `from_did`.
  Cache, public/dashboard lookup, registry continuity, and TOFU are not proof.

## Identity, routing, and continuation cases

Cover these cases for mail and chat wherever the operation exists:

1. Same-team bare alias.
2. Same-team full address.
3. Same-team alias first contact followed by full-address continuation.
4. Cross-team same-namespace send with an explicit team selector.
5. Cross-namespace address first contact with `inbound_mode=open`.
6. Cross-namespace address first contact with `team_and_contacts` and an exact
   active identity contact.
7. Cross-namespace address first contact with `team_and_contacts` and verified
   same-team membership but no exact contact.
8. Cross-namespace first contact without the required route/contact/team
   authority fails closed.
9. An existing participant continues by stored route without repeating address
   discovery, while current recipient policy is still enforced.
10. Bare external `did:aw` first contact fails closed; stored-route continuation
    remains valid.
11. Identity key rotation preserves a correctly bound conversation route.
12. A local identity has only team-local alias/stored-route delivery.
13. A global identity in multiple teams remains one identity; active team selects
    sender context.
14. Adding an existing identity to another hosted or customer-controlled team
    does not clone the identity.
15. Duplicate aliases across teams require concrete address or team context.
16. A hosted custodial identity satisfies the same signed routing contract.
17. Local trust-pin fallback applies only to an already-known peer and never
    creates first-contact address authority.
18. Mismatched recipient identity/address bindings fail closed.
19. Duplicate active one-to-one conversations are rejected or repaired rather
    than creating ambiguous routing.
20. Closed or expired conversations cannot be continued.
21. Conversation listing returns only conversations where the actor is a
    participant.
22. Federation v1 tolerates only the named deprecated routing fields as ignored
    compatibility input; they cannot shape routing or policy.
23. Federated responses are uncompressed and remain inside the response-size
    bound.

## Durable mail and read-state cases

1. Send acceptance returns `message_id` and `conversation_id` but does not claim
   wake, presentation, read state, or a recipient trust verdict.
2. Exact mail reads are participant-visible and do not change read state:
   authenticated senders and recipients may use `show --message-id`, while an
   unrelated or absent id returns the same 404. A rotated global sender's exact
   read uses the server-authorized stored sender routing DID plus the valid
   historical signature for authorship; a claimed stable field alone is not
   authority. Conversation `show` is also read-only.
3. Conversation history is oldest-first, defaults to 200, has a 500-message
   ceiling, and has no paging flag. A full-size window cannot prove completeness.
4. Inbox is newest-first. The CLI defaults to 50 while the server accepts at most
   200 per page; returned unread rows are presented and acknowledged. A response
   with `has_more` includes an opaque `next_cursor`, allowing the remaining
   mailbox to be fetched without overlap.
5. Mail reply resolves the source `conversation_id`; reply sends before its
   best-effort source acknowledgement. Failure of that acknowledgement does not
   unsend the reply.
6. `aw mail ack` is the authenticated recipient-side read transition. It
   idempotently sets `read_at` for unread recipient mail and emits the mutation
   event only on a state change. A sender may read its exact sent message but
   cannot acknowledge it; sender acknowledgement returns 404.
7. Read mail leaves unread inbox/actionable reconnect delivery but remains
   durable and exactly fetchable.
8. Hosted MCP `check_mail` marks returned unread rows read before the tool
   returns. That is its server-side hosted read transition; it does not prove a
   local self-custodial runtime presented or decrypted content.
9. Encrypted mail events expose routing/wake metadata without plaintext subject
   or body.

## Chat wait, selection, and read cases

1. Chat `session_id` is the chat `conversation_id`; exact session commands avoid
   alias re-selection after an event supplies the id.
2. Pending includes sessions with unread messages or an active counterpart wait.
   It exposes `sender_waiting` and remaining wait time.
3. Recipient-based open prefers a `sender_waiting` direct session, then direct
   over group, then recent activity. Ambiguous identities fail with a choose-one
   diagnostic rather than guessing.
4. Open fetches unread content before acknowledgement. It presents and marks the
   exact returned ids best-effort, surfaces a mark-read error, and refuses to
   acknowledge an incomplete snapshot above 1,000 unread messages.
5. Chat history is read-only. The CLI default is 1,000 messages and the server
   maximum is 2,000; exact `session_id` plus `message_id` selects one item.
6. `send-and-wait` defaults to 120 seconds. `--start-conversation` raises the
   implicit wait to 300 seconds unless the caller explicitly supplied `--wait`.
7. Wait/listen marks reply ids read after presentation, best-effort. A failed
   mark leaves them eligible for later pending presentation.
8. `extend-wait` continues the selected session; it does not create a replacement
   thread merely because a process restarted.
9. `sender_leaving` ends the current wait/turn, not durable participant
   membership. Explicit participant removal governs future group key wraps.

## Wake and reconnect cases

1. Communication events are wake signals; durable mail/chat remains content
   authority.
2. The raw stream emits no SSE `id`, accepts no `Last-Event-ID`, and has no
   resumable server cursor.
3. Each connection emits a fresh actionable snapshot. The mail snapshot contains
   the newest 50 unread messages plus total unread count, not a complete mailbox.
4. Raw `aw events stream` exits on EOF/error and leaves bounded backoff to its
   caller; managed runtime adapters own their documented reconnect behavior.
5. A consumer deduplicates stable message/session ids, fetches durable state,
   acknowledges only after its presentation point, and makes downstream actions
   idempotent.
6. Control signals are at-most-once and may be consumed before a dropped frame;
   reconnect must re-read authoritative state instead of assuming replay.
7. Authentication or authorization failure stops the retry loop for identity or
   membership repair.

## Content mode and custody cases

1. Current CLI plaintext is server-readable by default; explicit `--e2ee` fails
   closed on missing or invalid key/capability with no silent downgrade.
2. For self-custodial encrypted v2, plaintext never enters the routing service;
   events, server storage, and support surfaces remain metadata/ciphertext-only.
3. Hosted custodial MCP/dashboard/server-side compose or read is server-readable
   hosted messaging even when it uses the v2 wire format.
4. Lost archived self-custodial encryption keys make that history unrecoverable
   by the routing service or support.
5. Accepted asynchronous encrypted mail is verified on later read without
   reapplying the ingestion freshness window.
6. Legacy plaintext remains labeled server-readable and is never relabeled as
   retroactive E2E.

## Release evidence and document anchors

- Current user behavior: [`mail-and-chat.md`](mail-and-chat.md).
- Wake/reconnect behavior: [`receiving-events.md`](receiving-events.md).
- Identity/routing protocol: [`identity-messaging-contract.md`](identity-messaging-contract.md).
- Encryption/content modes: [`e2e-messaging-contract.md`](e2e-messaging-contract.md)
  and [`e2e-legacy-plaintext-policy.md`](e2e-legacy-plaintext-policy.md).
- Command/tool inventory: generated [`cli-command-reference.md`](cli-command-reference.md)
  and [`mcp-tools-reference.md`](mcp-tools-reference.md).
- Executable cross-surface proof: [`../scripts/e2e-oss-user-journey.sh`](../scripts/e2e-oss-user-journey.sh).

A change touching a case above must name and run its focused test plus the
applicable release gate against the exact artifact being reviewed. A passing
case does not authorize prose to redefine its upstream contract.
