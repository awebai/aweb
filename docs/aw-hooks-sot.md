---
title: "aweb mutation hook"
description: "The public on_mutation callback exposed by aweb route source."
weight: 27
---

# aweb mutation hook

Status: **shipped experimental embedding seam**. Owner: the aweb OSS server.
Source authority is `server/src/aweb/hooks.py`; registrations and
translations live in `server/src/aweb/api.py` and
`server/src/aweb/mutation_hooks.py`. Task events are fired by the task service,
`server/src/aweb/coordination/tasks_service.py`. Route-level behavior is exercised by
`server/tests/test_messages_http.py`, `test_chat_http.py`,
`test_tasks_http.py`, and `test_mutation_hooks.py`; MCP parity by
`test_mcp_mutation_hook_parity.py`.

This document describes the in-process `on_mutation` embedding seam.
Externally loaded callbacks and a private app-specific hook design do **not**
ship in aweb.

Named, owner-activated extension points are specified separately, in
[aw-hooks: catalog, bindings and delivery](hook-events.md). The server ships
their binding registry, owner activation and revocation, and resolution
(`server/src/aweb/hook_bindings.py`, `server/src/aweb/routes/hook_bindings.py`,
`server/src/aweb/routes/app_hooks.py`); apps produce and receive their events.
**Open (aweb-acgh.16.11):** the core server's `post-mutation-hook` producer.
**Open (aweb-acgh.16.17, aweb-acgh.16.16):** `aw`'s `post-command-hook` events
and the command `trace_id` they share. `on_mutation` is unchanged by them and is
not an audit hook: its route call sites are post-commit and best effort, so they
can lose an event, and it never carries a hook event.

## Callback shape

Routes call:

```python
await fire_mutation_hook(request, event_type, context)
```

`fire_mutation_hook` looks for one callback:

```python
request.app.state.on_mutation
```

Its required shape is:

```python
async def on_mutation(event_type: str, context: dict) -> None:
    ...
```

The task service fires its events itself, for every caller, through:

```python
await fire_mutation_callback(on_mutation, event_type, context)
```

Each of its member-facing functions takes the acting member and `on_mutation`
as required arguments. A route passes `mutation_callback(request)`, which is
`request.app.state.on_mutation`; an MCP tool passes the callback of the
application the MCP app is mounted in. The service fires after its own write
commits. A caller that runs it inside a transaction of its own passes the
`record` method of a `HeldMutationEvents` (`aweb.hooks`), and calls its `fire`
with `on_mutation` after that transaction commits.

If the attribute is absent or `None`, the helper returns. At route call sites
the callback is awaited before the route returns; this is not a durable queue or detached
background job. Any callback exception is logged and swallowed, so the
successful mutation response is not changed by hook failure.

Route calls happen after the route's state change succeeds. They are not in the
same database transaction as that change, do not provide rollback, and may be
missed if the process dies between commit and callback.

Inbound federation (`POST /v1/federation/messages`) is durable instead. The
delivery transaction that stores the message also writes its event to
`federation_mutation_outbox` (`server/src/aweb/federation/delivery.py`). After
the commit the route replays undelivered rows, and a background loop replays
them every 15 seconds (`server/src/aweb/outbox_recovery.py`; a host that sets
`host_runs_outbox_recovery` runs `recover_outboxes` on its own scheduler). A
row is marked delivered only when the callback returns. A callback exception is
logged, counted in `attempt_count` and `last_error`, and retried on the next
replay. Rows wait while no callback is installed. This path is at-least-once:
the callback may run from the background loop rather than the route, and may
see the same event more than once. Pending replay chooses the fewest-attempted
rows first, then creation order, so an old failing batch cannot indefinitely
hide an untried row behind it. This is retry fairness, not a per-conversation
callback ordering guarantee.

Event names and context keys are experimental Python integration data, not a
versioned network protocol.

### Typed producer contexts

`aweb.event_types.MutationEventType` names standard mutation events;
`TransportEventType` names the stream events produced by translation. These
are separate vocabularies: `message.sent` is a mutation, while
`message.delivered` is its delivery signal. The enums are string-compatible
constants, not an admission gate for host-defined callback names. A known
handler branch does not establish that a producer emits that event.

`aweb.message_events` provides frozen, keyword-only producer contexts:

- `MailSentContext` for local and outbound mail;
- `ChatMessageSentContext` for native chat sends;
- `FederatedMessageSentContext` for the shared inbound outbox shape;
- `MessageAcknowledgedContext` for incoming mail acknowledgements;
- `RoomMessageSentContext` for a committed team room post.

Each supplies `event_type` and `to_context() -> dict[str, object]`. Construct
them from validated producer data. Event names, message kind and transport use
the server's named enums. Received `content_mode` and priority instead use
`ContentModeValue` and `MessagePriorityValue` from `aweb.messaging.kinds`: a
named standard value or the original string. As before typed contexts, an absent
or empty mode emits `legacy_plaintext_v1`, and an absent or empty priority emits
`normal`. Exact named values become `ContentMode`/`MessagePriority` constants;
other accepted nonempty strings retain every character, including case and
whitespace. These are callback defaults only: request and signed payload bytes
are unchanged. No context performs validator narrowing. Constructors cannot
newly fail on accepted metadata, so callback timing remains unchanged.

Mail send, chat send, mail acknowledgement and inbound federation producers
use these contexts before passing dictionaries to the existing callback or
durable outbox. They pass the accepted mode and priority to the context without
changing the request or signed bytes; the context supplies the historical
emitted defaults described above. The inbound
context keeps its shared mail/chat shape rather than acquiring native chat's
preview or recipient-alias list.

`aweb.message_vocabulary.observe_message_vocabulary` measures unnamed accepted
metadata once at the mail/chat send entry, native preparation after its
signed envelope validation, or after federation signature
verification, before replay exits. The Prometheus counter
`aweb_unnamed_message_vocabulary_total` has only bounded `source` and `field`
labels. One log line names the source and unnamed fields; neither counter nor
log contains the received values, identifiers or message content. A counter
failure is logged and leaves the send working. Contexts and hook translation
do not observe again. This is measurement only; validators remain unchanged.

Native chat recipients accept the existing list or a tuple; the context takes
an immutable snapshot and returns a fresh list in the callback dictionary.
Nullable identity projections remain null. Local sends omit the
optional `federated` key; federation sends retain it. Inbound chat retains its
existing shared shape, which may have `to_alias` and no `to_aliases` or preview.

The same module reexports the existing workspace/team mail and chat transport
DTOs from `aweb.events`; these are the same classes, not another set of stream
payloads. Their existing imports and constructors remain supported.

This is an additive producer interface. The callback remains `(str, dict)`;
it is not replaced by a closed DTO parser. Readers still tolerate additive
keys, host-defined names and missing optional projections. Context objects do
not verify an identity, sanitize content or alter commit, best-effort failure
or durable replay semantics. Producer/translator conversion must keep the
source call-site inventory and its rejection of unresolvable dynamic names
effective when it adopts named event constants.

## Default handler and composition warning

Both standalone and library-mode `create_app` lifespans install
`create_mutation_handler(redis, db_infra)` as `app.state.on_mutation`. That
handler translates selected mutations into workspace/team SSE events, announces
task claims and their release, and runs cascades for selected event types: the
lifecycle cleanup of `agent.deleted`, the claim release of `task.deleted`, and
the claim of a task taken `in_progress` when the status transaction recorded
none.

The claims a status change ends are not part of the handler. The task service
releases them in the transaction that changes the status, whether or not a
callback is installed, and names the released workspaces in the event; the
handler only publishes their `task.unclaimed` events.

An embedder that replaces `app.state.on_mutation` replaces that default handler;
there is no automatic fan-out. To add behavior while retaining built-in event
publication and cascades, the embedder must explicitly compose and await the
original callback. Treat replacement as experimental embedding work and test
the combined behavior.

## Current route call sites

The table below groups the `fire_mutation_hook` and `fire_mutation_callback`
call sites by their public HTTP behavior. Inbound federation fires through its
outbox. The create, update, delete, dependency and comment rows of
`/v1/tasks` fire from the task service the route calls, a `POST /v1/messages`
send fires from `server/src/aweb/messaging/mail_send.py`, which the route and
the MCP `send_mail` tool both call, a chat send fires from
`server/src/aweb/messaging/chat_send.py`, which both chat send routes and the
MCP `send_chat` tool call, and an acknowledgement fires from
`server/src/aweb/messaging/mail_ack.py`, which the ack route and the MCP
`check_mail` tool both call; every other row fires from its route.

| HTTP route | Event | When called |
|---|---|---|
| `POST /v1/room/messages` | `room.message_sent` | After a new room post commits. Exact retries emit nothing. |
| `POST /v1/messages` | `message.sent` | After a successful local, stored-route, or federated outbound mail send. Helper branches converge on the same event. |
| `POST /v1/messages/{message_id}/ack` | `message.acknowledged` | Only when the ack changes the stored row. |
| `POST /v1/chat/sessions` | `chat.message_sent` | After the initial chat message is stored/sent, including federated first contact. |
| `POST /v1/chat/sessions/{session_id}/messages` | `chat.message_sent` | After a continuation message is stored/sent, including federated delivery. |
| `POST /v1/federation/messages` | `message.sent` or `chat.message_sent` | From the federation outbox, after an inbound federation envelope is verified, deduplicated, and stored; selected from envelope type. At-least-once, as described above. |
| `POST /v1/tasks` | `task.created` | After task creation. |
| `POST /v1/tasks/app-requests` | `task.created` | After first verified app-request creation; replay emits nothing. The actor is the authorized member, separate from the transporting app. |
| `POST /v1/tasks/{ref}/answer` | `task.status_changed`, `task.comment_added` | After the conditional answer commits; replay emits nothing. Context contains identifiers and safe metadata, never answer text, authorization signatures or certificates. |
| `POST /v1/tasks/app-requests/{id}/cancel` | `task.status_changed`, `task.comment_added` | After first cancellation commits; replay emits nothing. The task service releases claims in that same transaction. |
| `PATCH /v1/tasks/{ref}` | `task.status_changed` | When status changed. |
| `PATCH /v1/tasks/{ref}` | `task.updated` | When the update did not change status. |
| `PATCH /v1/tasks/{ref}` | `task.assignee_changed` | Additionally, when the stored assignee changes, including an implicit claim assignment. |
| `DELETE /v1/tasks/{ref}` | `task.deleted` | After soft deletion. |
| `POST /v1/tasks/{ref}/deps` | `task.dependency_added` | After dependency creation. |
| `DELETE /v1/tasks/{ref}/deps/{dep_ref}` | `task.dependency_removed` | After dependency removal. |
| `POST /v1/tasks/{ref}/comments` | `task.comment_added` | After comment creation. |
| `POST /v1/reservations/acquire` | `reservation.acquired` | After lock acquisition. |
| `POST /v1/reservations/renew` | `reservation.renewed` | After lock renewal. |
| `POST /v1/reservations/release` | `reservation.released` | Only when a lock was released. |

The MCP tools below fire the events of the route that performs the same
mutation, through the `app.state.on_mutation` of the application the MCP app is
mounted in (`server/src/aweb/mcp/mutations.py`). No MCP tool outside this
table fires the hook.

| MCP tool | Event | When called |
|---|---|---|
| `room_post` | `room.message_sent` | After a new room post commits, as `POST /v1/room/messages`. |
| `send_mail` (and `send_message_to_contact` for mail) | `message.sent` | After a successful local, stored-route, or federated send, as `POST /v1/messages`. |
| `check_mail` | `message.acknowledged` | Once for each unread message the call marks read; already-read mail does not fire again. |
| `send_chat` (and `send_message_to_contact` for chat) | `chat.message_sent` | After a new-session or continuation message is stored/sent, including federated delivery. |
| `task_create` | `task.created` | As `POST /v1/tasks`. |
| `task_update`, `task_claim`, `task_close`, `task_reopen` | `task.status_changed` or `task.updated`, and `task.assignee_changed` | As `PATCH /v1/tasks/{ref}`: `task_claim` sets `in_progress`, `task_close` sets `closed`, `task_reopen` sets `open`. |
| `task_comment_add` | `task.comment_added` | As `POST /v1/tasks/{ref}/comments`. |

The task tools and the task routes call one service function for each change,
and that function fires the events: for the same change by the same member the
event names, their order and the whole context are equal. `send_mail` and
`POST /v1/messages` likewise call one mail send, which fires `message.sent`
with one context for both, and `send_chat` and the chat send routes call one
chat send, which fires `chat.message_sent` with one context for both.
`check_mail` and `POST /v1/messages/{message_id}/ack` call one acknowledgement,
which fires `message.acknowledged` with one context for both. MCP
has no tool that deletes a task, changes its dependencies or answers it, and
none for reservations; those events come from the routes only.

`mark_chat_read` and its `chat_read` alias publish the same chat-session
`read_receipt` wake signal as `POST /v1/chat/sessions/{session_id}/read` when
they mark at least one message read; like that route, they fire no mutation
hook.

Reads do not fire the hook. Reservation revoke does not fire it. The default
handler contains support for `agent.deleted`, but no route call site in
`hooks.py` consumers emits that event; do not infer a public deletion hook from
the handler branch alone.

## Context keys passed by routes

Keys can be absent or null on paths that do not have that projection. Consumers
must tolerate additive keys and missing optional identity/workspace data.

### Messaging

`room.message_sent` uses only metadata:

```text
team_id, room_id, message_id, from_agent_id, from_did, from_did_aw, from_alias
```

Both HTTP and MCP room sends call one producer. It builds this context before
committing and calls the best-effort host callback after commit. An exact
retry returns the stored post without emitting or counting another send.
No room body or recipient list is included.

A host's pre-post quota admission uses the public dependency
`aweb.routes.room.room_post_identity`, the same `chat.send` scoped team
identity dependency used by the room route. A host may bind a wrapper which
calls it once, checks its authenticated actor, and returns that exact actor.
The post-commit callback counts a committed post and cannot refuse it at a
limit. Authentication, current membership and the room signature remain
native decisions.

`message.sent` route contexts use:

```text
team_id, from_agent_id, from_did, from_did_aw, to_agent_id,
from_alias, message_id, conversation_id, to_alias, subject,
priority, content_mode, federated
```

`federated` appears only on federation paths. Inbound federation has no local
`from_agent_id`.

`message.acknowledged` uses:

```text
team_id, agent_id, alias, message_id, from_alias, subject, content_mode
```

`chat.message_sent` from a chat send uses:

```text
team_id, session_id, conversation_id, message_id, from_agent_id,
from_alias, from_did, from_did_aw, to_aliases, preview,
content_mode, federated
```

The inbound federation route uses the shared federation context shape and may
supply `to_alias` rather than `to_aliases`. Experimental consumers must not
assume every path has a preview or recipient-alias list.

For encrypted v2 content, built-in translation suppresses subject/preview
content and carries `content_mode`/`encrypted` metadata instead.

### Tasks

| Event | Supplied keys |
|---|---|
| `task.created` | `task_id`, `team_id`, `task_ref`, `title`, `parent_task_id`, `assignee_alias`, `actor_agent_id`, `actor_alias`, `actor_did_aw` |
| `task.status_changed` | `task_id`, `team_id`, `task_ref`, `title`, `old_status`, `new_status`, `assignee_alias`, `parent_task_id`, `actor_agent_id`, `actor_alias`, `actor_did_aw`, `claim_preacquired`, `released_claim_workspace_ids` |
| `task.updated` | `task_id`, `task_ref`, `actor_agent_id`, `actor_did_aw` |
| `task.assignee_changed` | `task_id`, `team_id`, `task_ref`, `title`, `old_assignee_alias`, `assignee_alias`, `actor_agent_id`, `actor_alias`, `actor_did_aw` |
| `task.deleted` | `task_id`, `task_ref`, `actor_agent_id`, `actor_did_aw` |
| `task.dependency_added` | `task_id`, `depends_on_task_id`, `actor_agent_id`, `actor_did_aw` |
| `task.dependency_removed` | `task_id`, `removed_depends_on_task_id`, `actor_agent_id`, `actor_did_aw` |
| `task.comment_added` | `task_id`, `comment_id`, `actor_agent_id`, `actor_did_aw` |

`claim_preacquired` is true when the status transaction recorded the actor's
claim on a task taken `in_progress`. `released_claim_workspace_ids` lists the
workspaces whose claim that transaction released: every claim on the task when
its status changes to `open` or `closed`, and none otherwise. Both are event
context only; no task response carries them. The answer and app-cancellation
events carry fewer keys than the table lists.

`task.assignee_changed` uses `assignee_alias` for the new value, with null
meaning unassigned. Its old/new pair comes from the locked update, after alias
or member-ID resolution; setting the same resolved assignee does not fire it.
It is additional to the existing status/updated callback. The built-in team
SSE translations of `task.created` and `task.status_changed` include nullable
`assignee_alias`; `task.assignee_changed` carries both assignment values and
the task reference, title and actor alias. These signals carry task metadata,
including human assignees, without listing humans in the agent roster.

The default handler translates only a subset into SSE frames. In particular,
`task.updated`, dependency, and comment events have no generic SSE
translation. Their callback invocation is still observable to a composed
embedder, but it is experimental and not a durable event feed.

### Reservations

| Event | Route-supplied keys |
|---|---|
| `reservation.acquired` | `team_id`, `holder_agent_id`, `alias`, `resource_key`, `ttl_seconds` |
| `reservation.renewed` | `team_id`, `holder_agent_id`, `alias`, `resource_key`, `ttl_seconds` |
| `reservation.released` | `team_id`, `holder_agent_id`, `alias`, `resource_key` |

## Built-in enrichment and translation

Before translating, the default handler may backfill:

- `actor_did_aw`, `from_did_aw`, or `holder_did_aw` from agent/DID metadata;
- `actor_workspace_id` or `holder_workspace_id` from current workspace rows.

Those enriched keys belong to the built-in handler's local copy of the context;
the route does not promise them to a replacement callback. The default handler
then translates recognized events into the existing SSE event classes, performs
best-effort enrichment, and publishes workspace and/or team events through
Redis. Translation or publication errors are logged and do not change the
already-successful route mutation.

## Lifecycle and stability

Use this seam only when embedding the Python application and accepting an
experimental, in-process contract. For cross-process integrations use public
HTTP/SSE protocols such as [`receiving-events.md`](receiving-events.md) or the
experimental installed-app event contract in [`app-events.md`](app-events.md).
Do not build against a private named-hook specification or describe it as
shipped aweb authority.
