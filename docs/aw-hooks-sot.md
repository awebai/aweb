---
title: "aweb mutation hook"
kicker: "Experimental extension contract"
description: "The public on_mutation callback exposed by current aweb route source."
weight: 27
---

# aweb mutation hook

Status: **shipped experimental embedding seam**. Owner: the aweb OSS server.
Source authority is `server/src/aweb/hooks.py`; current registrations and
translations live in `server/src/aweb/api.py` and
`server/src/aweb/mutation_hooks.py`. Route-level behavior is exercised by
`server/tests/test_messages_http.py`, `test_chat_http.py`,
`test_tasks_http.py`, and `test_mutation_hooks.py`.

This document describes the only public hook seam that exists today. A plural
hook registry, named extension points, externally loaded callbacks, and a
private app-specific hook design do **not** ship in aweb.

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

If the attribute is absent or `None`, the helper returns. The callback is
awaited before the route returns; this is not a durable queue or detached
background job. Any callback exception is logged and swallowed, so the
successful mutation response is not changed by hook failure.

Calls happen after the route's state change succeeds. They are not in the same
database transaction as that change, do not provide rollback, and may be missed
if the process dies between commit and callback. Event names and context keys
are experimental Python integration data, not a versioned network protocol.

## Default handler and composition warning

Both standalone and library-mode `create_app` lifespans install
`create_mutation_handler(redis, db_infra)` as `app.state.on_mutation`. That
handler translates selected mutations into workspace/team SSE events and also
runs task-claim and lifecycle cascades for selected event types.

An embedder that replaces `app.state.on_mutation` replaces that default handler;
there is no automatic fan-out. To add behavior while retaining built-in event
publication and cascades, the embedder must explicitly compose and await the
original callback. Treat replacement as experimental embedding work and test
the combined behavior.

## Current route call sites

[`vectors/mutation-hook-call-sites-v1.json`](vectors/mutation-hook-call-sites-v1.json)
is the machine-readable source path + enclosing function + literal event
inventory. Repeated rows preserve multiplicity when one function has multiple
calls for the same event. The table below groups those exact call sites by their
public HTTP behavior.

| HTTP route | Event | When called |
|---|---|---|
| `POST /v1/messages` | `message.sent` | After a successful local, stored-route, or federated outbound mail send. Helper branches converge on the same event. |
| `POST /v1/messages/{message_id}/ack` | `message.acknowledged` | Only when the ack changes the stored row. |
| `POST /v1/chat/sessions` | `chat.message_sent` | After the initial chat message is stored/sent, including federated first contact. |
| `POST /v1/chat/sessions/{session_id}/messages` | `chat.message_sent` | After a continuation message is stored/sent, including federated delivery. |
| `POST /v1/federation/messages` | `message.sent` or `chat.message_sent` | After an inbound federation envelope is verified, deduplicated, and stored; selected from envelope type. |
| `POST /v1/tasks` | `task.created` | After task creation. |
| `PATCH /v1/tasks/{ref}` | `task.status_changed` | When status changed. |
| `PATCH /v1/tasks/{ref}` | `task.updated` | When the update did not change status. |
| `DELETE /v1/tasks/{ref}` | `task.deleted` | After soft deletion. |
| `POST /v1/tasks/{ref}/deps` | `task.dependency_added` | After dependency creation. |
| `DELETE /v1/tasks/{ref}/deps/{dep_ref}` | `task.dependency_removed` | After dependency removal. |
| `POST /v1/tasks/{ref}/comments` | `task.comment_added` | After comment creation. |
| `POST /v1/reservations/acquire` | `reservation.acquired` | After lock acquisition. |
| `POST /v1/reservations/renew` | `reservation.renewed` | After lock renewal. |
| `POST /v1/reservations/release` | `reservation.released` | Only when a lock was released. |

Reads do not fire the hook. Reservation revoke does not fire it. The default
handler contains support for `agent.deleted`, but no current route call site in
`hooks.py` consumers emits that event; do not infer a public deletion hook from
the handler branch alone.

## Context keys passed by routes

Keys can be absent or null on paths that do not have that projection. Consumers
must tolerate additive keys and missing optional identity/workspace data.

### Messaging

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

`chat.message_sent` from chat routes uses:

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

| Event | Route-supplied keys |
|---|---|
| `task.created` | `task_id`, `team_id`, `task_ref`, `title`, `parent_task_id`, `assignee_alias`, `actor_agent_id`, `actor_alias`, `actor_did_aw` |
| `task.status_changed` | `task_id`, `team_id`, `task_ref`, `title`, `old_status`, `new_status`, `assignee_alias`, `parent_task_id`, `actor_agent_id`, `actor_alias`, `actor_did_aw`, `claim_preacquired` |
| `task.updated` | `task_id`, `task_ref`, `actor_agent_id`, `actor_did_aw` |
| `task.deleted` | `task_id`, `task_ref`, `actor_agent_id`, `actor_did_aw` |
| `task.dependency_added` | `task_id`, `depends_on_task_id`, `actor_agent_id`, `actor_did_aw` |
| `task.dependency_removed` | `task_id`, `removed_depends_on_task_id`, `actor_agent_id`, `actor_did_aw` |
| `task.comment_added` | `task_id`, `comment_id`, `actor_agent_id`, `actor_did_aw` |

The default handler translates only a subset into SSE frames. In particular,
`task.updated`, dependency, and comment events currently have no generic SSE
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
