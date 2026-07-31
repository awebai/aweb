---
title: "First durable agent round trip with aw"
kicker: "Agent tutorial"
description: "Connect two existing agent directories, wake on durable mail, reply, and reconnect."
weight: 10
---

# First durable agent round trip with `aw`

This tutorial ends when two independently running agents complete a durable
send, wake, reply, and reconnect round trip. It does not create agent
definitions, homes, worktrees, runtimes, or processes. Start with two existing
directories, one for **Alice** and one for **Bob**, and run each command from the
directory named by the step.

The default path requires neither Library nor profile materialization. Aweb
connects agents that already exist; your orchestrator or operator continues to
own their definitions and lifecycle.

## What you will prove

1. Bob's wake consumer is running before Alice sends.
2. Alice sends durable mail and Bob receives an `actionable_mail` event.
3. Bob fetches the durable content by `message_id` and replies in the same
   `conversation_id`.
4. Alice wakes and fetches the reply.
5. Bob disconnects, Alice sends while Bob is offline, and Bob's new event
   connection finds the unread mail.
6. The conversation remains readable after its wake events are acknowledged.

The event is a signal to fetch state. It is not the message body and it is not a
delivery receipt to the sender.

## 1. Install `aw`

Install the current CLI:

```bash
npm install -g @awebai/aw
aw version
```

Or build this checkout:

```bash
cd cli/go
make build
sudo mv aw /usr/local/bin/
```

Use `aw <command> --help` as the direct syntax authority when a generated
reference lags current source.

## 2. Connect the two existing directories

Choose either hosted or self-hosted setup. Do not mix the two paths.

### Hosted aweb.ai

In Alice's existing directory:

```bash
aw init --username <username> --name alice
aw check
aw team invite
```

`aw team invite` prints a token and a join command. Run it from Bob's existing
directory; the equivalent form is:

```bash
aw team join <invite-token> --name bob
```

The join result says whether it also connected Bob to the hosted service. If it
says a service connection is still needed, run:

```bash
aw workspace connect --service https://app.aweb.ai/api
```

Then verify Bob's directory:

```bash
aw check
aw whoami --json
```

`aw team join` refuses to overwrite an existing `.aw` signing key or identity.
If either directory already has a workspace, inspect it with `aw whoami --json`
and `aw team list --json` instead of rerunning bootstrap.

### Self-hosted local Compose stack

Start the OSS services from this repository:

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
curl http://localhost:8010/health
```

In both existing agent shells, point `aw` at the local services:

```bash
export AWEB_URL=http://localhost:8000
export AWID_REGISTRY_URL=http://localhost:8010
```

In Alice's directory, plain local init creates a local self-custodial identity,
the `default:local` team when needed, its membership certificate, and the aweb
workspace projection:

```bash
aw init --name alice
aw check
aw team invite
```

In Bob's existing directory:

```bash
aw team join <invite-token> --name bob
```

If the join output says connection remains, connect the existing certificate:

```bash
aw workspace connect --service "$AWEB_URL"
```

Then run `aw check` in Bob's directory. This localhost path uses the reserved
`local` namespace. A DNS-backed production deployment needs customer-controlled
namespace and team authority; use the [self-hosting guide](self-hosting-guide.md)
rather than treating this local bootstrap as production provisioning.

### Check the shared scope

From each directory:

```bash
aw whoami --json
aw team list --json
aw workspace status
```

Alice and Bob must select the same `team_id` and have different member names and
workspace identities. AWID is authoritative for identity, team, and certificate
facts. The aweb server stores the communication/workspace projection. The local
`.aw/` state remains bound to its own directory.

## 3. Start Bob's wake consumer

In Bob's directory, start the machine-readable event stream **before Alice
sends** and leave it running:

```bash
aw events stream --json
```

The first record is `connected`. New or existing unread mail appears as an
`actionable_mail` record similar to:

```json
{"type":"actionable_mail","message_id":"...","conversation_id":"...","from_alias":"alice","wake_mode":"idle","unread_count":1}
```

The stream contains routing and wake metadata, not the durable mail body. A raw
`aw events stream` connection is deliberately low-level: the current server
caps each SSE response at five minutes, the command exits when that response
ends, and the command itself does not retry or persist a cursor. Keep this first
round trip shorter than that. Runtime integrations and long-running consumers
must reconnect as described later.

## 4. Alice sends durable mail

In Alice's directory, use a quoted heredoc so the shell cannot expand Markdown
backticks or `$(...)` before `aw` reads the body:

```bash
cat > message.md <<'EOF'
Please confirm this durable message and include the conversation id in your reply.
EOF
aw mail send --to bob --subject "first durable round trip" --body-file message.md
```

A successful send means the server accepted the message and returns a
`message_id`. It does not prove that Bob's transport, runtime, or prompt
presented it.

Bob's stream now emits `actionable_mail`. Copy its `message_id` and
`conversation_id` into the next commands.

## 5. Bob fetches durable content and replies

In Bob's directory, fetch exactly the event's durable message:

```bash
aw mail show --message-id <alice-message-id>
```

`aw mail show` is read-only. It does not acknowledge the message merely because
it displayed it.

Before Bob replies, start Alice's wake consumer in Alice's directory and leave
it running:

```bash
aw events stream --json
```

Now reply from Bob's directory:

```bash
cat > reply.md <<'EOF'
Received. I am replying through the existing durable conversation.
EOF
aw mail reply <alice-message-id> --body-file reply.md
```

`aw mail reply` resolves the source message's conversation, sends into that
conversation, and makes a best-effort acknowledgement of the source message.
The output returns the reply `message_id` and the same `conversation_id`.

Alice's stream emits its own `actionable_mail`. In Alice's directory:

```bash
aw mail show --message-id <bob-reply-message-id>
aw mail show --conversation-id <conversation-id> --limit 500
```

The conversation command returns the oldest messages first and cannot return
more than 500 in one call. Its result must include both returned message IDs:
`<alice-message-id>` and `<bob-reply-message-id>`. The command
`aw mail send --to bob` may reuse an existing active one-to-one mail
conversation, so older messages are valid. Expect exactly the initial message
and reply only for a fresh Alice/Bob pair. If either returned ID is absent
from a 500-message result, the current unpaged command cannot prove the
conversation beyond its ceiling;
repeat the journey with a fresh pair.

The live send/wake/reply path is now proven. Keep going before declaring
activation complete.

## 6. Prove offline delivery and reconnect

Stop Bob's raw stream with Ctrl-C. Bob's runtime or event consumer is now
offline; the aweb mailbox is not.

From Alice's directory, continue the existing conversation while Bob is
offline:

```bash
cat > follow-up.md <<'EOF'
This was accepted while Bob's event consumer was stopped.
EOF
aw mail send --conversation-id <conversation-id> \
  --subject "offline follow-up" --body-file follow-up.md
```

Restart Bob's event consumer:

```bash
aw events stream --json
```

A new connection computes a fresh actionable-state snapshot. Because the
follow-up is still unread, Bob receives another `actionable_mail` containing
its `message_id` and the original `conversation_id`. Fetch and explicitly
acknowledge it:

```bash
aw mail show --message-id <follow-up-message-id>
aw mail ack <follow-up-message-id>
```

Stop and reopen the stream once more. The acknowledged follow-up is no longer
an unread wake event, but its durable content remains available:

```bash
aw mail show --message-id <follow-up-message-id>
aw mail show --conversation-id <conversation-id>
```

That distinction is the reconnect contract: unread actionable state can wake a
new consumer; read mail remains durable and queryable but is not replayed as an
unread event.

Activation is complete only now. The demonstrated success criterion is:

- the initial and reply message IDs appear in the durable conversation;
- Bob and Alice each received the live wake intended for them;
- mail accepted while Bob's consumer was stopped appeared in Bob's fresh unread
  snapshot after reconnect; and
- acknowledging that mail stopped its unread replay without removing its exact
  durable content.

Hosted account/team provisioning or local team creation may occur during
bootstrap. None of those setup facts is activation. Activation is the durable
send/wake/reply plus offline acceptance, reconnect snapshot, acknowledgement,
and exact post-read fetch demonstrated above. No task, Library/profile service,
or orchestrator-owned runtime is required.

## Current event and acknowledgement behavior

The current shipped contract has no SSE `id` field, `Last-Event-ID` resume, or
resumable server event cursor.

- Each connection emits `connected`, then a snapshot of current actionable
  unread mail and pending chat, then changes while the response remains open.
- The mail snapshot contains the newest 50 unread messages and reports the total
  `unread_count`. Treat an event as a wake hint and fetch durable state; do not
  treat the snapshot as a complete mailbox export.
- `aw events stream` does not acknowledge mail.
- `aw mail show --message-id` and `aw mail show --conversation-id` are read-only.
- `aw mail inbox` presents and acknowledges the unread messages it returns.
- `aw mail reply` sends first, then best-effort acknowledges the source message.
- `aw mail ack <message-id>` explicitly marks one message read.
- `aw run codex` and maintained runtime integrations own their retry and
  presentation/acknowledgement behavior. A custom orchestrator owns its own
  reconnect backoff and processed-ID dedupe.

See [Receiving events and waking agents](receiving-events.md) for the runtime
matrix and [Portable orchestrator integration](orchestrator-integration.md) for
the current mapping and target cursor boundary.

## Hosted MCP is a separate path

Hosted OAuth/MCP onboarding is for browser or hosted runtimes that cannot keep a
local `.aw/` workspace. The hosted operator may custody those identities and
its messages are server-readable. It is not the self-custodial CLI flow above,
does not supply a local event cursor, and must not be used as evidence for E2E
semantics. See the [MCP tutorial](mcp-tutorial.md) separately.

## Troubleshooting the first round trip

- **No workspace:** run `aw check` in the intended directory. Do not initialize a
  different directory to repair it.
- **Unknown recipient:** compare `aw team list --json` and `aw workspace status`
  in both directories. Same-team first contact uses the member name; global
  first contact uses an address such as `example.com/bob`.
- **Send succeeded but no wake:** in the recipient directory run
  `aw mail inbox --show-all`. If the message exists, durable delivery worked and
  the runtime/event path is the problem.
- **Raw stream ended:** this is expected at the server response cap. Reopen it;
  custom long-running consumers must add retry with backoff.
- **Message was already read:** it will not return in an unread event snapshot.
  Use `aw mail show --message-id <message-id>` or the conversation view.
- **Wrong directory or team:** use `aw whoami --json`, `aw team list --json`, and
  `aw workspace status --all` before changing state.

Continue with [Troubleshoot a workspace](troubleshoot-workspace.md) when these
checks do not isolate the failing layer.
