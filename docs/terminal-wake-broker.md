---
title: "Terminal wake broker"
kicker: "Design note"
description: "Host daemon that supervises channel-core terminal delivery for OATS-launched sessions."
weight: 59
---

# Terminal wake broker

## Current contract

`aw wake` is a host daemon for OATS-launched terminal sessions. Go owns the
host lifecycle surface: registration, deregistration, status, stream admission,
process supervision, pause/resume and the OATS `session inspect|input` transport.
A long-lived channel-core child owns delivery: readiness gating, exact fetch,
local decrypt/trust, formatting, terminal input, durable delivered IDs, mail
acknowledgement and chat read marking.

The boundary is intentionally the same one documented in
[channel-core-terminal-adapter.md](channel-core-terminal-adapter.md):

- **Go never fetches, decrypts, formats message bodies, marks delivery, or marks
  mail/chat read.** It starts and supervises channel-core and reports lifecycle
  and readiness status.
- **Channel-core presents content.** For mail/chat wake and steer events it waits
  for terminal readiness, fetches the exact unread item(s), decrypts/verifies,
  formats the awakening and calls the terminal adapter. The terminal adapter
  calls OATS `input(home, text)` and resolves only after OATS accepts the input.
- **Accepted terminal presentation is the read point.** After the terminal input
  is accepted, channel-core writes its durable delivery mark and marks mail/chat
  read where the identity's capabilities permit. This acknowledges presentation,
  not completion of the requested task.
- **Read-only mail grants are capability-limited.** A grant with `mail.read` but
  not `mail.send` can fetch and present mail and can record the local
  `DeliveryStore` mark after accepted input, but it cannot call the server mail
  ack route. The server row remains unread for a holder with ack authority.
  Chat read grants continue to use the chat read endpoint.

There is no `/v1/events/actionable` endpoint and no Go-side read/ack logic.

## Registration, streams and state

A registration is one instance home plus one or more receive bindings. A receive
binding is the resolved `(identity_home, team_id)` pair. Go admits at most one
registration for an effective binding; duplicate stores written by older clients
are served deterministically with the earliest registration admitted and later
ones reported as conflicts.

`~/.config/aw/wake/` contains only Go-owned lifecycle/status state:

- `registry.d/<sha256-home>.json` — durable registrations;
- `instances.d/<sha256-home>.json` — pause/inactive lifecycle, first live
  observation, readiness/error/status metadata and child admission evictions;
- `status.json`, `lock/`, and `control.sock`.

Legacy `pending` hint queues from the retired hint-only broker are accepted on
load only so older stores do not break startup; they are counted as evicted and
dropped. They are not replayed, composed or injected. Channel-core's delivered-ID
store is separate delivery state. It dedupes accepted presentations; it is not a
proof that the agent completed the work.

## Readiness and presentation

Terminal readiness is evaluated before exact fetch. The normalized readiness
states are:

| Raw/backend state | Normalized | Wake/steer |
| --- | --- | --- |
| `idle`, `done` | `idle` | allowed after confirmed live, coalescing and rate limit |
| unknown/empty/new words | `unknown` | allowed after confirmed live, coalescing and rate limit |
| `working`, `busy`, `running` | `working` | defer before fetch |
| `blocked` | `blocked` | defer before fetch |
| `shell`, `generic shell` | `shell` | defer before fetch; never type message text into a bare shell |
| `stopped` after confirmed live | `stopped` | inactive/status, no input |
| `present:false` after confirmed live | `not-launched` | inactive/status, no input |

Nothing is delivered before the first confirmed live inspect (`present:true`). A
pending home may report the typed OATS error `E_RUNTIME_ENDPOINT_UNKNOWN`; before
first live inspect, that and every other pending state/error are tolerated until
the pending-expiry bound. After a confirmed live observation, `stopped` or
`not-launched` marks the registration inactive and waits for the retire hook to
call `aw wake deregister`.

Pause is durable Go state. While paused, channel-core waits before fetch; it
holds no already-fetched wake content. Resume lets the next readiness pass fetch
and present.

## Reconnect and crash windows

The event stream has no resumable cursor. On reconnect the server snapshot
raises actionable unread mail and pending chat. That means:

- if input/presentation fails before read marking, the item remains unread and a
  later event/snapshot can raise it again;
- if terminal input is accepted and read marking succeeds, the server row is read
  and unread-only reconnect will not raise it again;
- if the child dies after accepting input but before the local delivered mark or
  server ack/read lands, a later snapshot may present the item again;
- if the child dies after accepting an event but before completing presentation,
  Go does not force a reconnect or replay the in-flight offer; recovery waits for
  the next stream snapshot, up to the stream cycle (about five minutes).

Those are presentation crash windows, not guarantees of task completion. A
crashed or compacted agent must recover procedurally from durable state instead
of assuming unread state is a work-completion ledger.

## Recovery after uncertain crash or compaction

Unread checks still find newly waiting messages:

```bash
aw mail inbox
aw chat pending
```

Empty unread/pending results do **not** prove that previously presented work was
completed. Read means presented. To recover safely:

1. If a mail `message_id` is known, read that exact durable message:

   ```bash
   aw mail show --message-id <id> --json
   ```

2. If exact mail IDs are unknown, page the read-inclusive inbox until the
   uncertain interval is covered:

   ```bash
   aw mail inbox --show-all --json
   aw mail inbox --show-all --json --cursor <next_cursor>
   ```

3. `aw mail show --conversation-id <conversation-id>` is an oldest-first bounded
   conversation view. It is useful when that window is sufficient, but it is not
   an unbounded recent recovery query.
4. For chat, prefer exact session recovery:

   ```bash
   aw chat history --session-id <session-id> --json
   aw chat history --session-id <session-id> --message-id <message-id> --json
   ```

   Without an exact message ID, history is bounded (default 1000), includes read
   and unread messages, and does not establish completeness beyond its limit.
5. Reconcile recovered messages with durable task state, `STATE.md`, commits,
   command logs and side-effect receipts before retrying actions. Avoid blindly
   repeating mutations.

## Commands

`aw wake register` is called by the OATS spawn hook. It refuses registrations
without `--delivery session` / `AWEB_DELIVERY=session`, because a live native
channel and the terminal broker are two presentation surfaces on one identity.
The command writes durably through the running daemon or directly to the state
directory when the daemon is down.

`aw wake deregister` is called by the retire hook after quiescence. It is
idempotent. The daemon stops the retired runner before deleting the registration
and instance state, so runner shutdown cannot recreate deleted state. An unknown
home exits 0 with a note because the hook may run twice.

`aw wake pause|resume` updates durable pause state. Pause suppresses terminal
presentation before fetch; it does not stop the stream or itself mark anything
read.

`aw wake status` reports the running daemon's lifecycle, readiness and delivery
status. The daemon reports its own build in `daemon_version` and `daemon_commit`;
a CLI must not substitute its own version for an older daemon that does not
report these fields.

## Service units

Example **launchd** user agent:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>ai.aweb.wake</string>
  <key>ProgramArguments</key> <array><string>/usr/local/bin/aw</string><string>wake</string><string>run</string></array>
  <key>RunAtLoad</key>        <true/>
  <key>KeepAlive</key>        <true/>
  <key>StandardOutPath</key>  <string>/tmp/aweb-wake.log</string>
  <key>StandardErrorPath</key><string>/tmp/aweb-wake.log</string>
</dict>
</plist>
```

Example **systemd user unit**:

```ini
[Unit]
Description=aweb terminal wake broker
After=default.target

[Service]
Type=simple
ExecStart=/usr/local/bin/aw wake run
Environment=PATH=/usr/local/bin:/usr/bin:/bin
Environment=LC_ALL=en_US.UTF-8
Restart=always
RestartSec=2

[Install]
WantedBy=default.target
```

Restarting the daemon is safe for registered instances, but it is not a promise
of lossless replay for already accepted presentations; use the recovery guidance
above after uncertain crashes.

## Qualification coverage

The retired standalone shell fixture implemented the old hint-only contract and
has been deleted. Current terminal delivery qualification is the Go
shared-core/channel-core test coverage that runs the real bundled child in
candidate gates:

- `cli/go/wake/channel_core_runner_test.go` `TestBundled*` cases prove bundled
  channel-core readiness/status behavior, exact fetch, terminal input,
  delivered-ID handling, grant-home auth, and the read-only mail grant exception.
- `cli/go/wake/broker_channel_core_lifecycle_test.go` `TestBroker*` cases prove
  broker lifecycle around channel-core: pause restoration, binding replacement,
  generation fencing for stale inactive callbacks, deregister stop-before-delete,
  same-home reactivation, and daemon-down fallback.
- `cli/go/cmd/aw` wake/status tests prove the command surface, daemon-down file
  fallback, binary help/reference behavior, and version/status formatting.

A live-server wake end-to-end that exercises real hosted infrastructure would be
a separate piece of work; it is not part of this patch.
