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
A long-lived channel-core child owns delivery: immediate exact fetch,
local decrypt/trust, formatting, terminal input, durable delivered IDs, mail
acknowledgement and chat read marking.

The boundary is intentionally the same one documented in
[channel-core-terminal-adapter.md](channel-core-terminal-adapter.md):

- **Go never fetches, decrypts, formats message bodies, marks delivery, or marks
  mail/chat read.** It starts and supervises channel-core and reports lifecycle
  and readiness status.
- **Channel-core presents content.** For mail/chat wake and steer events it immediately fetches the exact unread item(s), decrypts/verifies,
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
ones reported as conflicts. Normalized bindings are retained in memory until a
successful registration update replaces them. Event routing never re-resolves a
binding from mutable team files; a transient filesystem failure during refresh
keeps the last accepted binding usable.

Streams quarantine only HTTP 401, 403, 404 and 422. Other failures, including 408,
409 and 429, use bounded retry. Child restart jitter shifts below its configured
maximum near the cap, keeping both the bound and jitter.

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

## Immediate presentation and safety

Mail and chat are delivered on arrival, including while the harness reports
working, blocked or unknown. Readiness gating, coalescing and rate limiting were
removed pending an architecture rethink. Legacy `--coalesce` and `--rate-limit`
options are accepted but ignored.

The serialized terminal adapter inspects only for safety before input. A raw
shell, stopped/not-launched harness, `present:false`, or failed inspect refuses
input and leaves the message unread for bounded retry and fresh-snapshot recovery. Exhausted mail/chat presentation
requests one coalesced stream re-open after five seconds. Stopped/not-launched observations mark the instance inactive only after the
child has observed `present:true`; a prelaunch home stays pending and retries
through unread snapshots without needing re-registration.

Persistent refusal backs off the coalesced snapshot re-open per stream: five
seconds, ten seconds, twenty seconds, doubling to a five-minute cap. Requests
within one pending window coalesce without advancing that backoff. Accepted
terminal input resets the receiving stream's window; resume resets it and
re-opens immediately. Transport reconnects retain the refusal backoff. A newly
launched terminal recovers on the next unread snapshot; no re-registration is
required, though a long-refused home can wait for its current backoff window.

Full sanitized content includes sender/trust metadata and a recovery footer for
multiple receiving identities; no ID-only notice substitutes for mail/chat.

Pause is durable operator control, independent of readiness. While paused,
channel-core rejects input; after applying resume it immediately requests a
stream re-open so the fresh snapshot re-offers unread content.
There is no held-text readiness queue or timer.

## Reconnect and crash windows

The event stream has no resumable cursor. On reconnect the server snapshot
raises actionable unread mail and pending chat. That means:

- if input/presentation fails before read marking, the item remains unread and a
  a requested fresh snapshot raises it again (an unrelated exact-ID event does
  not recover that message);
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
directory when the daemon is down. With the daemon running, an identical active
registration keeps its child and liveness state. A fresh registration discards
any orphaned lifecycle state. An inactive home reactivates;
a changed binding also restarts the child and resets liveness while preserving
pause. Per-instance persistence serializes snapshot and write so an older write
cannot overwrite a newer pause.

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

## Runtime prerequisite

`aw wake` runs the bundled channel-core child with the system `node` executable
found on the daemon's `PATH`; Node is not embedded in the `aw` binary. Current
terminal wake delivery evidence is Node 22 in the Linux candidate gate and Node
26.8.2 on the macOS host. Use a tested Node runtime available to the daemon
rather than assuming the `aw` binary carries one.

A service unit must set a `PATH` that contains both `aw` and `node` as seen by
the service user. On macOS/Homebrew, replace the example with the real `aw` path
and include the Node directory, commonly `/opt/homebrew/bin` on Apple Silicon or
`/usr/local/bin` on Intel/Homebrew. On Linux/systemd, replace the example with
the real `aw` path and include the directory printed by `command -v node` for
that user. After installation, `aw wake status` should show
`channel_core node=<path>` for active registered homes. `system Node executable
not found` means the service `PATH` is wrong.

## Service units

Example **launchd** user agent:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>            <string>ai.aweb.wake</string>
  <key>ProgramArguments</key> <array><string>/usr/local/bin/aw</string><string>wake</string><string>run</string></array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
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

The `ExecStart` and `PATH` values above are placeholders: replace them with the
actual locations of `aw` and `node` for the service user.

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
