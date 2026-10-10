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
  calls OATS `input(home, text)` and resolves after OATS reports `submitted:true`.
- **Terminal submission is the read point.** After OATS reports submission,
  channel-core writes its durable delivery mark and marks mail/chat read where
  the identity's capabilities permit. Today this means tmux accepted paste and
  Enter, not that a harness queue or intended turn accepted the message. The
  at-least-once contract remains; this receipt proves neither model consumption
  nor completion of the requested task. The `blocked` guard does not change it.
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
- `status.json` and `lock/`;
- `control.sock` when the socket path fits the 100-byte portable limit.

Periodic `status.json` snapshots continue to advance `updated_at`, including
when the broker is idle. Each status writer reuses its own temporary filename
to avoid accumulating filesystem name-cache metadata on every refresh. Writes
still create the temporary file exclusively with mode 0600, sync it, and rename
it atomically; readers see a complete snapshot. An unexpected file or symlink
at that temporary name is refused without altering it or the previous snapshot.
Registration and instance-state writes retain their existing persistence path.

Long control socket paths use a stable hash of the canonical socket path in
an owner-only per-user runtime directory, shared with custody:
`/private/tmp/aw-custody-<uid>` on macOS and `/tmp/aw-custody-<uid>` on other
Unix systems. The directory is 0700 and the socket is 0600. For these shortened paths, unsafe ownership,
permissions, symlinks or file types are refused before listen and dial. Existing
short paths stay unchanged. `--state-dir` and `AW_WAKE_STATE_DIR` still select
all durable state and the input to the socket locator; no state moves to tmp.

`aw wake run` binds its control socket before reporting “listening”. A bind or
permission failure exits immediately with an error and releases the daemon
lock. Transient accept errors are logged and retried with backoff from 5 ms up
to 1 second; a closed control listener stops the broker. Restart the
broker after upgrading to use the new locator; status and control commands
compute the same path.

Legacy `pending` hint queues from the retired hint-only broker are accepted on
load only so older stores do not break startup; they are counted as evicted and
dropped. They are not replayed, composed or injected. Channel-core's delivered-ID
store is separate delivery state. It dedupes accepted presentations; it is not a
proof that the agent completed the work.

## Immediate presentation and safety

Mail and chat are delivered on arrival, including while the harness reports
working or unknown. Readiness gating, coalescing and rate limiting were
removed pending an architecture rethink. Legacy `--coalesce` and `--rate-limit`
options are accepted but ignored.

The serialized terminal adapter inspects only for safety before input. A raw
shell, `blocked` modal, stopped/not-launched harness, `present:false`, or failed inspect refuses
input and leaves the message unread for bounded retry and fresh-snapshot recovery. Exhausted mail/chat presentation
requests one coalesced stream re-open after five seconds. Stopped/not-launched observations mark the instance inactive only after the
child has observed `present:true`; a prelaunch home stays pending and retries
through unread snapshots without needing re-registration.

The `blocked` refusal prevents wake text and Enter from answering a modal such
as a permission prompt or AskUserQuestion. It does not defer ordinary working
sessions. It relies on inspection identifying the modal; `unknown` still
delivers, and a modal appearing between inspection and input requires protection
in the session/harness transport. A submitted-input receipt is not evidence of
model consumption.

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

### Observed managed-receiver withdrawal

Ordinary deregistration keeps its offline/idempotent behavior. Its successful
exit, registry-file removal, and status absence are **not** a managed-stop
completion receipt: a control timeout can use file fallback while the daemon
is still joining the worker.

For an explicitly authorized withdrawal requiring that proof, the additive
strict mode is:

```sh
aw wake deregister --home /absolute/receiver --state-dir /authorized/broker-state \
  --require-managed-stop --expect-registration receiver.json --json
```

Obtain `receiver.json` from the selected row's complete `managed_receiver`
object in `aw wake status --state-dir /authorized/broker-state --json`.
For example, after saving that output as `status.json`:

```sh
jq -e --arg home /absolute/receiver \
  '[.instances[] | select(.home == $home and .registration_pending != true) | .managed_receiver | select(. != null)] | if length == 1 then .[0] else error("no unique eligible managed receiver") end' \
  status.json > receiver.json
```

Use the already established target broker scope; a default path is not evidence
of which daemon owns a receiver. This object comes from the live daemon's
accepted in-memory registration, including every receive binding, its original
registration clock, generation, and an ephemeral `owner_id`. It is omitted by
file-fallback status, older daemons, pending registration updates, and owners
without a captured child. `registration_pending` is an additive live-status
field. Other status fields remain compatible. A cached/exported object is an
expectation, not a lease: strict admission compares the full normalized snapshot
and current stored registration before invalidating, stopping, or deleting
anything. Pending changes, another owner (including daemon replacement), and a
changed generation or complete registration are refused.

A paused child remains eligible; pause is preserved until withdrawal. An
inactive signal may already have joined and cleared the child, which is **not**
eligible. The strict operation does not invent historical completion from that
absence, nor from a file-only registration, prior crash, or missing owner. A
plan needing this receipt must withdraw the eligible managed receiver before
stopping its harness; it must not resume or create a child to manufacture proof.

The new control operation is distinct (`deregister-managed`); an old daemon
rejects it without taking the ordinary deregistration path. Both the CLI and
actual owning daemon must support it. Installing a new CLI does not upgrade the
owner, and a replacement daemon cannot certify its predecessor's join. This
interface supplies no daemon adoption or global-restart procedure.

A positive JSON receipt has `version: 1`, `scope: "captured-managed-worker"`,
`receiver` equal to the invocation's complete expectation, `managed_joined:
true`, a nonzero `completed_at`, and `accepted_input_disposition:
"not_certified"`. The client validates these fields before successful exit.
The daemon has joined the captured supervisor (including its pipe readers) and
observed absence of the process groups it recorded for that child's executions.
Observation uses only those owned group IDs, without host-wide discovery or
additional signals. Unsupported observation, permission error, or a group
remaining present is non-complete. PID/group reuse may conservatively prevent
confirmation; it does not authorize killing a different process. Escaped process
groups and historical owners are outside this proof.

The strict client bounds dial plus exchange to 15 seconds. Server admission
waits within its 15-second request context; the existing shutdown has a
five-second graceful period plus reader cleanup. After join, owned-group
confirmation gets at most five seconds and never exceeds the remaining server
context. Once stop begins, serialization stays held until actual join, even if
the context or transport expires: 15 seconds is **not** a promise that all daemon
work has finished. Timeout, lost/truncated response, or an invalid receipt is
unconfirmed even if the daemon later finishes. Strict mode never performs local
file fallback. A failed operation may have stopped the worker/deleted state;
there is no durable completion journal, so retry cannot manufacture success
from a now-absent owner. Existing ordinary control deadlines are unchanged.

This receipt concerns the captured managed worker, not permission for successor
admission, native receivers, an exclusive future lease, or all orphan processes.
A later authorized registration can create new ownership. Stopping future
managed presentation cannot retract already accepted input, certify command
execution/model consumption, or guarantee all delivery marks persisted. The
operator must separately reconcile durable message/task IDs through withdrawal
and obtain successor acceptance of the bounded remaining work. Do not replay
completed effects merely because a stop receipt is absent.

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
