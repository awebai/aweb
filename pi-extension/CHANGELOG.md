# Changelog

## 0.2.3

- Blocks visible Pi bash calls that directly tear down tmux sessions/servers or invoke `aw team up --recreate`; the launcher-inherited tmux PATH shim remains the runtime guard for commands hidden inside scripts and traps.

## 0.2.2

- Holds normal wake delivery received mid-turn until `turn_end`, and acknowledges source mail/chat only after Pi accepts the injection; shutdown rejects queued and in-flight receipts so late settlement cannot acknowledge mail.
- Refreshes stale AWID key/address state for registered senders and authoritative team-roster rows for local `did:key` mismatches; stale/unavailable continuity reports `verification_stale`, while roster-key differences remain `identity_mismatch`.
- Shows honest event-stream health, one polished disconnect/recovery message per transition, and a durable-inbox catch-up prompt after reconnect; verbose structured diagnostics are opt-in via `AWEB_CHANNEL_DEBUG=1`.

## 0.2.0

- Adds the `app_event` consumer from channel-core 45d414d2: Pi sessions can wake on app-emitted events such as `folio/doc.changed` when delivery intent is `wake`.
