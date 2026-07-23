# Changelog

## 1.5.2

- Refreshes stale AWID key/address state for registered senders and authoritative team-roster rows for local `did:key` mismatches; stale/unavailable continuity reports `verification_stale`, while roster-key differences remain `identity_mismatch`.
- Keeps Claude-channel mail unread because MCP notifications are fire-and-forget; reconnect replay is deduplicated locally, and only an agent-side reply or explicit `aw mail ack` marks mail read.
- Reports event-stream disconnect/recovery once per state change with a concise cause and retry cadence, and prompts durable inbox catch-up after recovery instead of printing raw retry errors.

## 1.5.0

- Adds the `app_event` consumer from channel-core 45d414d2: Claude Code sessions can wake on app-emitted events such as `folio/doc.changed` when delivery intent is `wake`.
