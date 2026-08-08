# Changelog

## 1.7.4

- Stops repeated sender-identity mismatches from forcing an uncached AWID or
  team-roster lookup on every message. Mismatches remain fail-closed, while
  ordinary bounded cache expiry picks up updated roster, address, and key state.

## 1.7.3

- Uses the distinct `aweb-channel` MCP declaration and runtime name as an
  empirical defense against observed fresh-session plugin MCP non-enumeration.
  The underlying Claude Code mechanism remains unconfirmed.

## 1.7.2

- Keeps plaintext mail with a null encrypted envelope on the authenticated
  Channel trust path instead of hydrating it through a child `aw` process.
- Accepts only decrypted subject/body content from child `aw` output, so it
  cannot overwrite sender identity, signature, or trust fields.
- Pins child mail/chat reads to Channel's selected team and refuses startup
  when that team lacks certificate-signing authentication.

## 1.5.2

- Refreshes stale AWID key/address state for registered senders and authoritative team-roster rows for local `did:key` mismatches; stale/unavailable continuity reports `verification_stale`, while roster-key differences remain `identity_mismatch`.
- Keeps Claude-channel mail unread because MCP notifications are fire-and-forget; reconnect replay is deduplicated locally, and only an agent-side reply or explicit `aw mail ack` marks mail read.
- Reports event-stream disconnect/recovery once per state change with a concise cause and retry cadence, and prompts durable inbox catch-up after recovery instead of printing raw retry errors.

## 1.5.0

- Adds the `app_event` consumer from channel-core 45d414d2: Claude Code sessions can wake on app-emitted events such as `folio/doc.changed` when delivery intent is `wake`.
