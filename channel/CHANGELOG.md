# Changelog

## 1.7.9

- Adds `AWEB_DELIVERY`. With `AWEB_DELIVERY=session` the plugin registers no
  channel, opens no event stream, and delivers no notifications, so a host-side
  wake service can own this identity's single event stream without competing
  with the plugin for it. Identity resolution, the bundled aweb skills, and the
  `aw` CLI path are unaffected, and one startup line says delivery is external.
  Unset or `channel` is the existing behaviour; any other value is reported once
  and treated as `channel`.

## 1.7.6

- Retries a trust pin commit when a concurrent writer wins the compare-and-set,
  so simultaneous first contacts no longer drop one side's pin.
- Stops a steady-state message from forcing a pin-store commit: last-seen
  updates coalesce over a bounded window instead of writing on every delivery.
- Resolves trust outside the pin lock, leaving only the decision and its commit
  inside it, so one slow resolution no longer holds the lock against everyone.

## 1.7.5

- Collapses concurrent authenticated team-roster resolution into one shared
  request, briefly caches the roster, and applies a short backoff after shared
  failures. Sender metadata now resolves before the per-process trust critical
  section, while each trust decision and its pin-store commit remain atomic.
  This stops burst traffic from becoming a 30-second-per-lane notification
  ladder.
- Adds opt-in closed-schema delivery-stage diagnostics, written asynchronously
  to a local regular file. Explicit trace destinations must not be FIFOs,
  devices, sockets, mounted or network volumes, or sinks whose appends can hang.
- Bundles js-yaml 4.3.1, addressing GHSA-5p4m-2wfm-xmqj / CVE-2026-59870.
  Exposure is local-config denial-of-service hardening: Channel does not parse
  untrusted YAML from the delivery wire, and pin-store YAML uses JSON_SCHEMA.

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
