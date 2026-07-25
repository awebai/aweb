# Changelog

## 0.3.0

- **Address handover is now fail-closed, and this is user-visible.** An address
  only rebinds across stable identities when the replacement announcement is
  signed by the controller published in the domain's `_awid` TXT record. A
  self-owned DID log is no longer authority over someone else's address, and an
  unanchored handover is refused rather than accepted. **Until controller
  publication exists (`default-aakj`), a LEGITIMATE handover surfaces as
  `identity_mismatch` with no remedy available to the operator.** If you are
  moving an address between identities and see `identity_mismatch`, that is this
  change, not a misconfiguration on your side.
- Trust-pin store fails closed: a present-but-empty, unreadable, or corrupt pin
  store now throws instead of silently proceeding with no pins.
- DID-log verification is bound to genesis/rotation authority: a log not derived
  from genesis is rejected, and advancing `seq` requires a `rotate_key`
  operation.
- Strict base64 parity on identity decoding (three lenient decoders closed),
  plus legacy-pin migration.

## 0.2.3

- Blocks visible Pi bash calls that directly tear down tmux sessions/servers or invoke `aw team up --recreate`; the launcher-inherited tmux PATH shim remains the runtime guard for commands hidden inside scripts and traps.

## 0.2.2

- Holds normal wake delivery received mid-turn until `turn_end`, and acknowledges source mail/chat only after Pi accepts the injection; shutdown rejects queued and in-flight receipts so late settlement cannot acknowledge mail.
- Refreshes stale AWID key/address state for registered senders and authoritative team-roster rows for local `did:key` mismatches; stale/unavailable continuity reports `verification_stale`, while roster-key differences remain `identity_mismatch`.
- Shows honest event-stream health, one polished disconnect/recovery message per transition, and a durable-inbox catch-up prompt after reconnect; verbose structured diagnostics are opt-in via `AWEB_CHANNEL_DEBUG=1`.

## 0.2.0

- Adds the `app_event` consumer from channel-core 45d414d2: Pi sessions can wake on app-emitted events such as `folio/doc.changed` when delivery intent is `wake`.
