# Changelog

## 0.3.4

- Carries the channel-core mail acknowledgement fix: the ack is deferred until
  delivery promotion rather than notification send, and promotion is claimed
  atomically.

## 0.3.3

- Bounds half-open Channel Core SSE attempts with a local deadline and a
  byte-inactivity watchdog derived from the server heartbeat; heartbeat comments
  count as liveness and reconnect continues through the existing bounded backoff.
- Removes each completed backoff's parent abort listener, preventing listener
  accumulation across repeated reconnect cycles.
- Preserves the 0.3.2 selected-team authentication and trust boundary: child
  reads remain certificate-authenticated, and decrypted child output cannot
  overwrite sender identity, signature, or trust fields.

## 0.3.2

- Keeps plaintext mail with a null encrypted envelope on the authenticated
  Channel trust path instead of hydrating it through a child `aw` process.
- Accepts only decrypted subject/body content from child `aw` output, so it
  cannot overwrite sender identity, signature, or trust fields.
- Pins child mail/chat reads to Channel's selected team and refuses startup
  when that team lacks certificate-signing authentication.

## 0.3.1

- Delivery store saves are serialized across processes, so concurrent Pi
  runtimes can no longer clobber each other's read/delivery marks.
- A corrupt delivery store is refused instead of silently reset: only a missing
  file counts as empty, and read, JSON, root-shape, or timestamp failures
  surface before an atomic save can overwrite existing marks.
- Attached principals resolve their identity home correctly, so channel
  operations under an attached identity use that principal's credentials.
- Packaged ESM channel bundles are executable, fixing launch of the bundled
  channel entry points from the installed package.

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
- **Anti-rollback checkpoint is now persisted, and it ADDS FIELDS TO YOUR PIN
  FILE.** Each pin now records `log_seq` and `log_entry_hash`, so a truncated or
  forked DID log served after a restart can no longer roll a pin back to a
  retired key. If you diff your pin store and see these two new keys, that is
  this change — they are written automatically and need no operator action.
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
