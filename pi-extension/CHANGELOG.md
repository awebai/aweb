# Changelog

## Unreleased

- Add opt-in `AWEB_WAKE_PRESENTATION=line` for one-line mail/chat wakes with exact read/reply commands; full presentation remains the default and acknowledgement is unchanged.

## 0.4.0

- Publish live agent activity for the session when the host owner opts in
  with `activity: status` in the identity home's `activity.yaml` (off by
  default; see docs/agent-activity.md). An agent run is a turn; reasoning,
  reply text and tool calls publish short, templated, signed status events,
  attributed to the chat whose wake started the run, and a session ended
  mid-run closes its turn. Requires server 1.27.26 or later; against an older
  server publishing stops quietly.

## 0.3.15

- Record successful event-stream reads in the selected identity directory's
  `receive/stream.json` for host health publishers. The receipt includes the
  signing DID, optional stable ID, process ID and read timestamps. It is written
  atomically with mode 0600, refreshed at most every 30 seconds on server reads
  (including keepalives), and removed on clean stream close or disconnect.
  `AWEB_DELIVERY=session` opens no stream and writes no receipt.

## 0.3.14

- Connection and stopped-loop diagnostics stay in operator logs/status and do
  not inject agent turns. Reconnect no longer asks for manual inbox/chat scans;
  the resumed stream catches up from durable actionable state.
- Bundles channel-core's addressless global and cross-team local sender trust
  fixes, with signature and recipient binding checks retained.

## 0.3.13

- **Upgrade from 0.3.12.** Pi 0.3.12 presents end-to-end encrypted mail from
  a legitimate sender as `trust_status: unverified`, with a warning that
  sender verification failed: it predates the Channel Core encrypted-envelope
  verification below. Upgrade to 0.3.13.
- Requires `@awebai/aw` `^1.36.35`, the release tested with this version.
- Bundles the Channel Core sender-trust fixes released for the Claude channel
  since Pi 0.3.12:
  - Verify encrypted mail/chat push trust against the locally decrypted v2
    envelope and the existing sender trust checks (channel 1.7.12).
  - Grant receivers authenticate the authoritative team roster read used for
    same-team sender verification (channel 1.7.13).
  - A sender the AWID registry definitively does not know (HTTP 404) is
    `identity_mismatch`; an unavailable or unreachable registry stays
    `verification_stale` (channel 1.7.14).
- Surfaces grant verification failures reported on the event stream.
- Also bundles Channel Core's terminal wake adapter changes made for the
  `aw wake` broker.

## 0.3.12

- Bundles Channel Core 0.2.0, including the shared terminal wake adapter
  readiness/status APIs and grant-home client support used by the `aw-v1.36.15`
  wake broker.

## 0.3.11

- Keeps event-stream reconnect/disconnect status out of Pi model turns while
  preserving status-line updates and warning diagnostics. Genuine aweb
  awakenings still enqueue through the Pi wake dispatcher.
- This is the bounded Stage 1 wake fix for planned CLI tag `aw-v1.36.14`;
  `aweb-abkk` remains the follow-up architecture work for a full
  channel-core terminal wake adapter.

## 0.3.10

- Adds `AWEB_DELIVERY`. With `AWEB_DELIVERY=session` the extension opens no
  event stream and delivers no wake-ups, so a host-side wake service can own
  this identity's single event stream without competing with the extension for
  it. Identity resolution, the bundled skills, the welcome, and the `aw` CLI
  path are unaffected; one startup line says delivery is external and the status
  line reads `aweb delivery external`. Unset or `channel` is the existing
  behaviour; any other value is reported once and treated as `channel`.

## 0.3.6

- Includes the Channel Core trust-path changes above: compare-and-set retry on
  pin commits, coalesced last-seen writes, and trust resolution moved out of the
  pin lock.

## 0.3.5

- Includes the Channel Core burst-resolution fix and the opt-in delivery-stage
  diagnostics.
- Queues active-turn wake deliveries through Pi's accepted follow-up path
  instead of holding them behind the current turn; source mail and chat are
  acknowledged only after Pi accepts the injection.
- Bundles js-yaml 4.3.1 with the same local-config exposure bound.

## 0.3.4

- Bundles the Channel Core identity fix so repeated sender mismatches remain
  fail-closed without forcing an uncached AWID or team-roster lookup for every
  message; ordinary bounded cache expiry reconciles updated identity state.

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
