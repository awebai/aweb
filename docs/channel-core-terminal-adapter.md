# Channel-core terminal wake adapter contract

`aweb-abkk` moves terminal wake delivery onto `channel-core` instead of the Go
hint composer. The Go daemon remains the OATS transport and process supervisor,
but there is one delivery decision path: channel-core owns readiness gating,
coalescing, rate limiting, exact fetch, decrypt/trust, delivered IDs, mail ack
and chat read marking. Go implements `TerminalSession` (`inspect`/`input` by
instance home), registration lifecycle (including pending expiry and retire
hooks), process supervision and status surfaces only.

Endpoint C remains withdrawn: no `/v1/events/actionable` route and no Go
read/ack logic.

## Boundary

- `channel-core` owns event consumption, exact unread fetch, local decrypt,
  sender trust, durable delivered IDs, mail ack and chat read marking.
- `ChannelLoopOptions.awaitDeliveryReady(intent, signal)` runs **before** exact
  fetch for wake/steer delivery. If the terminal is busy, nothing has been
  fetched yet, so an out-of-band read while waiting is seen by the later
  unread-only fetch and drops out.
- The terminal `onAwakening` adapter serializes presentation per terminal across
  delivery lanes. Each caller re-inspects immediately before input, preserving
  the terminal boundary checks after waiting for a previous caller. It resolves
  only after input accepts. Ambient items are attached once to that input.
- If input rejects, `onAwakening` rejects. Channel-core retries the failed event
  lane by re-running the event, including the unread-only exact fetch. Messages
  already acked before a later failure are not re-presented because the refetch
  is unread-only.
- Ambient awakenings never call `awaitDeliveryReady` and never initiate input.
  They are bounded in the terminal adapter and piggyback on the next wake/steer
  input.
- The residual at-least-once window is the small interval from unread exact
  fetch through terminal input acceptance. The earlier minutes-long hold of
  already-fetched content is forbidden.

Claude/Pi do not pass `awaitDeliveryReady`, so their success path is unchanged.
The retry-on-rejected-awakening path improves them too: a failed notification is
retried by re-dispatch rather than waiting for a later reconnect/event. The
bounded retry budget is 100 ms, 250 ms and 500 ms. After it is exhausted the
event is left for the next event or the next stream re-open snapshot (the server
stream cycle is up to 300 seconds), preserving at-least-once delivery without
holding already-fetched terminal content. The gate currently stamps the rate
window when readiness releases. If the subsequent unread fetch finds nothing
because the item was read out of band, the next real delivery can still wait up
to the 30 second rate limit; a later `noteInput`-style stamp can narrow that,
but it is outside this foundation pass.

## Readiness before fetch

The terminal readiness gate normalizes backend vocabulary:

| Raw backend state | Adapter state | Wake/steer |
| --- | --- | --- |
| `idle`, `done` | `idle` | allowed after confirmed live, coalescing and rate limit |
| unknown/empty/new words | `unknown` | allowed after confirmed live, coalescing and rate limit |
| `working`, `busy`, `running` | `working` | defer/retry before fetch |
| `blocked` | `blocked` | defer/retry before fetch |
| `shell`, `generic shell` | `shell` | defer/retry before fetch; never type message text into a bare shell |
| `stopped` after confirmed live | `stopped` | inactive/status, no input |
| `present:false` after confirmed live | `not-launched` | inactive/status, no input |

Nothing is delivered before the first confirmed live inspect (`present:true`).
Pause is an input to the gate (`isPaused`) supplied by the Go bridge; while
paused, the gate sleeps and continues before fetch. Inspect errors are treated
like transient OATS failures: they are logged/statused, then the gate sleeps and
tries again. Every delivery window uses the Go broker defaults: 2 seconds
coalescing, 30 seconds rate limit and a 2 second inspect/defer poll. The first
waiting caller opens the window; after coalesce and rate-limit have elapsed,
the gate checks pause and performs a fresh inspect. All callers waiting at that
fresh ready inspect pass together immediately, with no await between readiness
and release. If pause is set or the fresh inspect reports busy/blocked/shell,
the gate polls and re-inspects; it does not restart the already-elapsed
coalesce/rate wait. The window then resets so the next burst coalesces again.

After every await in readiness (inspect or delay), abort is checked again. Abort
while inspect is in flight rejects readiness and no input may occur. Once
terminal `input` has accepted text, a later abort must not turn that accepted
presentation into a rejection; channel-core may then write delivered IDs and
mail/chat read acknowledgments.

## Queue and retry

1. A wake/steer event reaches channel-core.
2. Channel-core awaits `awaitDeliveryReady(intent, signal)` before exact fetch.
3. When ready, channel-core performs the usual unread exact fetch. Anything read
   out of band during the wait is absent and is not presented.
4. Channel-core calls `onAwakening` for fetched messages. The terminal adapter
   serializes the final readiness re-inspect and input, then resolves after
   `input` accepts.
5. Only after `onAwakening` resolves does channel-core write delivered IDs and
   mail/chat read acknowledgments.
6. If input rejects, channel-core retries the event with bounded backoff and a
   fresh unread exact fetch. The adapter does not retry held text.
7. Ambient events are stored in a bounded adapter queue (default cap 50, latest
   per `task_id`/`event_id`; updating a key refreshes its recency). Overflow
   rejects the oldest ambient item; app events therefore remain undelivered and
   can return on snapshot, while work/claim have no durable read state.

The terminal gate reports status data for Go to surface in `aw wake status`:
last state, last inspect error, paused state supplied by Go, inactive callback,
and ambient queue depth/drops from the adapter. This is status reporting, not a
second Go-side delivery decider.

Multi-message fetches are gated once, before the fetch. Items 2..N from the same
fetch are not re-gated after item 1 is typed. Future implementations may batch
all per-fetch awakenings into one input; one input per message is allowed only
with this no-regate rule.

## Packaging note

The aw distribution bundles channel-core JavaScript (prefer embedded/extracted
JS) and runs it with system Node. npm installs already provide Node; standalone
binary users without Node must get a clear `aw wake status`/log error. aw does
not ship a Node runtime inside every binary.

## Child process lifecycle

The Go supervisor sends events through a bounded queue to a dedicated pipe
writer. A stalled reader cannot block supervision or shutdown; overflow drops
oldest queued events and counts evictions. Unread work can return on the next
stream snapshot. Fatal child status triggers restart with backoff, and a fatal
startup error exits the Node process even while its input pipe remains open.

Shutdown requests the protocol shutdown and SIGTERM, allowing up to five
seconds for in-flight input and delivery marks to complete. The Unix child runs
in its own process group; final cleanup kills remaining descendants. OATS
commands have a 30-second timeout. Readiness commands are aborted on shutdown;
an input already in flight can finish during the grace period. This reduces
avoidable duplicate delivery without promising exactly-once terminal receipt.
An `ok:true` input with `submitted:false` remains an ordinary input error: the
existing bounded retry applies, and failed delivery is neither marked nor acked.

Child stdout/stderr records are bounded to 1 MiB. Oversized records are reported
and drained to the next newline so subsequent status records still arrive.

At child startup, one bounded inspect reports readiness even if no event is
waiting. A stopped or not-launched result marks the instance inactive through
the same callback used by the delivery readiness gate. A successful present observation persists `first_present_at`, so a
quiet home retains its confirmed-live state when an older broker reads the
store. Startup inspect failure is reported; later events use the normal
readiness retry gate. There is no extra periodic idle probe. The child receives
the OATS executable resolved from `--oats-bin`, then `AW_WAKE_OATS_BIN`, then PATH.
