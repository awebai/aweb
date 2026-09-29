# Channel-core terminal wake adapter contract

`aweb-abkk` moves terminal wake delivery onto `channel-core` instead of the Go
hint composer. The Go daemon remains the OATS transport and process supervisor,
but there is one delivery decision path: channel-core owns readiness gating,
exact fetch, decrypt/trust, delivered IDs, mail ack and chat read marking. Go
implements `TerminalSession` (`inspect`/`input` by instance home), process
supervision and status surfaces only.

Endpoint C remains withdrawn: no `/v1/events/actionable` route and no Go
read/ack logic.

## Boundary

- `channel-core` owns event consumption, exact unread fetch, local decrypt,
  sender trust, durable delivered IDs, mail ack and chat read marking.
- `ChannelLoopOptions.awaitDeliveryReady(intent, signal)` runs **before** exact
  fetch for wake/steer delivery. If the terminal is busy, nothing has been
  fetched yet, so an out-of-band read while waiting is seen by the later
  unread-only fetch and drops out.
- The terminal `onAwakening` adapter performs no inspect gate and holds no
  fetched wake/steer content. It formats the awakening and calls terminal
  `input(home, text)` immediately. It resolves only after input accepts.
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
retried by re-dispatch rather than waiting for a later reconnect/event.

## Readiness before fetch

The terminal readiness gate normalizes backend vocabulary:

| Raw backend state | Adapter state | Wake/steer |
| --- | --- | --- |
| `idle`, `done` | `idle` | allowed after confirmed live |
| unknown/empty/new words | `unknown` | allowed after confirmed live, coalescing and rate limit |
| `working`, `busy`, `running` | `working` | defer/retry before fetch |
| `blocked` | `blocked` | defer/retry before fetch |
| `shell`, `generic shell` | `shell` | defer/retry before fetch; never type message text into a bare shell |
| `stopped` after confirmed live | `stopped` | inactive/status, no input |
| `present:false` after confirmed live | `not-launched` | inactive/status, no input |

Nothing is delivered before the first confirmed live inspect (`present:true`).
For `unknown` terminals (tmux), channel-core applies the same shape as the Go
policy: a coalescing delay plus a per-instance rate limit before fetch.

After every await in readiness (inspect or delay), abort is checked again. Abort
while inspect is in flight rejects readiness and no input may occur.

## Queue and retry

1. A wake/steer event reaches channel-core.
2. Channel-core awaits `awaitDeliveryReady(intent, signal)` before exact fetch.
3. When ready, channel-core performs the usual unread exact fetch. Anything read
   out of band during the wait is absent and is not presented.
4. Channel-core calls `onAwakening` for fetched messages. The terminal adapter
   inputs immediately and resolves after `input` accepts.
5. Only after `onAwakening` resolves does channel-core write delivered IDs and
   mail/chat read acknowledgments.
6. If input rejects, channel-core retries the event with bounded backoff and a
   fresh unread exact fetch. The adapter does not retry held text.
7. Ambient events are stored in a bounded adapter queue (default cap 50, latest
   per `task_id`/`event_id`). Overflow rejects the oldest ambient item; app
   events therefore remain undelivered and can return on snapshot, while
   work/claim have no durable read state.

Multi-message fetches are gated once, before the fetch. Items 2..N from the same
fetch are not re-gated after item 1 is typed. Future implementations may batch
all per-fetch awakenings into one input; one input per message is allowed only
with this no-regate rule.

## Packaging note

The aw distribution bundles channel-core JavaScript (prefer embedded/extracted
JS) and runs it with system Node. npm installs already provide Node; standalone
binary users without Node must get a clear `aw wake status`/log error. aw does
not ship a Node runtime inside every binary.
