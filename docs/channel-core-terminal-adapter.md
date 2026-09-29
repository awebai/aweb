# Channel-core terminal wake adapter contract

`aweb-abkk` moves terminal wake delivery onto `channel-core` instead of the Go
hint composer. The Go daemon remains the host/session bridge: registration,
stream admission, pause/rate/coalescing policy and OATS calls stay host-local,
but message fetch/decrypt/trust/delivered/read/ack state belongs only to
`channel-core`.

## Boundaries

- `channel-core` owns event consumption, exact fetch, local decrypt, sender trust,
  durable delivered IDs, mail ack and chat read marking.
- The terminal adapter owns only presentation to the live session through an
  OATS-like `inspect`/`input` pair. It reports success by resolving the
  `onAwakening` promise only after `input` accepts the text.
- Go/OATS never marks mail/chat/app events read or delivered. If terminal input
  fails or the session is not ready, the `onAwakening` promise remains pending
  and channel-core does not ack/read/mark delivered.
- Endpoint C remains withdrawn: no `/v1/events/actionable` route and no Go
  read/ack logic.

## Readiness

The adapter normalizes backend vocabulary before it attempts input:

| Raw backend state | Adapter state | Wake/steer | Ambient |
| --- | --- | --- | --- |
| `idle`, `done` | `idle` | input allowed | queued only |
| unknown/empty/new words | `unknown` | input allowed | queued only |
| `working`, `busy`, `running` | `working` | defer/retry | queued only |
| `blocked` | `blocked` | defer/retry | queued only |
| `stopped` | `stopped` | defer/retry; no ack | queued only |
| `present:false` | `not-launched` | defer/retry; no ack | queued only |

`unknown` is intentionally deliverable for wake/steer because tmux often has no
better readiness signal. Ambient events never initiate terminal input by
themselves; they piggyback on the next wake/steer batch.

## Queue and retry

The adapter is a single FIFO queue per terminal home.

1. Every awakening is enqueued and represented by a promise returned to
   channel-core.
2. Ambient awakenings do not start a drain. Their promises remain pending until
   a wake/steer item arrives and the batch is typed.
3. Wake/steer starts a drain. The adapter inspects the terminal first.
4. If readiness is `idle` or `unknown`, the adapter formats all queued
   awakenings with channel-core's `formatAwakeningForAgent()` and calls
   `input(home, text)` once for the batch.
5. If `input` succeeds, all batched promises resolve. Only then may channel-core
   write delivered IDs and mail/chat read acknowledgments.
6. If inspection says not ready, or input fails/refuses, the queue is retained
   and retried after the configured delay. No promise resolves, and therefore
   no channel-core ack/read/delivered mark is written.
7. If the adapter is aborted, pending promises reject; channel-core leaves the
   source events pending.

This is deliberately at-least-once until the session accepts input. It does not
claim that a human/model processed the message; it only gives channel-core the
same presentation boundary that Claude/Pi have: accepted host delivery is the
point at which channel-core may acknowledge.
