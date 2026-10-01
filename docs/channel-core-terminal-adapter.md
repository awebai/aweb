# Channel-core terminal wake adapter contract

Go owns registration, stream admission, lifecycle and process supervision.
Channel-core owns exact unread fetch, decrypt/trust, formatting, terminal input,
durable delivered IDs, mail acknowledgment and chat read marking. Go implements
`TerminalSession` through OATS `session inspect|input` by instance home.

## Immediate presentation

Mail and chat are delivered on arrival. Readiness gating was removed pending an
architecture rethink: working, blocked and unknown states do not delay delivery.
There is no readiness queue, coalescing window, rate limit or readiness polling.

The terminal adapter serializes input across delivery lanes. Each caller checks
only terminal safety before input: `shell` (including `generic shell`), `stopped`,
`not-launched` and `present:false` refuse input, because there is no running
harness to receive it. A failed safety inspect also refuses input. These failures
use the normal bounded delivery retry and leave the source unread.

Mail and chat present full `formatAwakeningForAgent` text, including sender/trust
metadata and message body, through `terminalInputSafeText`. Terminal controls
are stripped. Multiple receive bindings add a safely quoted `--identity-home`
recovery command as a footer; invalid recovery context never replaces content.

Explicit operator pause remains independent of readiness. Paused input rejects
without typing, including if pause arrives during the safety inspection. Resume requests an immediate stream re-open after applying the control, so
a fresh unread snapshot re-offers refused messages; no held-text retry queue is
created. Legacy `--coalesce` and `--rate-limit` flags remain accepted but ignored.

## Acceptance and retry

1. Channel-core fetches the exact unread message and decrypts/verifies it.
2. The terminal adapter serializes the safety check and input, then resolves
   after input accepts.
3. Only after acceptance does channel-core record durable delivered IDs and
   acknowledge mail or mark chat read, where the identity's capabilities permit.
4. Rejected input retries the event after 100 ms, 250 ms and 500 ms, including a
   fresh unread fetch each time. After a mail/chat presentation exhausts these
   attempts, the child requests a stream re-open after five seconds. Requests
   coalesce into one timer per admitted binding stream, and a natural reconnect
   or resume replaces that timer. Repeated refusals get another bounded window.
   A later unrelated exact-ID event cannot recover a refused message; the fresh
   unread snapshot does. No message IDs or bodies are held for replay.

A read-only mail grant cannot acknowledge server mail. Its accepted input can
still record a local delivery mark. Presentation acknowledges content reaching
the terminal, not completion of the agent's work. A crash between accepted input
and durable delivery/read marks can cause duplicate presentation.

Abort during the safety inspection prevents input. Once input has accepted,
a later abort does not turn acceptance into rejection; delivery/read marks may
finish during shutdown.

Ambient app/work/claim awakenings retain their separate bounded piggyback queue
(default cap 50, latest per ID). They never initiate input and are attached once
to the next wake/steer input. Overflow rejects the oldest item; durable app events
can return on snapshot. This is not a readiness deferral queue.

There is no `/v1/events/actionable` route or Go read/ack implementation. Claude/Pi
use their native presentation callbacks with the same acceptance/read ordering.

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
commands have a 30-second timeout. Safety inspection commands are aborted on shutdown;
an input already in flight can finish during the grace period. This reduces
avoidable duplicate delivery without promising exactly-once terminal receipt.
An `ok:true` input with `submitted:false` remains an ordinary input error: the
existing bounded retry applies, and failed delivery is neither marked nor acked.

Child stdout/stderr records are bounded to 1 MiB. Oversized records are reported
and drained to the next newline so subsequent status records still arrive.

At child startup, one bounded inspect reports readiness even if no event is
waiting. A stopped or not-launched result marks the instance inactive through
the same callback used by the delivery safety check. A successful present observation persists `first_present_at`, so a
quiet home retains its confirmed-live state when an older broker reads the
store. Startup inspect failure is reported; later events use the normal
bounded delivery retry path. There is no extra periodic idle probe. The child receives
the OATS executable resolved from `--oats-bin`, then `AW_WAKE_OATS_BIN`, then PATH.
