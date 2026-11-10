# Event stream client policy

Status: **proposal for review** (aweb-acxc.23). Nothing here is implemented
until it is accepted. The terminal-status rules are a protocol decision.

A client of `GET /v1/events/stream` is a process that must hear about mail,
chat and control signals for as long as it runs. This page states one policy
for how such a client connects, reconnects and reports its state. Three
clients implement the stream today, each with its own rules:

- `channel-core/src/api/events.ts` (the Claude Code plugin, the Pi extension
  and the `aw wake` child);
- `cli/go/wake/stream.go` (the `aw wake` broker, one stream per identity);
- `cli/go/run/eventbus.go` (`aw run`).

## What the three clients do today

| | channel-core | wake broker | `aw run` |
|---|---|---|---|
| Backoff | 1 s doubling to 5 s; a failed open waits 5 s | 1 s doubling to 15 s | 250 ms doubling to 2 s |
| Jitter | none | between half and all of the delay | none |
| `Retry-After` | ignored on the stream | ignored | ignored |
| 401, 403, 404, 422 on open | retried every 5 s for ever | stream stops until the daemon restarts ("quarantined") | stream stops for the life of the process |
| Other 4xx on open (408, 409, 429) | retried every 5 s | bounded retry | stream stops for the life of the process |
| Grant terminal events (`grant_expired`, `grant_revoked`, `grant_subject_inactive`, `grant_issuer_revoked`) | retried every 5 s for ever | as the source reports them | as the source reports them |
| Planned close | reconnects at once after 4 minutes | closes itself at 4 minutes, reconnects at once | local deadline of 10 minutes |
| Silence on an open stream | reconnects after two missed heartbeats plus 15 s (75 s) | none of its own | none of its own |

Two of these are defects with a visible effect. An `aw run` agent that
receives one 429 or 408 while opening its stream hears nothing more until it
is restarted. A wake broker stream that receives one 401, for example because
the host clock was briefly wrong, stays stopped until the daemon restarts,
while the broker goes on reporting that identity as admitted.

The differences also matter together: after a server restart every client
reconnects within its own window, and the two without jitter reconnect in
step.

## Policy

### 1. A client never stops for the life of its process

No answer from the server ends the stream for good. A client that cannot
connect keeps a retry scheduled, at the pace sections 3 and 4 give, until its
process ends or its owner stops it. What a long-lived agent must not do is go
deaf without anyone asking it to.

### 2. Planned close is not an outage

The server closes a stream at the deadline the client asked for, at most five
minutes. A client asks for its own planned close before that and reconnects
at once, without backoff and without reporting a disconnect.

A client picks its planned close uniformly between 3 minutes 30 seconds and
4 minutes for each connection. Clients that connected together, as all of
them do after a server restart, then drift apart instead of reconnecting in
step every four minutes.

### 3. Transient failures: backoff with jitter

A failure to open, a stream that ends before its planned close, a read
error, silence (section 6), any 5xx, and the 4xx statuses that describe a
moment rather than the caller (408, 409, 425, 429) are transient.

- The delay starts at 1 second and doubles to a ceiling of 15 seconds.
- Each wait is drawn uniformly between half of the delay and all of it.
- The delay returns to 1 second only once a stream is confirmed live: its
  first event or heartbeat has been read. An open that returns 200 and then
  closes does not reset it.
- When the answer carries `Retry-After`, the client waits at least that long,
  up to 5 minutes, plus the jitter above. A larger or unparsable value is
  treated as 5 minutes.

### 4. Refusals: slow retry, not a stop

401, 403, 404 and 422 on open, and the grant terminal events on an open
stream, say that the server will not serve this caller as it presents itself.
Retrying at once cannot help. Stopping for good is wrong too, because each of
them has causes that end without the process restarting:

| Answer | Causes that end by themselves or by an operator's action elsewhere |
|---|---|
| 401 | the host clock was outside the five-minute window and has been corrected; a certificate was renewed on disk; the registry was briefly unable to confirm the key |
| 403 | membership or a scope was restored |
| 404 | the server was mid-deploy or the route was briefly unmounted; the agent was re-created |
| 422 | a server and client disagree on a parameter during a rolling upgrade |
| grant terminal event | the grant was renewed or reissued into the same home |

So a refused stream is **quarantined**:

- The client reports the stream as refused, with the status and when it will
  try again. It does not report it as connected or as merely retrying.
- It retries after 1 minute, doubling to a ceiling of 15 minutes, with the
  same jitter as section 3.
- Before each retry it reads its credentials again from where they are kept,
  so a renewed certificate or grant is used without a restart.
- An explicit request for the stream (a registration with the wake broker, a
  new `aw run` session, a restart of the channel) retries at once and, if
  refused again, continues from the 1-minute delay.
- The first successful, confirmed stream ends the quarantine.

`verification_unavailable` is not a refusal. It says the server could not
check the grant; it is transient and follows section 3.

### 5. No fallback and no change of identity

A refused client does not retry with other credentials, another signing
form or another server. It retries as itself or not at all.

### 6. Silence on an open stream

The server sends a heartbeat comment every 30 seconds. A client that has read
nothing for 75 seconds (two missed heartbeats plus 15 seconds) closes the
connection and treats it as a transient failure. Every byte counts, including
comments.

### 7. Catch-up after any reconnect

The stream has no cursor. The snapshot the server sends when a stream opens
raises what is still unread or pending, and that snapshot is the only
catch-up. A client does not replay events from memory across a reconnect.
This is the existing rule ([terminal wake broker, "Reconnect and crash
windows"](terminal-wake-broker.md#reconnect-and-crash-windows)); it is
restated because the delays above are only acceptable with it.

### 8. What a client reports

Each client exposes one of three states, with the cause and the time of the
next attempt where there is one:

- **streaming**: a confirmed stream is open;
- **retrying**: section 3 applies;
- **refused**: section 4 applies, with the status or event name.

A planned close does not leave `streaming`.

## What changes in each client

| | channel-core | wake broker | `aw run` |
|---|---|---|---|
| Backoff ceiling | 5 s becomes 15 s | unchanged | 2 s becomes 15 s |
| Jitter | added | unchanged | added |
| `Retry-After` | honoured | honoured | honoured |
| Refusals | every 5 s becomes 1 to 15 minutes, reported as refused | a stop becomes 1 to 15 minutes; a registration retries at once | a stop becomes 1 to 15 minutes |
| 408, 409, 429 | unchanged | unchanged | a stop becomes transient retry |
| Planned close | jittered | jittered | 10 minutes becomes 3.5 to 4 minutes |
| Silence | unchanged | added | added |

The two Go clients share one implementation of sections 2 to 6. The
TypeScript client has its own and is tested against the same table of cases.

## Questions for the reviewer

1. **Is slow retry right for 401 and 403, or should a revoked credential stop
   for good?** The case for slow retry is that the client cannot tell a
   revoked certificate from a corrected clock or a renewed file, and the cost
   to the server is one refused request per identity every 15 minutes. The
   case against is that a revoked identity keeps knocking. The server already
   counts refused authentication.
2. **Which 4xx statuses are transient.** This page lists 408, 409, 425 and
   429. Any 4xx not named in section 3 or 4 is treated as a refusal.
3. **The quarantine delays** (1 to 15 minutes) and the `Retry-After` cap
   (5 minutes) are choices, not derived values.
4. **`aw run`'s planned close.** Moving from 10 minutes to under 4 changes
   nothing a user sees, since the server closes at 5, but it is a change of
   behaviour in a released client.
