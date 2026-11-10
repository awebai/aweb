# Event stream client policy

Status: **accepted policy** (aweb-acxc.23). The clients are brought to it one
at a time; "What changes in each client" lists what remains. The
terminal-status rules are a protocol decision and change only by review.

A client of `GET /v1/events/stream` is a process that must hear about mail,
chat and control signals for as long as it runs. This page states one policy
for how such a client connects, reconnects and reports its state. Three
clients implement the stream today, each with its own rules:

- `channel-core/src/api/events.ts` (the Claude Code plugin and the Pi
  extension);
- `cli/go/wake/stream.go` (the `aw wake` broker, one stream per identity; the
  channel-core child it runs for each instance does not open the stream, it
  is fed the broker's events);
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
  closes does not reset it. This is the transient delay; the refused delay
  has its own rule in section 4.
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
- `aw run` and the wake broker also look, before each retry, for the mount of
  the stored server URL that answers as the API (the stored URL itself, or the
  same origin with or without `/api`), and sign the retry for that mount. See
  [Server URL and API mount](configuration.md#server-url-and-api-mount).
- An explicit request for the stream (a registration with the wake broker, a
  new `aw run` session, a restart of the channel) retries at once and, if
  refused again, continues from the 1-minute delay.
- The first successful, confirmed stream ends the quarantine: the client's
  state is no longer `refused` (section 8 says who is told).
- The refused delay returns to 1 minute only after the stream delivers an
  event other than a comment or the opening `connected` event (which the
  server sends before it checks the grant), or a connection that opened
  reaches its planned close. An attempt that reaches its deadline before the
  server answers reconnects at once and leaves the delay where it is. A
  heartbeat or `connected` confirms the stream and ends the
  quarantine but leaves the delay where it is, so a server that accepts the
  open, sends them and then refuses again is retried at a growing interval,
  not once a minute.

`verification_unavailable` is not a refusal. It says the server could not
check the grant; it is transient and follows section 3.

Slow retry is safe only because of two things. Section 5 holds without
exception. And a server must not turn refused retries into a lockout: it may
count them, but a refused stream open never extends, renews or triggers a
block on the identity, the certificate or the address. A client that keeps
knocking at this pace must be able to get in the moment the cause ends.

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

`refused` is reported when a stream enters it and when it leaves it, never
once per retry. Who is told what depends on the client:

- The wake broker's status shows the identity as refused, with the status or
  event name and the time of the next attempt. It never shows a refused
  identity as admitted.
- The channel (the Claude Code plugin and the Pi extension) reports to two
  readers. The operator surface (the plugin's stderr, the Pi status line)
  gets every transition. The model gets exactly one notice per refusal
  episode, at entry, naming the status and the time of the next attempt. It
  arrives as an ordinary channel message and may wake the agent: an agent
  that cannot hear its mail has to know. An episode ends only when the
  server serves: an event other than a comment or the opening `connected`
  event, or the planned close of an open stream. A server that accepts the
  open and refuses again therefore does not produce a notice per cycle. The
  model gets no notice on leaving; the next real event shows the recovery.
- `aw run` logs the same two transitions.

A retry that is refused again changes the time of the next attempt and says
nothing.

## What changes in each client

| | channel-core | wake broker | `aw run` |
|---|---|---|---|
| Backoff ceiling | 5 s becomes 15 s | follows the policy | follows the policy |
| Jitter | added | follows the policy | follows the policy |
| `Retry-After` | honoured | follows the policy | follows the policy |
| Refusals | every 5 s becomes 1 to 15 minutes, reported as refused | follows the policy | follows the policy |
| 408, 409, 429 | unchanged | follows the policy | follows the policy |
| Planned close | jittered | follows the policy | follows the policy |
| Silence | unchanged | follows the policy | follows the policy |

The two Go clients share one implementation of sections 2 to 6. The
TypeScript client has its own and is tested against the same table of cases.

## Decisions recorded at review

1. 401 and 403 are slow-retried, not stopped, on the conditions in section 4.
2. The transient 4xx statuses are 408, 409, 425 and 429. Every other 4xx is a
   refusal.
3. The quarantine delays (1 to 15 minutes) and the `Retry-After` cap
   (5 minutes) are as written.
4. `aw run`'s planned close moves from a local deadline of 10 minutes to
   between 3 minutes 30 seconds and 4 minutes.
