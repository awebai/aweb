---
title: "Terminal wake broker"
kicker: "Design note"
description: "One reconnecting event stream per authorized identity on a host, coalescing wakes and typing them into each instance's original terminal through the OATS input operation."
weight: 59
---

# Terminal wake broker

## 1. What the broker is and is not

The broker is an aweb-owned host daemon. For every identity registered on the
host it holds one bounded, reconnecting `aw events stream` connection,
coalesces the resulting hints per instance, and — when an instance is due a
wake — types a short message into that instance's original terminal through the
OATS input operation, as if the operator had.

**What it types is a fixed instruction to fetch, plus a hint summary.** Not the
message. The broker never fetches, decrypts, or types a sender's content as a
prerequisite for waking anybody: the harness already has `aw` inside the
instance, with native verification, decryption and presentation, and running
that machinery a second time in a daemon buys nothing and costs the instance's
private keys. This is the terminal wake model, and it is the single decision
the rest of the note follows from.

The boundary:

- **aweb owns** the broker: identity and authentication, the event streams,
  reconnect, coalescing, rate limiting, pending state, and the decision that an
  instance is due a wake.
- **OATS owns** instance launch and lifecycle, session receipts, the terminal
  target, and the backend-neutral `oats session inspect|input` contract over
  tmux windows and Herdr terminals (section 5).
- **The instance's own `aw` owns** fetching, decrypting, presenting and
  acknowledging. The broker touches none of it.

It is not a scheduler, a runtime, or a supervisor. It never starts, restarts,
or stops an instance. It is also, for a growing set of instances, the only wake
path there is: OATS now launches Codex natively through a launch adapter with
truthful instructions and no channel, so an instance like that is deaf to
coordination until the broker registers it.

## 2. What the native channel does today

Verified against `aweb-oss/channel-core/src/`, which is the surface the broker
replaces per instance. Read this section as the contract the broker must not
break, not as a design to copy: channel-core fetches, decrypts, presents and
acknowledges because it *is* the presentation surface. The broker is not. Every
mechanism below stays where it is — inside the instance's `aw` — and the
broker's job reduces to telling the instance there is something to fetch.

Events consumed (`channel-core/src/api/events.ts:3`): `connected`,
`mail_message`, `chat_message`, `control_pause`, `control_resume`,
`control_interrupt`, `work_available`, `claim_update`, `claim_removed`,
`app_event`, `error`. Two corrections to the requirement list:

- The wire names for mail and chat are `actionable_mail` and `actionable_chat`
  (`cli/go/awid/events.go:21`); channel-core normalizes them to `mail_message`
  and `chat_message` at `channel-core/src/api/events.ts:265`. Same events, two
  spellings — the broker must accept both.
- `connected` and `error` are informational in the Go bus, which drops both
  (`cli/go/run/eventbus.go:54`), and the bus synthesizes a local
  `channel_reconnected` after an outage (`cli/go/awid/events.go:33`, pushed at
  `cli/go/run/eventbus.go:295`). The broker needs all three.

Delivery intents are assigned per event kind, not negotiated:

| Event | Intent | Source |
| --- | --- | --- |
| mail | `wake` | `channel-core/src/channel.ts:664` |
| chat | `steer` if `sender_waiting`, else `wake` | `channel-core/src/channel.ts:741` |
| control pause/resume/interrupt | `steer` | `channel-core/src/channel.ts:500` |
| work / claim / claim removed | `ambient` | `channel-core/src/channel.ts:512,523,536` |
| app event | the server's `delivery_intent`, default `ambient` | `channel-core/src/channel.ts:572` |

Nothing in channel-core maps an intent onto a runtime state; it has no inspect.
The mapping in section 4 is new broker behaviour, not something preserved.

Presented means read, and the fetch is exact: `GET
/v1/messages/inbox?limit=200&message_id=<id>`
(`channel-core/src/channel.ts:585`), then present, then a durable delivery
mark, then the ack (`:670`); chat batch-marks the session read after presenting
(`:749`). The "never probe the inbox" rule is about the CLI, not the endpoint:
the GET is a pure select and the only `read_at` write on that path is the
separate ack route (`server/src/aweb/routes/messages.py:1904`), while `aw mail
inbox` acknowledges every unread message it displays
(`cli/go/cmd/aw/mail.go:856`). An unfiltered unread scan is wrong for a second
reason — it presents messages no event announced.

Dedupe is `channel:conversation_id:message_id` (`channel.ts:1001`), in memory
and in a durable store (`.aw/channel-delivered-ids.json` per workspace, or
`~/.config/aw/channel-delivered-ids.json` with no workdir, `channel.ts:22`),
24-hour TTL, store-wide 5000-entry cap. The mark is written before the ack and
rolled back if its save fails (`channel.ts:829`), so a failed mark never
becomes an ack.

E2E content is decrypted locally through `aw mail show --message-id <id>
--json` (`channel-core/src/local_aw.ts:67`); on decrypt failure the channel
still wakes, with metadata only (`channel.ts:625`). Two behaviours the
requirement list omits and the broker needs: self-sent messages are skipped
(`channel.ts:609`), and a message whose verification threw is left unread,
unacked, and recorded in an append-only undelivered log (`channel.ts:589`).

## 3. The base: what `cli/go/run` already provides

- `EventBus` (`cli/go/run/eventbus.go:149`) owns the persistent SSE connection,
  classification into an interrupt channel plus a priority queue
  (`eventbus.go:54`), backoff from 250 ms to 2 s (`eventbus.go:249`), permanent
  stop on a 4xx (`eventbus.go:262`), and an in-memory dedupe of the last 256
  message, signal, or event ids (`eventbus.go:185`, `:422`). `wake.go:12`'s
  `EventStreamOpener` makes the stream source injectable and testable without a
  server; `control.go:66` and `loop.go:845` apply control events to a run.
- `loop.go:252` calls `DispatchDecision.AfterDelivery` only after a run
  completes, and `cli/go/cmd/aw/run_dispatch.go:447` is where the mail ack
  fires — ack after evidence of a run, not on presentation. Two details the
  broker must not copy: that resolution scans unread without a message-id
  filter and applies the id client-side (`run_dispatch.go:390`), and it acks
  inline, before any delivery, on the self-sent skips (`:400`, `:418`).
- `awconfig.ResolveWorkspace` (`cli/go/awconfig/selection.go:72`) accepts an
  explicit `IdentityHome` and reads no env when `AllowEnvOverrides` is false —
  what makes many identities in one process possible; `aweb.NewWithCertificate`
  and `aweb.NewWithGrant` (`cli/go/client.go:28`, `:38`) build a client from
  loaded material.

What does not generalise: `Loop` holds one `Provider` (`loop.go:20`) and one
writer into it (`loop.go:95`), dedupe is in-memory and per-process, the stream
TTL is a 10-minute local deadline (`eventbus.go:243`) against a 5-minute server
cap, and backoff has no jitter — fine for one connection, not a hundred.

## 4. Decisions

**Process model: one broker per host, one stream per identity**, agreed on the
OATS side. The ownership split behind it is in the contract itself (section 5);
the per-host shape is the agreement, not something section 5 grants. A single
`aw wake` daemon holds one goroutine, one `aweb.Client`, and one `EventBus` per
registered identity, under a lock directory so a second start is a no-op.
Per-identity processes would multiply reconnect storms, give no single place to
enforce the connection bound or the `AWEB_DELIVERY=session` exclusivity check
(aweb-abik, landed 2026-09-05: the variable exists in channel-core, the Pi
extension and the Claude channel; the broker-side refusal does not yet), and
add N processes for OATS to supervise. Streams are capped at 128, an accepted
configurable initial bound rather than a measured one, matching the archived
draft (`Archive/aweb-wake-draft-2026-09-05/wake-service.mjs`); registrations
beyond it are reported in status, not silently dropped. On a remote host the
broker
runs there, next to the instances, and calls the same host-local `oats session`
commands.

**Authentication is never re-implemented, and credentials stay explicit per
client.** Each identity's client is built in Go from its identity home through
`awconfig.ResolveWorkspace` with `ExternalIdentityHome: true`, reusing or
extracting alongside the private helper at `cli/go/cmd/aw/helpers.go:310`. The
broker needs stream-read authority and nothing else: it never opens a message,
so it never needs decryption material for any identity.

**Pending state lives on disk, per instance, and holds no presented marks.**
`~/.config/aw/wake/` holds `instances.d/<sha256-of-canonical-home>.json`
(pending hints, last attempt, rate-limit state), `registry.d/`, `status.json`,
and `lock/`. The hint store is bounded at 512 per instance and eviction is
reported in status.

There is deliberately **no durable "presented" mark keyed on `submitted:true`,
and no suppression of a future wake for an item that is still unread.** A TTY
write is not evidence of processing. If a prompt is dropped — a harness
restarting, a pane replaced between inspect and input, a paste that lands
somewhere unintended — a mark taken on the strength of that write would strand
real unread work with no path back, because the broker is not the surface that
would notice. So the broker persists what it has *tried*, not what it believes
*arrived*: hints coalesce, retries are rate-limited, and the reconnect
snapshot's unread state drives later reminders until the authoritative unread
state clears.

**At-least-once bounded hints are the honest contract.** Exactly-once
presentation is not available on this transport and the note should not imply
it. A busy instance may be told twice that mail is waiting; it will not be told
zero times because a write silently failed. OATS holds no pending state, no
coalescing and no stream.

**Registration goes through the official `oats.aweb` capability**, with the
home and the identity home both supplied explicitly, and happens only when the
capability's delivery setting is `session`. This monorepo's older
`aweb.identity` grant deployment is one deployment, not the interface: nothing
in the broker may hardwire it, and initial direct identities and Merlin's
authority transfer are not grant homes at all. OATS owns the `delivery:session`
hook glue and the narrow retained-authority binding. The spawn hook records
`AWEB_DELIVERY=session` in the registration alongside the home, the same value
the instance gets in its launch environment; the field is explicit so the
broker's exclusivity check reads it rather than infers it, and a registration
without it is refused. The retire hook deregisters after quiescence. `aw wake
register|deregister|status` are the commands the hooks call.

**Before the first confirmed `present`, tolerate everything.** The hook
registers after the home exists but before the runtime receipt does, so a
pending home does not merely report `present:false` — it reports
`E_RUNTIME_ENDPOINT_UNKNOWN`, a typed error. Until the broker has seen one
confirmed live inspect, every pending state and every error is tolerated and
retried, and nothing is concluded from either. *After* a confirmed live
observation, `stopped` means inactive: the broker closes the stream and marks
the registration inactive, leaving removal to the retire hook.

**Pending registrations expire at 30 minutes.** The bound is operational
visibility, not data safety — it deletes no server messages. Hints are durable
server state, so a home that expires and later comes up is re-raised by the
reconnect snapshot's unread set; nothing is lost by dropping a stalled
registration, and a launch that never completed should not sit in `aw wake
status` indefinitely pretending to be a wake path. Expiry writes one log line
naming the home and the elapsed time.

**`aw run` is not refactored.** Earlier drafts moved stream ownership, dedupe
and coalescing into a shared package that both would consume; that is a
prerequisite the broker does not need and a way to break a working command for
a design idea. Reuse or extract only the narrow Go pieces the broker actually
needs, and keep `aw run` green. Working self-use over complexity.

**Coalescing and rate limiting, not dedupe.** With no presented marks there is
nothing to deduplicate against durably. Within a coalescing window the broker
collapses hints per instance — keyed on `kind` plus `message_id`, `signal_id`,
`event_id` or `session_id` — so a burst becomes one message; across windows, a
still-unread item may legitimately produce another reminder, rate-limited per
instance. One submission is in flight at a time, and a batch is ordered
interrupt, communication, coordination.

**Intent to inspect state, as implemented.** Herdr reports `idle`, `done`,
`working`, `blocked` or `unknown`; `generic shell`, `stopped` and
`not-launched` also occur. The broker maps `done` to idle and `working` to
busy, and treats any string it does not recognise as `unknown`, so a vocabulary
extension degrades to the conservative path rather than to a crash.

| Intent | idle / done | working | blocked | unknown | stopped / not-launched |
| --- | --- | --- | --- | --- | --- |
| `wake` | type now | defer | defer | coalesce, rate-limited | inactive after first confirmed live |
| `steer` | type now | defer | defer | coalesce, rate-limited | inactive after first confirmed live |
| `ambient` | type now | defer, coalesce | defer, coalesce | coalesce, rate-limited | inactive after first confirmed live |

**`unknown` gets a coalescing and rate-limit policy, not a delay.** tmux always
says `unknown` and carries no readiness promise, and no amount of waiting turns
that into one — an initial fixed delay would only make the instance feel deaf
without making the write safer. So the broker sends, and bounds how often it
sends. Typing while the harness is running may simply enqueue as a user
message, which is the behaviour that makes this acceptable; there is no
readiness framework here and the note should not invent one. Retry policy lives
in the broker, nowhere else.

A **known** `blocked` defers an ordinary wake — that is a real signal and worth
honouring. Deferred hints are re-evaluated on each inspect poll (two seconds)
with an unbounded wait; an instance that never leaves `working` fills its hint
store and reports the backlog and every eviction in status.

**What the broker types.** One short message, in two parts: the fixed
instruction — check pending mail and chat with `aw` from inside this instance,
and handle what is there — and a hint summary saying how many items of what
kind are waiting, with senders and ids where the event carried them. Metadata
and counts only. No subjects for encrypted mail, no bodies ever, and nothing
that requires the broker to have opened a message. The instance's own `aw`
verifies, decrypts, presents and acknowledges; the broker's text exists to make
it run.

**No broker acknowledgement, ever.** `submitted:true` means bytes reached the
terminal, and nothing in this design converts that into a read. The ack belongs
to the harness: the instance's own `aw mail reply` best-effort acks its source,
or `aw mail ack` does it explicitly (`docs/receiving-events.md`). No Herdr
state transition supplies a consumption ack either — `working` after a
submission means the agent is doing something, not that it did *this*.

The consequence is the honest one: an item the instance ignores stays unread,
the reconnect snapshot keeps surfacing it, and the broker keeps producing
rate-limited reminders until the authoritative unread state clears. The
identity's `unread_count` (`cli/go/awid/events.go:55`) is reported in
`status.json` so a backlog is visible rather than silent.

**E2E is not in the first broker's path at all.** Because the broker sends
hints rather than content, there is nothing for it to decrypt: no `aw mail
show` exec, no key material, no `AWEB_IDENTITY_HOME` handling for decryption
purposes, and no granted-identity decryption problem to solve. The instance's
`aw` decrypts under whatever identity it was launched with. Grant TTLs and E2E
key custody remain real questions, but they are deployment-specific and belong
to the deployment, not to this daemon.

**Controls.** Pause and resume are durable broker state, held per instance and
applied to whether the broker types at all — that part is authoritative and
survives restarts. Transient interrupts are best-effort. There is no
authoritative GET for control state and the broker does not need one as a
prerequisite: a control signal consumed during an SSE gap is lost, which is
existing aweb protocol behaviour (`docs/receiving-events.md` calls control
signals at-most-once), and the note states it plainly rather than designing
around it. If a real interrupt is wanted, lead adds a neutral `oats session
interrupt` that sends Ctrl-C to the original terminal; the logical pause and
resume policy stays in aweb. **Queued text is never called an interrupt.**

**Reconnect bounds.** The broker reconnects at four minutes, adopting
channel-core's planned-close margin (`channel-core/src/api/events.ts:49`)
inside the server's five-minute cap (`docs/receiving-events.md`,
`channel-core/src/api/events.ts:48`), rather than the Go bus's 10-minute local
deadline — so the close is always the broker's, never a server EOF it has to
classify. Backoff is 1 s doubling to 15 s with jitter, per identity: jitter is
required at a hundred connections and neither existing implementation has it,
and a ceiling above 15 s would spend a visible fraction of every five-minute
cycle deaf. A 4xx quarantines one identity and reports it; it never stops the
daemon. There is no resumable cursor and the broker must not invent one — the
reconnect snapshot is both the recovery mechanism and the reminder mechanism,
which is exactly why nothing durable may suppress what it re-raises.

## 5. Interface to the OATS input/inspect operation

The contract, as delivered by lead. Two host-local commands:

```
oats session inspect --home /absolute/instance/home --json
oats session input   --home /absolute/instance/home [--text-file /path] --json
```

`input` reads the text from stdin when `--text-file` is omitted; either way the
content never reaches a shell as an argument. Envelopes follow the OATS
convention: `{schemaVersion:1, ok:true, result:{home, backend, present, state,
...}}` on success, with `result.submitted:true` for `input`, and
`{schemaVersion:1, ok:false, error:{code, message}}` with a non-zero exit on
failure.

What the broker reads out of it:

- **`submitted:true` is delivery, not consumption** — the bytes reached the
  target, nothing more. That is why the ack point is not here (section 4).
- **`state` is what the backend actually reports.** Herdr: `idle`, `done`,
  `working`, `blocked`, `unknown`. Also occurring: `generic shell`, `stopped`,
  `not-launched`. tmux always says `unknown` and promises no readiness. The
  caller owns the `unknown` policy; the broker's is coalescing plus a rate
  limit (section 4), not a delay.
- **A pending home reports `E_RUNTIME_ENDPOINT_UNKNOWN`, not `present:false`.**
  The hook registers after the home exists and before the runtime receipt does,
  so the absence of a receipt is a typed error rather than an absent target.
  Only after one confirmed live inspect does `stopped` mean inactive; removing
  the registration stays with the retire hook (section 4).
- **`input` validates the lifecycle receipt before typing**, refusing a missing
  or replaced target (new Herdr terminal id, different tmux window identity)
  and a fallback shell left by an exited harness. The broker never has to prove
  target identity itself, and a refusal is authoritative.
- **The mechanism is backend-specific and the broker does not care**: tmux uses
  bracketed paste plus Enter, Herdr uses the pane run.
- **Host-local only.** OATS carries no SSE, idle detection, coalescing, pending
  state, or instance credentials — the ownership split in section 1.
- **Not in the contract, and not needed yet:** an interrupt. If one becomes
  necessary, lead adds a neutral `oats session interrupt` that sends Ctrl-C to
  the original terminal. Until then the broker has no way to interrupt anything
  and must not describe queued text as if it did.

## 6. Failure modes, and what the broker must never do

- **Never fetch, decrypt, or type a sender's content.** The instruction to
  fetch is the payload. This is also what keeps `aw mail inbox` out of the
  broker: the CLI acknowledges what it displays (`cli/go/cmd/aw/mail.go:856`),
  and inside the instance that is correct, while in the daemon it would mark
  messages read that no agent ever saw.
- **Never treat `submitted:true` as consumption**, and never let it suppress a
  later wake for an item that is still unread. A TTY write is not processing
  evidence.
- **Never acknowledge anything**, on any path, for any reason.
- **Never run beside a live native channel for the same instance.**
  Registration requires `AWEB_DELIVERY=session`, recorded as an explicit field
  by the spawn hook. The variable exists since aweb-abik landed
  (`selectDeliveryMode` in channel-core, honoured by the Pi extension and the
  Claude channel); what does not exist yet is the broker-side check. A
  registration without the field is refused with the conflict named, and the
  check reads the field rather than inferring the mode. Two presentation
  surfaces on one identity double every wake.
- **Never call queued text an interrupt**, in the code, the logs, or the text
  typed into the terminal.
- **Never type into a known `working` or `blocked` instance**, and never write
  message content into broker state, logs, or status.
- **Never submit before the first confirmed live inspect.** A pending home's
  `E_RUNTIME_ENDPOINT_UNKNOWN` is not an invitation to try anyway.
- **Never promise exactly-once.** Duplicate reminders are the designed
  behaviour; a missed wake is the failure.
- Stream deaf for one identity: reported in `status.json` and retried; on
  recovery the snapshot supplies what was missed and the synthesized
  `channel_reconnected` produces one catch-up hint, not one per message.
- Broker crash: instances keep running, wakes stop, nothing was acknowledged
  anyway; restart re-reads registrations and pending hints, and the reconnect
  snapshot re-raises anything still unread. This is the case the no-marks rule
  protects.
- `oats session input` refuses a replaced target: nothing was typed, the hint
  stays pending, and the registration is reconciled on the next inspect.
- OATS unreachable (a typed error): retry with backoff and report. An
  unanswerable backend is never treated as an absent instance, because that
  would mark a live agent inactive and stop its wakes.

## 7. Implementation plan

Go, in aweb-oss. Narrow additions; no restructuring of anything that works
today.

- `cli/go/wake/` — the broker: per-identity streams, the hint coalescer, the
  rate limiter, the state policy, and the message composer. Reuses
  `cli/go/run/eventbus.go` where it can be used as-is and copies the small
  parts it cannot; `aw run` is not touched and stays green.
- `cli/go/wake/session/` — the `oats session inspect|input` adapter: envelope
  parsing, the state mapping, the typed-error handling including
  `E_RUNTIME_ENDPOINT_UNKNOWN`, and a fake for tests. The only package that
  knows OATS exists.
- `cli/go/cmd/aw/wake.go` — `aw wake run|status|register|deregister`.
- A per-identity-home client constructor, reused from or extracted alongside
  `cli/go/cmd/aw/helpers.go:310`, whichever keeps the existing callers intact.

**What it types**, fixed instruction plus hint summary, e.g.:

```
aweb: 2 items waiting. Check them from this instance with `aw mail inbox`
and `aw chat pending`, then handle what is there.
  mail from alice (2 unread)
  chat from bob — sender waiting
```

**What it persists**, per instance: pending hints (bounded at 512), last
attempt, rate-limit state, and whether the instance is paused. No presented
marks, no message content.

Unit tests, all against a fake `oats session`, no network:

- composition: the typed text carries the fetch instruction and counts only — a
  test asserts no subject or body from a hint ever reaches the composed
  message.
- coalescing and rate limiting: a burst becomes one submission; a still-unread
  item produces a later reminder no sooner than the rate limit; the hint cap
  holds and eviction is reported.
- state mapping: `done` maps to idle, `working` to busy, an unrecognised string
  to `unknown`; `working` and `blocked` never produce an `input` call;
  `unknown` submits under the rate limit with no initial delay.
- registration: nothing is submitted before the first confirmed live inspect;
  `E_RUNTIME_ENDPOINT_UNKNOWN` and other errors are tolerated until expiry; a
  registration still pending at 30 minutes is dropped with one log line; a
  registration without `AWEB_DELIVERY=session` is refused; after a confirmed
  live observation `stopped` marks it inactive without removing it.
- no acknowledgement: no ack on any path; a restart with pending hints
  re-raises from the reconnect snapshot rather than suppressing.
- controls: pause survives a restart and suppresses typing; resume restores it;
  a transient interrupt lost across a stream gap is reported, not retried.
- reconnect: 4xx quarantines one identity and leaves others streaming; the
  planned close is not reported as an outage.

Scripted end-to-end on one machine, native channel disabled throughout, with
instances in `AWEB_DELIVERY=session` mode across all three runtimes — Claude
Code and Codex (both tmux, `unknown`, the same generic terminal mechanism) and
Pi. Mail each one and assert a single wake in the correct terminal, that the
broker marked nothing read, and that the instance's own `aw` fetched and
cleared it. Then the three qualification cases: **GUI close** — close the
terminal GUI and assert the broker reports the instance inactive only after a
confirmed live observation preceded it, never from a pending error; **broker
restart while the agents stay alive** — kill and restart the daemon mid-cycle
and assert the agents keep running, no wake is lost, and unread items are
re-raised from the snapshot rather than suppressed; and **pending
registration** — register a home before its runtime receipt exists, mail it,
and assert nothing is typed until the first confirmed live inspect.

## 8. Resolved with lead, 2026-09-05

Lead's design review. Where it differs from the oats answers below, it
supersedes them and oats concurs. Folded into sections 1 to 7 as decisions;
kept here so a reader can see what was settled rather than infer it.

- **Delivery is metadata and hints plus a fixed instruction to fetch** with
  `aw` inside the instance — Juan's terminal wake model. The broker does not
  fetch, decrypt or type sender messages as a prerequisite; the harness already
  has native `aw` verification, decryption and presentation. This also removes
  granted-identity decryption from the first broker's path entirely.
- **No presented marks and no suppression of future wakes.** A TTY write is not
  processing evidence, and a dropped prompt would strand unread work. Persist
  pending hints and last attempt, coalesce and rate-limit retries, and let the
  reconnect snapshot drive reminders until authoritative unread state clears.
  At-least-once bounded hints is the contract; exactly-once presentation is not
  available on this transport. No broker ACK, ever.
- **Inspect vocabulary as implemented:** Herdr `idle`, `done`, `working`,
  `blocked`, `unknown`; `generic shell`, `stopped` and `not-launched` also
  occur. `done` maps to idle, `working` to busy. tmux `unknown` carries no
  readiness promise, so the policy is short coalescing plus a rate limit, not
  an initial delay; typing while running may enqueue as a user message, and
  there is no readiness framework. A known `blocked` defers an ordinary wake.
  Retry policy lives in the broker.
- **Pending registrations see `E_RUNTIME_ENDPOINT_UNKNOWN`**, not necessarily
  `present:false`, because the hook registers after home creation and before
  the runtime receipt. Tolerate pending states and errors until expiry; after a
  confirmed live observation, `stopped` means inactive. The 30-minute expiry
  stands as a visible operational bound — it deletes no server messages, and
  hints survive as durable server state that the reconnect snapshot re-raises.
- **Registration works through the official `oats.aweb` capability** with home
  and identity home supplied explicitly. Do not hardwire the monorepo's older
  `aweb.identity` grant deployment. OATS owns the `delivery:session` hook glue
  and the narrow retained-authority binding. Grant TTL and E2E questions are
  deployment-specific: initial direct identities and Merlin's authority
  transfer are not 8-hour grant homes.
- **Controls:** persistent broker pause state and best-effort transient
  interrupt semantics, with no authoritative GET control endpoint as a
  prerequisite. Control lost across an SSE gap is existing aweb protocol
  behaviour, stated honestly. A real interrupt would be a neutral `oats session
  interrupt` (Ctrl-C to the original terminal) added by lead; logical pause and
  resume stays in aweb. Never call queued text an interrupt.
- **No wholesale `aw run` refactor as a prerequisite.** Extract or reuse the
  narrow Go pieces the broker needs and keep `aw run` green. Working self-use
  over complexity.

Also settled: 128 streams is an acceptable configurable initial bound; one
broker per host; `AWEB_DELIVERY=session` from the hook; explicit credentials
per client. Qualification adds Codex, GUI close, and broker restart while
agents remain alive (section 7).

## 9. Resolved with oats, 2026-09-05

Superseded in two places by section 8 — the 45-second quiet period and the
24-hour pending expiry are withdrawn — and recorded because the rest stands.

- **Registration and the exclusivity field.** Registration happens only from
  the `oats.aweb` hooks and only when the capability's delivery setting is
  `session`. The spawn hook records `AWEB_DELIVERY=session` in the registration
  alongside the home, the same value the instance gets in its launch
  environment. Explicit, so the broker's check reads it instead of inferring
  it; a registration without it is refused.
- **Hints for a pending home are kept, coalesced and delivered once the
  instance is present** rather than dropped with the registration.
- ~~Pending expiry of 24 hours~~ — withdrawn; 30 minutes stands (section 8).
- ~~A 45-second quiet period before the first submission on tmux~~ — withdrawn;
  coalescing and a rate limit replace it (section 8). What survives is the
  observation behind it: input arriving mid-turn is queued by the harness
  rather than lost, which is what makes sending without a readiness signal
  acceptable.
- **Two behaviours, not three, is the accepted scope.** OATS has no interrupt
  primitive and none is planned.

## 10. Status

Settled. Lead reviews the corrected note without another approval gate, and
implementation proceeds on the agreed design. The three questions this note
carried for lead are answered above: the ack belongs to the harness and no
Herdr transition supplies a consumption ack; the control gap is stated honestly
rather than blocked on a new endpoint; and grant-home E2E custody is
deployment-specific and not a blocker for the first broker.
