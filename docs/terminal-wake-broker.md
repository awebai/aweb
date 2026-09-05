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
wake — fetches the durable item by exact id and hands the text to the OATS
input operation, which types it into that instance's original terminal target
as if the operator had. It is the wake loop `aw run` already runs, generalised
from one identity to many and from a provider process aweb launched to a
terminal aweb does not own.

The boundary:

- **aweb owns** the broker: identity and authentication, the event streams,
  reconnect, dedupe, coalescing, pending state, and the decision that an
  instance is due a wake.
- **OATS owns** instance launch and lifecycle, session receipts, the terminal
  target, and the backend-neutral `oats session inspect|input` contract over
  tmux windows and Herdr terminals (section 5).

It is not a scheduler, a runtime, or a supervisor. It never starts, restarts,
or stops an instance. It is also, for a growing set of instances, the only wake
path there is: OATS now launches Codex natively through a launch adapter with
truthful instructions and no channel, so an instance like that is deaf to
coordination until the broker registers it.

## 2. What the native channel does today

Verified against `aweb-oss/channel-core/src/`, which is the surface the broker
replaces per instance.

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
add N processes for OATS to supervise. Connections are capped at 128 — chosen,
not measured, matching the archived draft
(`Archive/aweb-wake-draft-2026-09-05/wake-service.mjs`); registrations beyond
it are reported in status, not silently dropped. On a remote host the broker
runs there, next to the instances, and calls the same host-local `oats session`
commands.

**Authentication is never re-implemented.** Each identity's client is built in
Go from its identity home through `awconfig.ResolveWorkspace` with
`ExternalIdentityHome: true`; the one new export is a small constructor turning
an identity home into a configured client, extracted from the private helper at
`cli/go/cmd/aw/helpers.go:310`. Decryption needs no second extraction, because
the broker does not decrypt in-process (see the E2E policy below).

**Pending state lives on disk, per instance, and only in the broker.**
`~/.config/aw/wake/` holds `instances.d/<sha256-of-canonical-home>.json`
(pending hints, presented marks, last attempt), `registry.d/`, `status.json`,
and `lock/`. Two separate bounded stores, and they must not be confused: the
**presented-mark store** (30 days, 5000 marks per instance — longer and
per-instance rather than channel-core's 24 hours and store-wide, because an
unacked item here is re-announced indefinitely and the mark is the only thing
suppressing it) and the **pending-hint store** (512 hints per instance). The
eviction consequences differ: evicting a mark causes a re-presentation,
evicting a hint loses a wake, so hint eviction is reported in status and mark
eviction is not. Whichever bound binds first wins — an instance taking more
than 5000 items in 30 days will re-present the oldest. In-memory state alone is
wrong: a broker restart is an ordinary event and must not re-present messages
already typed into a terminal. OATS holds no pending state, no coalescing and
no stream; that division is part of the agreed contract.

**Registration is capability-owned, through the `oats.aweb` hooks**, with no
aweb-specific kernel phase, and happens only when the capability's delivery
setting is `session`. The spawn hook runs *before* the runtime is allocated, so
it registers the canonical home in a **pending** state together with the
identity home and an explicit `AWEB_DELIVERY=session` field — the same value
the instance gets in its launch environment. Explicit, so the broker's
exclusivity check reads the field rather than inferring it; a registration
without it is refused. The broker opens that identity's stream immediately but
polls `oats session inspect` and makes no submission until `present:true`. The
retire hook runs after quiescence and deregisters, so a spawn that never
launched and was then retired does not linger. `aw wake
register|deregister|status` are the commands the hooks call; neither side needs
the other running.

**Reconciliation reads `present:false` narrowly.** A pending home necessarily
reports `present:false`, so that alone must not deactivate anything. On
`present:false` *with state `stopped`* — section 5's "the target is missing" —
the broker marks the registration inactive and closes its stream. Inactive is
not removed: removal stays with the retire hook, and `aw wake status` keeps
showing a stopped home until it runs.

**A pending home is patient, then dropped.** A registration stays pending for
24 hours before the broker drops it with one log line naming the home and the
elapsed time. The generous bound is deliberate: a first launch can sit at a
folder-trust or channel prompt for as long as the operator is away, and a wake
lost to a 30-minute timer would be lost for exactly the reason the broker
exists. Hints for a pending home are not dropped with it — they accumulate and
coalesce inside the ordinary 512-hint store and are delivered as one batch when
inspect first reports `present:true`. Hints expire only under the 30-day mark
rule.

**`aw run`'s behaviour does not change**, though its internals do. It remains
the compatibility launcher aweb *starts* — `docs/aw-run.md` is explicit that
aweb does not own the launched runtime, process lifecycle, or session UX, and
the broker does not change that either. The refactor is extraction: stream
ownership, dedupe, and coalescing move into a reusable `cli/go/wake` package
that both `aw run` and the broker consume. A user who wants aweb to start the
process still runs `aw run`; a user whose terminal is owned by OATS gets the
broker. Neither runs beside the native channel for the same instance.

**Dedupe and coalescing.** The dedupe key is `kind:conversation_id:message_id`,
a compatible superset of `channel.ts:1001` rather than a match — channel-core's
first component is a closed `mail | chat | app`, the broker's `kind` must also
span control, work and claim — held in the durable per-instance store. Control
signals key on `signal_id` and app events on `event_id`; work and claim events
have no stable replay key and are deduped only within a coalescing window,
never durably, because dropping them risks hiding a real coordination change
(`cli/go/run/eventbus.go:422` records the same reasoning). Coalescing is per
instance: one submission in flight at a time, hints accumulate while an
instance is not idle, and the next submission presents them as one batch
ordered interrupt, communication, coordination.

**Intent to inspect state, including `unknown`.** `inspect` normalises the
backend state to exactly `idle | busy | blocked | unknown | stopped`: Herdr
supplies the first three, tmux always says `unknown`, and `present:false` says
`stopped`. Any other string the broker treats as `unknown`, so a vocabulary
extension degrades to the conservative path rather than to a crash. Lead still
pins the vocabulary. The `unknown` policy is the broker's, and this is it:

| Intent | idle | busy | blocked | unknown | `stopped` |
| --- | --- | --- | --- | --- | --- |
| `wake` | present now | defer | defer | present after quiet period | close stream |
| `steer` | present now | defer | defer | present after quiet period | close stream |
| `ambient` | present now | defer, coalesce | defer, coalesce | present after quiet period | close stream |

The quiet period (default 45 s, configurable) runs from the broker's own last
submission to that target — the only thing it knows about a tmux window. It is
a rate limit, not an idle detector, and this note should not pretend otherwise:
on tmux the broker can type into a running turn and occasionally will. What
that costs is bounded, and this is why 45 s is safe to ship unmeasured — Claude
Code queues input arriving mid-turn and processes it after the turn, so a
too-short period costs a queued message, not a lost one. Bracketed paste plus
Enter is what makes it a queued prompt rather than scrambled input. On Herdr
the state is known and the period never applies. Revisit the default against
measured turn lengths; the setting exists so nobody has to wait for that.

Where the state is known, the broker never types into busy or blocked. That
makes the mapping two behaviours, not three — wake when idle, inform otherwise
— and that is the accepted scope: OATS has no interrupt primitive and none is
planned, so `steer` differs from `wake` only in ordering and text template. An
operator-visible interrupt would be a separate, explicitly requested feature,
not something the broker improvises by typing into a live turn. Deferred hints
are re-evaluated on each inspect poll (two seconds, chosen) with an unbounded
wait; an instance that never goes idle fills its pending-hint store and reports
the backlog and every eviction in status.

**Presentation, and the acknowledgement the broker does not make.** For each
new mail hint the broker fetches by exact id (`awid.InboxParams{MessageID:
...}`, `cli/go/awid/mail.go:609`), skips self-sent messages, composes the text,
calls `oats session input`, and on `submitted:true` writes the durable
presented mark. Chat is the same shape against the session: fetch the exact
message through `aw chat history --session-id <id> --message-id <id>`, which
does not mark anything read (`cli/go/cmd/aw/chat.go:307`), and present it with
`sender_waiting` carried into the text. A message the broker declines to
present — verification threw, as at `channel-core/src/channel.ts:589` — is
written to an append-only undelivered log and left untouched on the server,
because a message dropped before presentation otherwise leaves no trace
anywhere.

Then it stops. `submitted:true` means the bytes reached the terminal, not that
the harness read them, so **the broker does not acknowledge mail or chat at
all.** The ack point stays with the harness: the instance's own `aw mail reply`
(best-effort acks its source) or an explicit `aw mail ack`
(`docs/receiving-events.md`).

Two rules stated sections apart combine here, so state the combination: every
presented item stays unread, reappears in every reconnect snapshot for as long
as the instance ignores it, and is suppressed each time by the durable mark. An
ignored message is presented exactly once and then absorbed for the 30-day mark
retention, while the identity's unread backlog grows. That backlog is the
operator's signal, so the broker reports each identity's `unread_count`
(`cli/go/awid/events.go:55`) in `status.json`. The trade against channel-core's
"presented equals read" (`channel-core/src/channel.ts:667-670`) is deliberate:
the unread list no longer clears itself, and no message is ever marked read
because bytes were written to a terminal.

**E2E policy: decrypt by exec, never in-process.** The broker runs `aw mail
show --message-id <id> --json` with `AWEB_IDENTITY_HOME` set to that instance's
identity home — the variable the OATS spawn hook already contributes
(`oats/docs/oats-aweb-seam.md`) — which is channel-core's path
(`channel-core/src/local_aw.ts:67`). Decrypting in-process would need the
key-load path at `cli/go/cmd/aw/mail.go:790-794` lifted out of `package main`
and would collect every instance's private key material in one long-lived
daemon. When the exec fails or returns no plaintext, the broker presents
metadata only and lets the harness fetch, as channel-core does
(`channel-core/src/channel.ts:625`). Plaintext reaches the instance's own
terminal and nowhere else; pending state holds ids and kinds, never bodies.

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
reconnect snapshot is the recovery mechanism, and durable dedupe is what makes
a repeated snapshot harmless.

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
- **`state` is normalised to `idle | busy | blocked | unknown | stopped`** and
  is truthful about what the backend knows: Herdr supplies the first three,
  tmux always says `unknown` because it cannot promise harness readiness, and
  `present:false` says `stopped`. The caller owns the `unknown` policy; the
  broker's is the quiet period in section 4.
- **`present:false` with state `stopped` means the target is missing**, while
  an inaccessible backend is a typed error. The broker separates "this instance
  is gone" from "OATS could not answer", and only the first marks the
  registration inactive; removing it stays with the retire hook (section 4).
- **`input` validates the lifecycle receipt before typing**, refusing a missing
  or replaced target (new Herdr terminal id, different tmux window identity)
  and a fallback shell left by an exited harness. The broker never has to prove
  target identity itself, and a refusal is authoritative.
- **The mechanism is backend-specific and the broker does not care**: tmux uses
  bracketed paste plus Enter, Herdr uses the pane run.
- **Host-local only.** OATS carries no SSE, idle detection, coalescing, pending
  state, or instance credentials — the ownership split in section 1.

## 6. Failure modes, and what the broker must never do

- **Never run `aw mail inbox`**, and never fetch unread without a message-id
  filter. The CLI acknowledges what it displays (`cli/go/cmd/aw/mail.go:856`),
  marking messages read that no instance ever saw.
- **Never treat `submitted:true` as consumption.** It is the strongest signal
  the interface offers and it is still only delivery.
- **Never run beside a live native channel for the same instance.**
  Registration requires `AWEB_DELIVERY=session`, recorded as an explicit field
  by the spawn hook. The variable exists since aweb-abik landed
  (`selectDeliveryMode` in channel-core, honoured by the Pi extension and the
  Claude channel); what does not exist yet is the broker-side check. A
  registration without the field is refused with the conflict named, and the
  check reads the field rather than inferring the mode. Two presentation
  surfaces on one identity double every wake.
- **Never present the same message twice** within the mark-retention window,
  across reconnects or restarts. Past 30 days the mark is gone and a
  still-unread item can be presented again; that is the bound, not an
  exception.
- **Never type into a known-busy or known-blocked instance**, and never write
  plaintext into broker state, logs, or status.
- **Never submit to a home that is not yet `present`.** The spawn hook
  registers before the runtime exists; typing then lands in whatever the
  terminal is at that moment.
- Stream deaf for one identity: reported in `status.json` and retried; on
  recovery the snapshot supplies what was missed and the synthesized
  `channel_reconnected` produces one catch-up presentation, not one per
  message.
- Broker crash: instances keep running, wakes stop, nothing was acknowledged
  anyway; restart re-reads registrations and durable marks.
- `oats session input` refuses a replaced target: nothing was presented, no
  mark is written, the item stays unread, and the registration is reconciled on
  the next inspect.
- OATS unreachable (a typed error, not `present:false`): retry with backoff and
  report. An unanswerable backend is never treated as an absent instance,
  because that would mark a live agent inactive and stop its wakes.

## 7. Implementation plan

Go, in aweb-oss.

- `cli/go/wake/` — the reusable core: per-identity stream ownership
  (generalised from `cli/go/run/eventbus.go`), durable delivery store,
  coalescer, dedupe, intent/state policy. No terminal knowledge.
- `cli/go/wake/session/` — the `oats session inspect|input` adapter: envelope
  parsing, the typed-error/`present:false` split, and a fake for tests. The
  only package that knows OATS exists.
- `cli/go/cmd/aw/wake.go` — `aw wake run|status|register|deregister`.
- Client construction extracted from `cli/go/cmd/aw/helpers.go:310` into an
  exported per-identity-home constructor.

Unit tests, all against a fake `oats session`, no network:

- coalescing: hints arriving while busy collapse into one submission at idle;
  ordering is interrupt, communication, coordination; the per-instance cap
  holds.
- dedupe: the same `message_id` across a reconnect and across a process restart
  presents once; work and claim events are not durably deduped.
- deferral: `busy` and `blocked` never produce an `input` call; a transition to
  idle flushes; `unknown` submits only after the quiet period and then respects
  it again.
- registration: a pending home is polled and never submitted to before
  `present:true`, and hints accumulated while it was pending are delivered as
  one batch when it becomes present; a registration still pending at 24 hours
  is dropped with one log line; a registration without `AWEB_DELIVERY=session`
  is refused; `present:false` with `stopped` marks the registration inactive
  without removing it, while a typed error does neither.
- acknowledgement: no ack is ever sent, on any path; a failed durable mark is
  retried rather than skipped; a refused `input` leaves no mark.
- reconnect: 4xx quarantines one identity and leaves others streaming; the
  five-minute close is not reported as an outage.

Scripted end-to-end on one machine: two instances in `AWEB_DELIVERY=session`
mode, one Claude Code (tmux, `state: "unknown"`) and one Pi, each with its own
identity home, native channel disabled for both. Send mail to each and assert
one presentation in the correct terminal, that the broker marked nothing read,
and that the instance's own reply clears it; send during the quiet period and
assert the deferral then the flush; kill the broker mid-cycle and assert no
duplicate on restart; register a home before its runtime exists, mail it while
it is still pending, and assert the first submission waits for `present:true`
and then carries the hint that arrived before it; finish with an E2E message,
proving decryption under the instance's own identity home and metadata-only
delivery when the key is unreadable.

## 8. Resolved with oats, 2026-09-05

These were open questions in the first draft. The answers are folded into
sections 4 to 7 as decisions; they are recorded here so a reader can see what
was settled and by whom rather than inferring it.

- **Registration and the exclusivity field.** Registration happens only from
  the `oats.aweb` hooks and only when the capability's delivery setting is
  `session`. The spawn hook records `AWEB_DELIVERY=session` in the registration
  alongside the home, the same value the instance gets in its launch
  environment. The field is explicit so the broker's check reads it instead of
  inferring it, and a registration without it is refused.
- **Pending expiry: 24 hours, not 30 minutes.** A first launch can sit at a
  folder-trust or channel prompt while the operator is away. Hints for a
  pending home are kept and coalesced inside the existing 512 cap and delivered
  once when inspect first reports present; they expire only under the 30-day
  rule. The retire hook deregisters, so a spawn that never launched and was
  retired never lingers.
- **The state vocabulary.** `inspect` normalises to exactly `idle | busy |
  blocked | unknown | stopped` — Herdr supplies the first three, tmux always
  says `unknown`, `present:false` says `stopped` — and any other string is
  treated as `unknown`. Lead still pins the vocabulary.
- **The quiet period stays 45 s, configurable.** On tmux, input sent during a
  running Claude Code turn is queued by the harness and processed after it, so
  too short costs a queued message rather than a lost one; on Herdr the state
  is known and the period does not apply. Revisit against measured turn
  lengths.
- **Two behaviours, not three, is the accepted scope.** OATS has no interrupt
  primitive and none is planned. Wake when idle, inform otherwise; an
  operator-visible interrupt would be a separate, explicitly requested feature.

## 9. Open questions for lead

1. The broker acknowledges nothing, because `submitted:true` is not consumption
   and no other evidence exists, so unread items sit on the server until the
   instance handles them. Confirm that is the intended end state, or name the
   signal that closes the loop — a Herdr state transition is the only
   candidate, and it exists on one backend of two.
2. This is a knowing deviation, not an open choice. `docs/receiving-events.md`
   instructs consumers to "re-fetch authoritative state after reconnect rather
   than depending on control-frame replay"; the broker cannot, because the only
   control surface is `POST /agents/{alias}/control`
   (`server/src/aweb/routes/agents.py:1003`) and there is no GET. So the broker
   presents control signals when seen and loses any consumed before a dropped
   frame. Accept the gap, or the endpoint has to exist first.
3. **Does a grant home carry E2E decryption material at all?**
   `oats/docs/oats-aweb-seam.md` says the worker's grant home "contains only
   `grant.yaml` and the session key", while the decrypt path resolves an
   assertion plus an X25519 private key inside the identity home
   (`cli/go/cmd/aw/mail.go:790-794`). If it does not, every E2E message to a
   granted instance silently takes the metadata-only path, which the broker
   would report as normal. The 8-hour grant TTL against a long-lived broker is
   the same question a second time.
