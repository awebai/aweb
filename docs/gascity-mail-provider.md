# Gas City mail provider: design record

Status: **decided design record** for `aw gc-mail`, the aweb-backed Gas City
exec mail provider (`GC_MAIL=exec:aw-gc-mail`). It is the sibling of
[the beads mail delegate record](beads-mail-delegate.md) and reuses that
record's decisions wherever the Gas City contract allows; where it diverges,
the divergence is stated here with its reason. If implementation shows a
decision here is wrong, the fix goes through this record first, not into a
quiet divergence.

Authority: the beads-ecosystem plan §5
(`bookshelf/strategy/2026-08-22-beadhub-revival-and-federation-plan.md`),
plus the beads-mail record for everything the two providers share.

Verified sources, pinned 2026-09-02:

- `gastownhall/gascity` @ **`c96e54a3ab890ca984755b7fc5b5290cba5122d5`**
  (main, 2026-09-02). Read as source, not summary:
  `internal/mail/exec/exec.go`, `internal/mail/exec/json.go`,
  `internal/mail/mail.go`, `internal/mail/resolve.go`,
  `cmd/gc/providers.go`, `cmd/gc/cmd_mail.go`,
  `internal/session/mailbox_address.go`,
  `contrib/mail-scripts/README.md`,
  `contrib/mail-scripts/gc-mail-mcp-agent-mail`,
  `internal/mail/exec/exec_test.go`,
  `internal/mail/exec/conformance_test.go`,
  `internal/mail/exec/mcp_conformance_test.go`,
  `internal/mail/mailtest/conformance.go`,
  `internal/bootstrap/packs/core/skills/gc-mail/SKILL.md`.
- Latest Gas City release: **v1.4.1, 2026-08-15**. `internal/mail/exec/exec.go`,
  `internal/mail/exec/json.go` and `internal/mail/mail.go` are **byte-identical
  between v1.4.1 and the pinned main** — verified by diff, not assumed. The
  compatibility floor is therefore the shipped release, not an unreleased main.
- aweb-oss @ current main — all `file:line` references below.

Two source notes recorded because they cost time to discover:

- `contrib/mail-scripts/README.md` tells the reader to run
  `./gc-mail-mcp-agent-mail.test`. **That file does not exist at the pinned
  commit** (`contrib/mail-scripts/` holds only `README.md` and the script).
  The live driver for the reference provider is
  `internal/mail/exec/mcp_conformance_test.go`, which runs the contrib script
  through the real exec provider with a mock `curl`. §8 ports the shape of
  that, since the missing file cannot be ported.
- The plan's §5.2.1a **predates this seam**. It was verified against
  `gastownhall/gastown`'s `internal/cmd/mail.go` and describes an
  argv-passthrough delegate with no JSON protocol. Gas City's `GC_MAIL=exec:`
  is a different mechanism — one process per operation, JSON on stdin and
  stdout, single-token command. The plan's *strategy* survives intact; its
  *mechanism* paragraph does not describe this integration and should not be
  cited as if it did.

## 1. The contract we plug into

`GC_MAIL=exec:<command>` (or `[mail] provider` in `city.toml`) makes every gc
mail operation a fork/exec of `<command>`
(`cmd/gc/providers.go:855-857` → `mailexec.NewProvider`). One process per
operation:

```
<command> <operation> [single argument]
```

- **The value carries no arguments.** `newMailProviderNamedWithSessionStore`
  passes `strings.TrimPrefix(v, "exec:")` straight to `exec.CommandContext` as
  the program name (`internal/mail/exec/exec.go:249`). There is no whitespace
  split and no shell. `exec:aw gc-mail` looks for a program literally named
  `aw gc-mail`. A bare name with no `/` gets a `PATH` lookup, so
  `exec:aw-gc-mail` resolves against `PATH`. **This single fact decides §3.**
- **stdin** carries `{"from":...,"subject":...,"body":...}` for `send` and
  `reply`, and is explicitly set to an empty reader otherwise — the provider
  never inherits gc's stdin (`exec.go:243`, guarded by
  `TestArchiveDoesNotConsumeCallerStdin`).
- **stdout** is JSON: one message object, an array of them, or
  `{"total":N,"unread":N}`. It is `TrimRight`ed of newlines and then decoded
  into `mail.Message` (`internal/mail/mail.go:57-70`). **An empty stdout means
  "no messages"**, not an error.
- **stderr is discarded on success.** `run()` buffers it and only reads it when
  the exit code is non-zero (`exec.go:252-264`). There is no channel for a note
  a successful operation wants to make. §4 turns on this.
- **Exit codes are the contract's sharpest edge**:

  | code | gc's interpretation |
  |---|---|
  | 0 | success; stdout is the result |
  | **2** | **unknown operation → SUCCESS WITH EMPTY OUTPUT** |
  | anything else | error wrapping our stderr |

  Exit 2 is forward compatibility, and it is a loaded gun: `aw`'s own
  `usageError` exits 2 (`cli/go/cmd/aw/errors.go:24-29`). A usage failure under
  a *known* operation that exited 2 would be reported to the gc user as a
  successful send that delivered nothing. See §7.
- **`ensure-running` is called once per provider lifetime and its result is
  thrown away**: `_, _ = p.run(nil, "ensure-running")` (`exec.go:216-220`).
  Neither its output nor its exit status reaches anyone.
- **Two stderr strings are protocol.** `gc-mail-error:not-found` anywhere in
  stderr turns a failed `get`/`read`/`mark-read`/`mark-unread`/`reply` into
  `mail.ErrNotFound` (`exec.go:178-183`). `already archived` anywhere in an
  `archive`/`delete` error makes gc print `Already archived <id>` — a success
  line (`exec.go:98-113`). Our refusals must emit the first and must never
  contain the second.

**Compatibility floor:** the provider behaves correctly when exec'd by any gc
that implements this contract. Verified identical at v1.4.1 and pinned main.

## 2. Architecture: the same three pieces

Unchanged from the beads-mail record §2 — client (`aw gc-mail`), server (any
aweb server), optional wake path (the Claude Code channel plugin). `aw notify`
still checks chat only, never mail (`cli/go/cmd/aw/notify.go:64`); no surface
here may promise mail wakes from it.

Install story:

```
npm i -g @awebai/aw
aw init
export GC_MAIL=exec:aw-gc-mail
```

## 3. Packaging: a built-in subcommand plus a one-token launcher

**Decision: `aw gc-mail` is a built-in cobra subcommand of `aw`, and
`aw-gc-mail` is a launcher shipped as a second `bin` entry of the same npm
package** (`cli/go/npm/aw/package.json`, `cli/go/npm/aw/bin/aw-gc-mail`). The
launcher runs `aw gc-mail "$@"` against the exact platform binary in its own
package, so provider and CLI cannot skew.

Reasons of record:

- A Go subcommand is what we want: it reuses the client, identity, E2EE,
  address-resolution and comm-log plumbing the mail commands already link, and
  it ships with `aw` rather than adding an install step.
- But **`GC_MAIL` cannot name a command with arguments** (§1), so
  `exec:aw gc-mail` is not available. Something has to occupy one token.
- Rejected: **a script in this repo**. `exec:/path/to/aweb-oss/scripts/...`
  requires the user to clone or copy a file and keep it current — a worse
  install story than the bd delegate's, for the same product.
- Rejected: **generating a shim into the city** (`aw gc-mail install`). It adds
  a setup step and a file the user then owns and must re-generate on upgrade.
- Rejected: **a second Go binary**. It doubles the release artifacts, the
  vulnerability-exception entries and the VCS-stamp checks
  (`scripts/publish_release.py:335-380`, `scripts/check-cli-release-vcs-stamps.sh`)
  to save one `execFileSync`. The launcher adds no build step at all: `npm
  publish` already ships the whole `cli/go/npm/aw` directory.

The launcher costs one Node process per mail operation. gc mail operations are
interactive CLI calls with a 30s provider timeout, not a hot loop; the batch
paths that would have made this hurt (`ArchiveMany`, `DeleteMany`) are refused
anyway (§6).

Obligations discharged with the new command
(`cli/go/cmd/aw/identity_home_policy.go:24-83`, `root.go:20-26`):

- Every `aw gc-mail <op>` path is in `identityHomeAwareCommandPaths`, with the
  production-binary regression in `gc_mail_test.go`
  (`TestGCMailVerbRouterProductionBinary`) and the consumption evidence in
  `gc_mail_contract_test.go`.
- `GroupID` is `groupNetwork` (Messaging & Network).
- `docs/cli-command-reference.md` regenerated
  (`scripts/regenerate-cli-reference.sh`).
- `gc-mail` registered in both copies of the reserved-app-ids release-gate
  artifact (`test-vectors/reserved-app-ids-v1.json` and the byte-identical
  `server/src/aweb/data/reserved-app-ids-v1.json`) — the same pair beads-mail
  needed in commits `4dc97145` and `056a571a`.
- **Flag parsing stays enabled** on every operation, even though gc's protocol
  is positional-only. `DisableFlagParsing` hands the subcommand cobra's
  unparsed argv including `aw`'s own root flags, so
  `aw --identity-home <path> gc-mail send <to>` arrives as three positional
  arguments and fails arity instead of running. Found by the identity-home
  regression, not by reading.

## 4. Identity and addressing

### Sender identity

Mail goes out under the workspace identity `aw init` created — signed, and
verifiable against the AWID registry. This is unchanged from beads-mail §4 and
is the whole point.

gc supplies a `from` field on stdin for `send` and `reply`: its own local
mailbox name, defaulted from `$GC_SESSION_ID`, `$GC_ALIAS`, `$GC_AGENT`, or
`"human"` (`cmd/gc/cmd_mail.go:927-947`). **It is ignored for identity.** The
bd delegate could reject `--from` with an explanation because it was a flag a
user typed; here the field is unconditional protocol, so there is nothing to
refuse — it is simply not a sender. It is not recorded as one anywhere either:
no envelope carries it, because carrying an unverified sender name beside a
verified one invites reading the wrong one.

### Recipient resolution

**The resolution order is the beads-mail record §5 order, unchanged**, and is
literally the same code (`cli/go/cmd/aw/mail_delegate_address.go`, shared by
both providers): map entry → `did:` → `list:` refusal → well-formed
`domain/name` (leading `@` normalized to the hosted handle form) → bare name as
a same-team alias → the unmapped-name error quoting the exact line to add.

One gc-specific guard sits in front of it: **`human` and `controller` are gc's
reserved names** (`cmd_mail.go:912-925`) and are refused unless explicitly
mapped. Unmapped, a bare `human` would otherwise fall through to step 5 and be
looked up as an aweb team alias — sending the operator's mail to whoever
happens to hold that name.

### The map

`<city>/.gc/aweb-mail.toml`, same strict-TOML grammar and same value
validation as `.beads/aweb-mail.toml`. The city root comes from `GC_CITY` when
gc set it (the reference provider script reads exactly that variable), else by
walking up for a directory containing `.gc`. Note the asymmetry the shared
spec exists for: **`BEADS_DIR` names the marker directory itself; `GC_CITY`
names the directory containing it.**

**The map's standing differs from the bd delegate's, and this is the honest
statement.** The beads record calls the map an optional convenience that may be
removed if nobody authors one. Here it is load-bearing inside a running city,
for a reason that has nothing to do with preference:

> **Inside a city with a bead store, gc resolves and validates the recipient
> against its own live session mailboxes before the provider is ever called**
> (`cmd_mail.go:1997-2010` canonicalization, then
> `doMailSendJSON`'s `validRecipients` gate at `cmd_mail.go:1869-1872`). A full
> aweb address is not a live session mailbox, so gc refuses it with
> `unknown recipient` and the provider never runs. Outside a city store — the
> `exec:` path explicitly tolerates having none (`cmd_mail.go:1749-1755`) — the
> recipient passes through verbatim and the whole address grammar is available.

So: no city store, no map needed, full addressing. Inside a city, you address
the names gc accepts, and the map is what turns those into aweb addresses. It
is still not a setup step — `aw init` plus the export is the setup — but the
first cross-org send from inside a city will meet the unmapped-name error, and
that error is the onboarding.

The prohibition from the beads record carries over verbatim: **this file must
never grow into the plan's task 1.4** (verified actor↔AWID binding). It is
unverified repo-writable data; actor binding gets built on identity.

### Disclosure, and what we lost

The beads record §5 requires every send to print the resolved address, because
the map is repo-controlled data redirecting mail that carries the user's
verified identity. **The exec protocol has no channel for that line**: stdout
must be JSON, and stderr is discarded unless we fail (§1). Recorded as a real
reduction in disclosure, with two partial substitutes rather than a pretence:

1. **The returned message's `to` is always the RESOLVED aweb address.** gc's
   plain `gc mail send` output prints the argument it was given
   (`cmd_mail.go:1888` uses `to`, not `m.To`), but `gc mail send --json`,
   `gc mail read`, `gc mail thread` and `gc mail reply`'s own line
   (`cmd_mail.go:2293`, which uses `reply.To`) all show what we returned.
2. **`aw gc-mail resolve <name>`** — not part of gc's protocol — prints where a
   name would deliver and which file mapped it, without sending anything.

For the same reason, the identity labels we emit (`from`, `to`) are the
verified aweb address (else DID, else team alias) and are **not** reverse-mapped
to local names. Every label we emit therefore re-resolves through the order
above, so a name gc displays can be handed straight back as a recipient.

## 5. One identity per city: the limitation, stated plainly

gc's mail model is many mailboxes inside one city — each session, plus `human`,
plus `controller`. aweb's model is one workspace identity per workspace.

**With this provider, the whole city shares one aweb identity.** Every
operation's recipient argument (`inbox`, `check`, `all`, `count`) is accepted
and ignored: `gc mail inbox mayor` and `gc mail inbox deacon` return the same
inbox. Refusing the argument instead was rejected because gc's default
recipient is `$GC_SESSION_ID`, so refusal would break the bare `gc mail inbox`.

This is a genuine loss of gc's per-session addressing, not a temporary gap, and
it is the first thing the user doc says. It leaks nothing: anyone who can run
`gc mail` in this city can already run `aw mail inbox` there. Per-session aweb
identities would need one aweb workspace per session and a way to hand each
session its own; that is out of scope for v1 (§10).

## 6. The operation table

Legend: **impl** = implemented; **rej** = refused with an explanatory error and
exit 1; **n/a** = the protocol has no such operation.

| gc operation | v1 | Mapping / message |
|---|---|---|
| `ensure-running` | impl | Explicit no-op, exit 0. gc discards both the result and the error (§1), so a preflight here reports to nobody and costs a round trip. Identity and reachability failures surface on the first real operation, where gc shows our stderr. |
| `send <to>` | impl | Resolve `<to>` (§4) → `POST /v1/messages` under the workspace identity. `from` on stdin is ignored (§4). Fresh conversation; HTTP 409 triggers the server-directed continuation retry of beads-mail §8. |
| `send` — empty subject | impl | gc allows it (`gc mail send <to> "body"` passes none). An empty subject becomes the body's first line, truncated to 72 runes — the same choice the reference `gc-mail-mcp-agent-mail` script makes. |
| `reply <id>` | impl | Continuation of the source message's conversation, then ack the source. Empty subject → `Re: <original>`. **No recipient is named**: the server requires a continuation's signed recipient to match the conversation's (beads-mail §8), so the conversation id alone routes it and there is nothing to get wrong — the shared client resolves the conversation's live participants at send time and signs that target. The returned `to` is the conversation's counterparty, because gc prints `reply.To`; note it is **display, inferred from the source message**, not a read-back of the routed target, since the send response carries no recipient field. 1:1 conversations make the two agree, and the routed target is the truthful one if they ever could not. |
| `inbox [recipient]` | impl | `GET /v1/messages/inbox?unread_only=true`, **read-only**. Recipient ignored (§5). |
| `check [recipient]` | impl | Identical to `inbox`. gc keeps the two apart because a backend's inbox may mark read; ours never does. |
| `all [recipient]` | impl | One page, read and unread. aweb has no open/closed state, so "all open messages" is everything the inbox holds inside the retention window. |
| `get <id>` | impl | Exact read, no read-state change. Uses the sender-OR-recipient scoped endpoint, so mail this workspace *sent* is visible too (beads-mail §8). |
| `read <id>` | impl | Exact read, then ack. Reading is what marks read, because read state drives the unread count and the wake path. A failed ack exits non-zero rather than claiming the message is read. |
| `mark-read <id>` | impl | `POST /v1/messages/{id}/ack`. No output, as the protocol expects. |
| `thread <id>` | impl | Conversation view, oldest first, 500-message ceiling. gc documents the argument as a thread id **or any message id in the thread**, so both work: the conversation endpoint is tried first, and a miss is looked up as a message and answered with its conversation. Thread ids **are** aweb `conversation_id`s. |
| `count [recipient]` | impl | `{"total":N,"unread":N}`. "Total" is what the inbox holds inside the retention window, not a lifetime total; counting stops at 4000 (20 pages of 200) and reports that ceiling rather than a wrong number. |
| `mark-unread <id>` | rej | No server capability (`messages.py:1901-1912`). Same decision as beads-mail. |
| `archive <id>` | rej | aweb mail cannot be removed on request; it expires under the retention policy (§9). Note that **gc's own `archive` deletes the message bead outright** — its bundled skill says "IRRECOVERABLE: deletes the underlying bead, despite the name" — which this provider deliberately does not imitate even where it could. |
| `delete <id>` | rej | As `archive`; gc's `Delete` is an alias for it. |
| `ArchiveMany` / `DeleteMany` | n/a | Not protocol operations: gc's exec provider loops over single-id `archive`/`delete` (`exec.go:117-143`). Both refused, so both loops refuse per id. |
| `--priority`, `--type`, `--cc`, `--pinned` | n/a | **The exec protocol carries no metadata.** `sendInput` is exactly `{from, subject, body}` (`exec/json.go:9-22`). Nothing to map, so §9's fenced envelope from the beads record is not emitted here and would carry nothing if it were. `mail.Message.priority` is likewise not emitted inbound: aweb's four-value priority does not obviously mean gc's integer, and guessing a scale is worse than omitting a field gc's decoder already treats as optional. |
| `--notify` | n/a | Handled entirely gc-side by its nudge function before/after the provider call; never reaches us. |
| unknown operation | impl | Exit 2 — gc's forward-compatibility case, and the one place the code means what gc thinks it means. `refuseUnknownSubcommands` already produces it. |

Additional, outside gc's protocol:

| verb | why |
|---|---|
| `aw gc-mail resolve <name>` | The disclosure surface of §4, since the protocol has no send-time channel. |

## 7. The exit-code rule

**No failure of a known operation may exit 2.** `gcMailError` builds exit-1
errors, `gcMailForceExitCode` re-codes anything that arrives as 2 from the
helpers shared with the bd delegate (which raise `usageError`), and both the
unit test and the contract test assert it, including through the real binary.

The refusals in §6 exit 1 rather than 2 for the same reason: exit 2 would make
`gc mail archive <id>` print `Archived message <id>` while nothing happened.
Honest refusal over silent fake — and the refusal text is checked not to
contain `already archived`, which would trip gc's other success path (§1).

## 8. Tests

- `cli/go/cmd/aw/gc_mail_test.go` — unit tests in the style of the
  `beads_mail_*_test.go` files: subject derivation, timestamp normalization
  (an unparseable `created_at` would fail gc's decode of the *whole* message,
  so it is dropped instead), wire-shape pinning, the reserved-name guard, the
  map's `GC_CITY`/walk-up lookup, the exit-code rule, and the production-binary
  identity-home regression.
- `cli/go/cmd/aw/gc_mail_contract_test.go` — the contract test.
  `gcExecProvider` in it **reimplements gascity's `exec.Provider.run()`
  semantics** (args, JSON stdin never inherited, exit 2 → success with empty
  output, stderr wrapped on other failures, stdout `TrimRight`ed then decoded
  into a struct mirroring `mail.Message`) and drives the **real production
  binary** through every operation against a local aweb server. This ports the
  shape of `internal/mail/exec/mcp_conformance_test.go` — the live driver, since
  the `.test` file the contrib README names does not exist (see the source
  notes) — and deliberately not its `curl` mock, which belongs to
  mcp_agent_mail rather than to the protocol.
- **The OSS user-journey e2e gains no Gas City phase.** Phase 16b can drive
  `bd mail` because `bd` is installable and the delegate contract is argv
  passthrough. Driving `gc mail` needs a `gc` binary, a city, and a bead store;
  everything cheaper than that is the contract test above, which already drives
  the real `aw` binary through gc's own protocol semantics. Adding a phase that
  skips whenever `gc` is absent would report green on machines that tested
  nothing.

## 9. Retention

Unchanged from beads-mail §11: aweb mail is delivery, not archival storage, and
30 days is the floor a client may rely on (`server/src/aweb/gc.py:18`). No
surface here may imply the server keeps mail forever, and `count`'s help says
so where a user would otherwise read "total" as a lifetime figure.

The difference worth naming: the bd delegate could point at the beads graph as
the durable record, and dual-writes to it. **Gas City's own mail beads are what
this provider replaces**, so there is no second store to fall back on. Nothing
here dual-writes: `gc mail` with an `exec:` provider deliberately runs without
a bead store, and reaching around the protocol to write beads gc did not ask
for would make this provider a second author of gc's data plane.

## 10. E2EE

v1 sends `legacy_plaintext_v1`, exactly as `aw mail send` and `aw beads-mail`
default today. Reading encrypted mail that arrives is supported — the read
paths call `configureClientE2EEForRead` like the other mail commands.

## 11. Instrumentation

Per beads-mail §15 — mark the transport, never the content — every request
carries `User-Agent: aw-gc-mail/<version>`.

**Decision recorded: a distinct token, not the beads marker.** Gas City
adoption and plain-beads adoption are separate questions with separate
audiences and separate next moves; one shared marker would make the two
indistinguishable in exactly the measurement the wedge exists to produce. The
contract test asserts gc-mail requests never carry `aw-beads-mail/`.

## 12. Out of scope for v1, recorded so nobody re-litigates

- **No replication, no Team Server alternative, no webhooks.** The plan's
  do-NOT-pitch list binds this implementation and its docs as it binds the bd
  delegate's.
- **No per-session aweb identities.** One workspace identity per city (§5).
- **No dual-write into gc's bead store** (§9).
- **No server-side capability additions** (mark-unread, archive, delete,
  search); each becomes an explicitly proposed task only if demand appears.
- **No attempt to widen gc's own recipient gate** (§4). Changing which names
  `gc mail send` accepts is a change to gc, not to a mail provider, and would
  be an upstream proposal rather than a local workaround.
