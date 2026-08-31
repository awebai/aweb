# Beads mail delegate: design record

Status: **decided design record** for `aw beads-mail`, the aweb-backed
`bd mail` delegate (epic aweb-abhf, subtask .1). Implementation subtasks
cite sections of this record instead of making local decisions. If
implementation shows a decision here is wrong, the fix goes through this
record first, not into a quiet divergence.

Authority: the beads-ecosystem plan §5.2.1/§5.2.1a
(`bookshelf/strategy/2026-08-22-beadhub-revival-and-federation-plan.md`).

Verified sources, pinned 2026-08-31:

- `gastownhall/beads` @ `d530cddfa64b` — the delegate exec contract,
  `cmd/bd/mail.go`; the message-issue shape, `engdocs/messaging.md`.
- `gastownhall/gastown` @ `649b832b7672` — the reference verb surface,
  `internal/cmd/mail.go`.
- aweb-oss @ current main — all `file:line` references below.

## 1. The contract we plug into

`bd mail <anything>` resolves a delegate command from, in order,
`BEADS_MAIL_DELEGATE`, `BD_MAIL_DELEGATE`, then `bd config
mail.delegate`, and **execs it with the raw args appended** —
stdin/stdout/stderr passed through, exit code propagated. There is no
JSON protocol and no API: the delegate is a CLI that owns the whole mail
verb surface. With no delegate configured, `bd mail` errors.

Two facts we verified rather than assumed:

- The contract is stable across versions we care about: the pinned main
  matches the plan's 2026-08-23 verification except metrics and error
  plumbing, and a live probe against Homebrew bd 1.1.2 (the old version
  users already have installed) execs the delegate correctly.
- `bd mail` intercepts `--help`/`-h` itself; everything else reaches us
  verbatim, including flags we do not recognize. The delegate must parse
  gt-shaped argv defensively: unknown verbs and flags produce our error
  messages, never a crash or a silent reinterpretation.

**Compatibility floor:** the delegate behaves correctly when exec'd by
any bd that implements this contract (≥ 1.1.x verified). It must not
depend on bd being present for anything except the dual-write of §12.

## 2. Architecture: three pieces, one of them ours

- **Client** — `aw beads-mail`, a subcommand of the `aw` CLI (§3). It
  translates the verb surface into aweb mail API calls using the
  workspace identity from normal `aw init` state. It delivers nothing
  itself.
- **Server** — any aweb server: `app.aweb.ai` hosted by default, or
  self-hosted. Durable storage under the recipient's identity, offline
  tolerance, wake events. Nothing in this design is hosted-only.
- **Wake path (optional)** — the Claude Code channel plugin
  (`@awebai/claude-channel`) turns "mail waiting on the server" into
  "session wakes and reads it". Without it, mail still works by polling
  (`bd mail inbox` / `bd mail check`). `aw notify`, the standard
  PostToolUse hook, checks **chat only, never mail**
  (`cli/go/cmd/aw/notify.go:64`); no documentation may promise mail
  wakes from it.

Install story, documented for plain-beads users first:

```
npm i -g @awebai/aw
aw init
bd config set mail.delegate "aw beads-mail"
```

Docs prefer `bd config set mail.delegate` over the env var: it persists
in the beads DB and survives shells.

## 3. Packaging: built-in subcommand

**Decision: `aw beads-mail` is a built-in cobra subcommand of the `aw`
binary**, not an out-of-process `aw-beads-mail` plugin (the dispatcher
at `cli/go/cmd/aw/plugin.go:793` would support one, and the name is
unreserved) and not a standalone binary. Reason: the three-line install
story is the product; a plugin or second binary adds an install step and
a version skew surface, and the delegate needs the same client, identity
and E2EE plumbing the mail commands already link.

Obligations that come with a new command
(`cli/go/cmd/aw/identity_home_policy.go:24-83`, `root.go:20-26`):

- Every `aw beads-mail <verb>` path is added to the identity-home
  allowlist with the required production-binary regression test.
- The command gets a `GroupID` (Messaging & Network, registered at
  `root.go:110`).
- `docs/cli-command-reference.md` is regenerated
  (`scripts/regenerate-cli-reference.sh`).
- Help text is written for a beads user who has never heard of aweb:
  what this is, the three-line setup, where mail lives, how to get the
  wake path.
- **`bd mail` swallows `--help`/`-h` anywhere in the args** (its
  interception scans the whole argv before delegating), so
  `bd mail send --help` never reaches us. Per-verb help is therefore
  reachable as `bd mail help [verb]` (a plain arg, delivered — cobra's
  built-in help command answers it) and as `aw beads-mail <verb>
  --help` directly; every help surface and doc teaches those two forms
  instead of `bd mail <verb> --help`.

## 4. Identity: who mail comes from

Mail goes out under the workspace identity that `aw init` created —
signed, and verifiable against the AWID registry. This is the live
counterargument to beads' caller-asserted `actor` string and the demo
for the plan's §5.2.2 proposal.

**`--from` is rejected**, with a message explaining that sender identity
is cryptographic here, not asserted; gt uses `--from` as a relay
affordance and a relay is not what this is. There is no spoofable
sender.

## 5. Addressing and the per-repo map

aweb's global address grammar is `domain/name`. There is no
`name@domain` parsing path anywhere: addresses split on `/` only, so an
email-style string is treated as an opaque alias and fails as "not
found", not as a grammar error. A *leading* `@` is hosted-handle
shorthand — `@handle/agent` normalizes to `handle.aweb.ai/agent`
(`cli/go/awid/network_address.go:12`); the server separately rejects a
leading `@` on `to_address` (`messages.py:172-178`). Map values are
validated to the `domain/name` or `did:aw:` forms precisely so an
email-style value fails at map load with a helpful message instead of
as a late "not found".

### Map file

`.beads/aweb-mail.toml`, committed alongside the beads DB so the whole
repo shares one mapping:

```toml
# beads-style local names -> aweb addresses
[addresses]
"mayor/"  = "acme.aweb.ai/mayor"
"worker/" = "acme.aweb.ai/worker"
"crow"    = "did:aw:..."          # DIDs allowed as values
```

Keys are arbitrary strings (trailing-slash rig names included). Values
must be a `domain/name` address or a `did:aw:` DID; anything else fails
validation with a message quoting the two accepted forms.

### Resolution order for a recipient argument

1. Exact key in the map → mapped value.
2. Starts with `did:` → DID target.
3. Starts with `list:` (gt's mailing-list fan-out) → not implemented in
   v1; explicit error naming the prefix, so gt-shaped input gets a real
   answer instead of falling through to alias lookup.
4. Contains `/` with a dot in the prefix (`acme.com/reviewer`) → already
   an AWID address; passes through, no map needed.
5. Bare name with no `/` **and no `@`** → same-team alias, following the
   same convention `aw mail send --to` applies (`resolveMailTarget`,
   `cli/go/cmd/aw/mail.go:683` — the convention, not necessarily the
   same callable). The `@` exclusion is a deliberate delegate-side
   improvement over raw aw grammar (review amendment, 2026-08-31): a
   bare `alice@acme.com` is almost certainly a typo'd address, so it
   gets the step-6 map guidance rather than a doomed alias lookup.
   Control characters are likewise excluded everywhere: an input
   carrying them never resolves, and the disclosure line neutralizes
   them defensively.
6. Anything else (an unmapped rig-style name like `mayor/`) → error:

   ```
   "mayor/" is not mapped to an aweb address.
   Add it to .beads/aweb-mail.toml:

     [addresses]
     "mayor/" = "<domain/name or did:aw:...>"
   ```

   This error is part of the product; a beads user meets it before any
   documentation.

Dispatch onto the client follows the same split the mail commands use
(`cli/go/cmd/aw/mail.go:490-493,612`): a same-team alias sends through
`c.SendMessage` (certificate-authenticated); DID, address, and every
conversation continuation (including all of `reply`) send through
`c.SendMessageByIdentity`.

### Disclosure

**Every send prints the resolved address** (`sent to mayor/ →
acme.aweb.ai/mayor`). The map is repo-controlled data redirecting mail
that carries the user's verified identity; a wrong or hostile entry must
be visible at the moment it acts, not discoverable later. Inbox and read
display the local name (reverse map) alongside the sender's AWID
address — attribution is a feature; show it.

## 6. Verb surface: the v1 table

Reference surface: `gt mail` at the pinned gastown commit. Legend:
**impl** = implemented in v1; **env** = accepted, carried in the §9
envelope, no aweb behavior; **rej** = rejected with an explanatory
error; **n/i** = not implemented in v1, clear message, nonzero exit.

| Verb / flag | v1 | Mapping / message |
|---|---|---|
| `send <address>` | impl | `POST /v1/messages` via the Go client (§8) |
| `send -s/--subject` | impl | required, as in gt |
| `send -m/--message`, `--body` | impl | body |
| `send --stdin` | impl | body from stdin, bytes in bytes out |
| `send --to` | impl | alternative to the positional argument |
| `send --priority 0-4` | impl | mapped per §9; original value in envelope |
| `send --urgent` | impl | priority 0 |
| `send --type` | env | `task\|scavenge\|notification\|reply` |
| `send --reply-to <id>` | impl | continuation of that message's conversation (§8) |
| `send --self` | impl | send to own workspace identity |
| `send --cc` | n/i | aweb mail is one recipient per message; "send separately" |
| `send --from` | rej | §4 |
| `send --pinned` | env | no delivery behavior; meaningful to dual-write later |
| `send --wisp` / `--permanent` | env | gt defaults wisp; drives `ephemeral` when dual-write lands |
| `send -n/--notify` | impl | bumps priority to high (gt: same); mutually exclusive with `--no-notify`, hard error, as gt |
| `send --no-notify` | impl | no-op at priority ≤ normal (idle wake anyway); warns if combined with high/urgent, which always wake |
| `inbox` | impl | `GET /v1/messages/inbox?unread_only=true`, read-only. **Deliberate default flip:** gt's bare `inbox` shows all messages; ours shows unread only, matching mail convention and the `check` story. `--all` restores gt's view. |
| `inbox -u/--unread` | impl | explicit form of our default |
| `inbox -a/--all` | impl | includes read (`--show-all` listing) — gt's default view |
| `inbox --json` | impl | |
| `inbox [address]` positional | n/i | same reason as `--identity`: one workspace identity per repo |
| `inbox --identity/--address` | n/i | one workspace identity per repo |
| `read <id\|index>` (alias `show`) | impl | `GET /v1/messages/{id}`, then ack — **a deliberate break from gt**, whose `read` promises non-mutation; see §7 |
| `read --json` | impl | |
| `peek` | impl | first unread, read-only, no ack; exit 0 with or without mail, like `check` (§10) — same disclosed divergence from gt |
| `reply <id> [msg]`, `-s`, `-m/--body` | impl | send into the source message's conversation, then ack source; `-s` omitted → subject `Re: <original>`, as gt |
| `thread <id>` | impl | conversation view (§8) |
| `thread --json` | impl | |
| `check` | impl | §10 |
| `check --json`, `--inject` | impl | §10 |
| `check --identity/--address` | n/i | as inbox |
| `mark-read [ids...]`, `--all` (alias `ack`) | impl | `POST /v1/messages/{id}/ack` |
| `mark-unread` | n/i | no server capability (`messages.py:1901-1912`); server-side follow-up task if demanded |
| `archive`, `--stale`, `--dry-run` | n/i | no server capability; aweb mail expires ~30 days on its own (§11); the beads graph is the archive |
| `delete` | n/i | no server capability; TTL GC only (`gc.py:29`) |
| `clear [target]`, `--all` | n/i | as delete |
| `help [verb]` | impl | cobra built-in; the reachable per-verb help path (§3) |
| `search` | n/i | no server endpoint; message points at `bd` search over dual-written beads, or `aw log` |
| `claim [queue]` / `release <id>` | n/i | per plan §5.2.1a; may later map to aweb tasks/locks |
| `announces [channel]` | n/i | per plan §5.2.1a |
| `drain` | n/i | gt's bulk inbox-drain; use `mark-read --all` |
| `send list:<name>` | n/i | mailing-list fan-out; §5 resolution step 3 |

Every n/i and rej message says what the verb would do, why v1 does not
do it, and what to use instead. Honest refusal over silent fake.

## 7. Read state

The delegate talks to the API/Go client directly and **never shells out
to `aw mail`**, because `aw mail inbox` acknowledges everything it
presents (`presentAndAcknowledgeMailInbox`,
`cli/go/cmd/aw/mail.go:856-873`) — the wrong semantics for a gt-shaped
surface.

- `inbox` and `peek` are **read-only** (unread stays unread).
- `read` acknowledges the message after displaying it successfully —
  reading is what marks read. **This deliberately breaks gt's `read`,
  which documents itself as non-mutating.** Reason: aweb's read state
  drives the unread count and the wake path; a displayed message that
  stays "unread" would keep re-firing `check` and channel wakes. gt
  users who want a non-mutating look have `peek` and `thread`.
- `reply` acknowledges the source message after the reply sends
  (matching `aw mail reply`'s behavior).
- `mark-read` is the explicit form.
- There is no `mark-unread` (§6).

Caveat documented to users: a recipient running the channel plugin will
find mail already marked read, because the plugin acknowledges on
presentation to the session (`channel/src/index.ts:159`). That is the
wake path working, not a bug.

**Index contract:** `read <index>` (1-based) refers to the most recent
`inbox` listing in this workspace. The listing's message ids are stored
in `.aw/beads-mail/state.json` (workspace-local, never committed).
`read` with no prior listing, or an index out of range, errors and says
to run `bd mail inbox` first.

## 8. Threading

- Thread ids **are** aweb `conversation_id`s. (The `thread_id` field in
  the client structs is dead — the server never emits it.)
- The delegate always controls conversations explicitly: a plain `send`
  creates a fresh conversation; `reply` and `send --reply-to` continue
  the source message's conversation by id. The delegate never relies on
  `aw mail send`'s opportunistic auto-threading
  (`cli/go/cmd/aw/mail.go:391-419`) — sending via the client with
  explicit parameters bypasses it.
- `thread <id>` renders the conversation oldest-first. The server view
  has a 500-message ceiling and no paging
  (`cli/go/cmd/aw/mail.go:1007-1022`); when the returned count equals
  the limit, the output says the thread may be truncated rather than
  implying completeness.
- On success, `send` and `reply` print both `message_id` and
  `conversation_id` in a stable, parseable line.

## 9. Priority mapping and the envelope

Mail carries no structured metadata: `SendMessageRequest` is
`extra="forbid"` (`server/src/aweb/routes/messages.py:94-95`). Subject,
body, and a four-value priority are the only carriers, and **priority is
the wake lever**: `high|urgent` → `wake_mode: prompt`, everything else →
`idle` (`server/src/aweb/routes/events.py:94`).

Priority map (original beads value always preserved in the envelope):

| beads | aweb | recipient wake |
|---|---|---|
| 0 (urgent), `--urgent` | urgent | prompt |
| 1 (high), `--notify` | high | prompt |
| 2 (normal, default) | normal | idle |
| 3 (low) | low | idle |
| 4 (backlog) | low | idle |

Anything gt-shaped that aweb cannot express rides a fenced envelope
appended to the body — the established aweb pattern for structure in
mail (the A2A gateway's fenced JSON,
`cli/go/a2agw/mail_bridge.go:443,446`):

````
```beads-mail
{"v":1,"type":"task","priority":1,"pinned":true,"ephemeral":false}
```
````

(Wire-key amendment, 2026-08-31, from the abhf.4 review: the field is
`ephemeral` — matching §6/§12's vocabulary and the beads message-issue
shape — not `wisp`; an earlier example here showed `wisp`. Fields are
emitted only when non-default: `type` ≠ notification, `priority` ≠ 2,
`pinned` true, `ephemeral` false.)

Rules: the envelope is emitted only when it would carry non-default
values (plain messages stay plain); it is the **last** fenced
`beads-mail` block in the body; `read`/`thread` parse it, render its
fields as headers, and strip the block from the displayed body
(`--json` output includes it verbatim). A malformed envelope is
displayed as ordinary body text, never an error — inbound mail is data.
The envelope carries **no trust boundary**: it is sender-controlled body
text, so nothing behavioral may key off it — the wake-driving priority
is always the server-side message field, and envelope fields are display
metadata only (amendment, 2026-08-31, from the abhf.5 review).

## 10. `check` and the wake path

`check` is the hook-facing probe, implemented as read-only
`GET /v1/messages/inbox?unread_only=true`.

Contract: with unread mail, prints `You have N unread bd mail
message(s). Run: bd mail inbox` and exits 0; with none, prints nothing
and exits 0; nonzero exits are reserved for real errors (no workspace,
server unreachable). **This deliberately diverges from `gt mail check`,
which exits 0 for new mail and 1 for none** — overloading the exit code
as the mail-present signal makes "no mail" indistinguishable from
"probe broke" in a hook line. Scripts branch on stdout or `--json`
(`{"unread": N}`) instead; the divergence is stated in the delegate's
help text so a `gt mail check &&`-style hook is not silently
miswired. `--json` always emits `{"unread": N, "has_more": bool}`, and
when the 50-message probe page is full with more waiting, the text and
inject lines render the count as `N+` — an honest floor, never a
misleading partial (amendment, 2026-08-31, from the abhf.6 review).
`--inject`
emits the Claude Code PostToolUse hook JSON envelope (the
`hookSpecificOutput.additionalContext` shape `aw notify` uses,
`notify.go:198`) when N > 0, nothing otherwise — cheap and safe to call
from a hook loop.

The in-session wake path is the channel plugin, set up via `aw init
--setup-channel`; the docs present it as the optional upgrade and are
explicit that without it, polling still works. Wake urgency is
priority-derived (§9) — senders who want a prompt wake send beads
priority 0/1.

## 11. Retention

aweb mail is delivery, not archival storage. The retention contract is a
~30-day TTL: `gc_expired_messages(ttl_days=30)`
(`server/src/aweb/gc.py:18`) defines it. Verified 2026-08-31: **no
deployment currently schedules that GC** — it has zero callers in
aweb-oss and zero references in the hosted repo — so mail persists
longer in practice today. Neither fact changes the rule: a deployment
may wire the GC at any time, so 30 days is the floor a client may rely
on, and no surface of the delegate may imply the server keeps mail
forever. The durable record is the beads graph — via dual-write (§12)
when enabled, or the user's own process.

## 12. Dual-write: deferred, shaped here

The data-plane dual-write (beads stores the message as a `type: message`
issue with `replies_to` threading, per `engdocs/messaging.md`; aweb does
delivery) is **not in the v1 core**. It lands behind a config toggle,
default off, as epic subtask aweb-abhf.7 (P1), which also owns the
re-entrancy question (a child `bd` writing the DB the parent `bd` may
hold open) and the hang/failure isolation bounds. v1 ships without it;
the docs' retention honesty (§11) is what makes that acceptable.

The envelope (§9) already carries the fields dual-write needs (`type`,
original priority, `wisp`/`ephemeral`, `pinned`), so enabling it later
changes no wire format.

## 13. E2EE

v1 sends `legacy_plaintext_v1`, exactly as `aw mail send` defaults
today. A `--e2ee` passthrough is **not implemented in v1**: it fails
closed without recipient key state, which is friction a first-contact
beads user cannot debug, and under E2EE the envelope is invisible to the
server (fine) but subject/body rules differ (`messages.py:129-130`).
Reading encrypted mail that arrives is supported — read paths call
`configureClientE2EEForRead` (`cli/go/cmd/aw/mail.go:732`) like the
other mail commands, and render what keys allow.

## 14. Out of scope for v1, recorded so nobody re-litigates

- No replication (bd dolt push/pull is the data plane), no Team Server
  competition, no webhooks — the plan's do-NOT-pitch list binds the
  implementation and its docs.
- No `--identity` multi-inbox support; one workspace identity per repo.
- No server-side capability additions (mark-unread, archive, delete,
  search); each becomes an explicitly proposed task only if user demand
  shows up.
