---
title: "Mail for beads"
kicker: "Integration guide"
description: "Turn bd mail on with three lines — durable delivery, offline recipients, and verified sender identity, no orchestrator required."
weight: 56
---

# Mail for beads, no orchestrator required

[beads](https://github.com/gastownhall/beads) ships a `bd mail` command
that delegates to an external mail provider — and without one
configured, it only prints an error. This page turns it on, backed by
aweb: durable delivery, recipients who can be offline, and messages
signed by a verifiable identity instead of a caller-asserted name.

You do not need to know anything about aweb beyond this page.

## Setup: three lines

```bash
npm i -g @awebai/aw
aw init
bd config set mail.delegate "aw beads-mail"
```

That's it. `bd mail send`, `bd mail inbox`, `bd mail read`, and friends
now work in this repo. Prefer `bd config set mail.delegate` over the
`BEADS_MAIL_DELEGATE` environment variable: the config persists in the
beads database and survives shells.

`aw init` creates this workspace's identity — the cryptographic sender
your mail goes out as — and connects it to a mail server (hosted at
app.aweb.ai by default; self-hosting is a Docker container, see the
[self-hosting guide](self-hosting-guide.md)).

Two setup facts worth knowing up front:

- **Run `aw init` in the bd repo itself.** aw resolves identity from the
  current directory only — it does not look upward the way bd finds
  `.beads` — so a bd repo nested under some other aw workspace still
  needs its own identity, or an attached one via
  `AWEB_IDENTITY_HOME=<path-to-.aw>`.
- **`bd init` edits agent instruction files in place** (it appends
  managed blocks to `AGENTS.md`/`CLAUDE.md` and its injected guidance
  may not match your team's conventions). That's beads behavior, not
  this delegate's — but you meet it on this page's path, so review
  those files after `bd init`.

## Mail has two ends

The recipient runs the same three lines in their repo. Then connect the
two ends, either way:

- **Same team**: one side runs `aw team invite`, the other `aw team
  join`; after that, bare member names route (`bd mail send reviewer -s
  "hi"`).
- **Across organizations**: no shared team needed — send to the full
  address (`bd mail send acme.aweb.ai/reviewer -s "hi"`). Delivery is
  federated server-to-server; the sender's identity verifies on the
  receiving side against the AWID registry (aweb's public identity
  directory).

## Addressing mail

Two forms cover almost everyone, no configuration needed:

- **A teammate**: the bare member name (`bd mail send reviewer -s "hi"`)
  — anyone on your aweb team.
- **Anyone else**: the full address (`bd mail send acme.aweb.ai/reviewer
  -s "hi"`) — works across organizations and servers.

### Optional: mapping rig-style names

Only if your repo already uses Gas Town rig-style local names
(`mayor/`, `worker/`) and you want to keep typing them: map them once in
`.beads/aweb-mail.toml`, committed alongside the beads database so the
whole repo shares it:

```toml
[addresses]
"mayor/"  = "acme.aweb.ai/mayor"
"worker/" = "acme.aweb.ai/worker"
```

Anything already carrying a domain (`acme.com/reviewer`) needs no
mapping. Every send prints the resolved address — the map redirects mail
that carries your verified identity, so you always see where a message
actually went:

```
sent to mayor/ -> acme.aweb.ai/mayor (message_id=... conversation_id=...)
```

An unmapped name fails with the exact line to add. That error is the
whole onboarding for the map.

## The everyday verbs

```bash
bd mail send mayor/ -s "Water levels" -m "the well is low"
bd mail inbox            # unread, numbered; read-only
bd mail read 1           # by number from the last inbox, or by id; marks read
bd mail reply <id> -m "on it"
bd mail thread <thread-id>
bd mail peek             # first unread, changes nothing
bd mail check            # for hooks and scripts; see below
bd mail mark-read --all
```

Priorities are beads-style `--priority 0-4` (or `--urgent`): 0 and 1
wake a recipient whose session is listening (see the wake path below);
2-4 wait quietly. `-n/--notify` bumps a message to waking priority the
gt way (`--no-notify` cannot silence 0/1 — those always wake). `--type
task` and similar metadata travel with the message and show up as
headers on the reading side.

Per-verb help: `bd mail help send` (note: `bd mail send --help` never
reaches the delegate — bd intercepts `--help` itself).

### Three things that differ from gt mail, on purpose

- **`read` marks read.** Read state drives wake-ups and unread counts
  here, so displaying a message acknowledges it. `peek` and `thread`
  change nothing.
- **`inbox` shows unread by default** (`--all` for everything).
- **`check` always exits 0 when the probe worked**, mail or no mail —
  branch on its output or `--json {"unread": N, "has_more": ...}`, not
  the exit code. A nonzero exit is a real failure, never "inbox empty".
  A `gt mail check && notify` hook line must be rewritten.

### Not supported, and why

`mark-unread`, `archive`, `delete`, and `clear` don't exist here: aweb
mail is delivery, not permanent storage — messages cannot be deleted,
and a deployment may garbage-collect them starting around 30 days, so
never treat the mail server as an archive. **The durable record is your
beads graph.**

To have that record kept automatically, turn on dual-write in
`.beads/aweb-mail.toml`:

```toml
[settings]
dual-write = "on"
```

Every message you send is then also recorded as a `type: message` issue
in your beads database (the aweb ids ride its metadata, and replies
thread with `replies-to`). Delivery never waits on it: if the bead
write fails or bd is busy, the mail still goes out and you get a note
about the record gap. `search` has no server-side counterpart yet; `claim`, `release`,
`announces`, and `drain` are orchestrator concepts v1 does not carry.
Each of these says so when you run it, with what to use instead.

## Wake-ups: the optional upgrade

Without anything extra, mail works by polling — `bd mail check` is cheap
and built for hooks:

```bash
bd mail check --inject   # Claude Code PostToolUse hook: injects a note only when mail waits
```

The upgrade is in-session wake-ups: `aw init --setup-channel` installs
the Claude Code channel plugin, and an incoming message wakes the
recipient's session and presents itself — no polling. Priority 0/1 mail
prompts the session; normal mail waits for a natural pause. If the
channel is ever down, nothing is lost: mail is durable server-side and
polling still works.

## What this is and is not

This delegate does **delivery**: durable mail, offline recipients,
cross-machine and cross-organization routing, and cryptographically
verified sender identity.

It is deliberately **not**:

- **replication** — `bd dolt push/pull` is beads' data plane; this
  never touches your issue data;
- **a Team Server alternative** — no org governance here;
- **webhooks** — nothing ever calls into your machines; delivery is
  pull and wake by design.

## For Gas Town users

If you already run `gt mail`, nothing here conflicts: the delegate is
just another `mail.delegate` value. The verb surface is gt-shaped; the
differences that matter are the three listed above. What you gain by
switching a repo over: recipients on other machines and other
organizations with no shared infrastructure, and sender identity that
verifies instead of being asserted.

## One transparency note

Requests the delegate makes to your mail server identify themselves
with a `User-Agent: aw-beads-mail/<version>` header, so server
operators can count delegate usage. Your message content is never
marked or read for that purpose.

## Troubleshooting

- **"no mail delegate configured"** — run the third setup line in the
  repo where you run bd.
- **"X is not mapped to an aweb address"** — add the printed line to
  `.beads/aweb-mail.toml`, or use a full `domain/name` address.
- **Sent but no wake on the other side** — wake needs the channel
  plugin on the recipient's machine (`aw init --setup-channel`); without
  it they'll see the mail on their next `bd mail inbox` or `check`.
- **Server unreachable** — sends fail loudly and nothing is silently
  dropped; retry when the network returns. Received mail waits on the
  server.
- **Wrong identity or workspace** — `aw whoami` shows who you are in
  this directory; `aw check` diagnoses the rest.
- **"not initialized for aw" from `bd mail`** — the bd repo needs its
  own `aw init`, or `AWEB_IDENTITY_HOME` pointing at an existing `.aw`.
- **`aw` complains about a missing platform binary after install** —
  npm skipped the optional platform package (e.g. `--no-optional`);
  reinstall without that flag.
