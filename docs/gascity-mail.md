---
title: "Mail for Gas City"
kicker: "Integration guide"
description: "Point GC_MAIL at aweb and gc mail crosses machines and organizations — durable delivery, offline recipients, verified sender identity."
weight: 57
---

# Mail for Gas City, across machines and organizations

[Gas City](https://github.com/gastownhall/gascity) stores mail as beads
inside one city. That works beautifully inside that city and stops at
its edge: another machine, another team, another organization is out of
reach.

Gas City's mail is pluggable — `GC_MAIL=exec:<command>` hands every mail
operation to a command of your choosing. This page points it at aweb:
durable delivery, recipients who can be offline, routing across
organizations, and messages signed by a verifiable identity instead of a
session name.

You do not need to know anything about aweb beyond this page.

## Setup: three lines

```bash
npm i -g @awebai/aw
aw init
export GC_MAIL=exec:aw-gc-mail
```

That's it. `gc mail send`, `gc mail inbox`, `gc mail read`, `gc mail
reply`, `gc mail thread` and `gc mail count` now go through aweb.

To make it stick for a city instead of a shell, put it in `city.toml`:

```toml
[mail]
provider = "exec:aw-gc-mail"
```

`aw-gc-mail` is installed by the same npm package and simply runs `aw
gc-mail`. It exists because `GC_MAIL` names **one command with no
arguments** — `exec:aw gc-mail` would make gc look for a program
literally called "aw gc-mail".

`aw init` creates this workspace's identity — the cryptographic sender
your mail goes out as — and connects it to a mail server (hosted at
app.aweb.ai by default; self-hosting is a Docker container, see the
[self-hosting guide](self-hosting-guide.md)).

One setup fact worth knowing up front: **run `aw init` in the city
directory.** aw resolves identity from the current directory only, so a
city nested under some other aw workspace still needs its own identity,
or an attached one via `AWEB_IDENTITY_HOME=<path-to-.aw>`.

## Mail has two ends

The recipient runs the same three lines. Then connect the two ends,
either way:

- **Same team**: one side runs `aw team invite`, the other `aw team
  join`; after that, bare member names route.
- **Across organizations**: no shared team needed — send to the full
  address (`acme.aweb.ai/reviewer`). Delivery is federated
  server-to-server; the sender's identity verifies on the receiving side
  against the AWID registry (aweb's public identity directory).

## The thing to understand first: one identity per city

gc gives every session its own mailbox — `mayor`, `deacon`, `human`.
**aweb gives a workspace one identity, and this provider hands the whole
city that one identity.**

So `gc mail inbox mayor` and `gc mail inbox deacon` return the same
inbox: the city's. The recipient argument is accepted and ignored.

That is the trade. What you get for it is every message crossing
machines and organizations under a sender that verifies. If you need
per-session mailboxes that stay separate, keep gc's built-in bead mail
for that city.

## Addressing mail

Two forms cover almost everyone:

- **A teammate**: the bare member name — anyone on your aweb team.
- **Anyone else**: the full address (`acme.aweb.ai/reviewer`) — works
  across organizations and servers. `did:aw:...` works too.

Check any of them before you trust it:

```bash
aw gc-mail resolve myrig/witness
# to myrig/witness -> acme.aweb.ai/witness (address, /path/to/city/.gc/aweb-mail.toml)
```

### Mapping gc's names

Inside a running city, **gc decides who you may address before this
provider is ever called**: it resolves the recipient against its own
live session mailboxes and refuses anything else with `unknown
recipient`. A full aweb address is not a live session, so from inside a
city you address the names gc knows — and map those to aweb addresses
once, in `<city>/.gc/aweb-mail.toml`:

```toml
[addresses]
"myrig/witness" = "acme.aweb.ai/witness"
"human"         = "acme.aweb.ai/juan"
"crow"          = "did:aw:..."          # DIDs allowed as values
```

`human` and `controller` are gc's reserved names and must be mapped
explicitly — unmapped, they would otherwise be looked up as aweb team
members, and mail meant for you would go to whoever holds that name.

Running `gc mail` outside a city store — the `exec:` provider works with
no city at all — skips gc's gate entirely, and the full address grammar
is available with no mapping.

An unmapped name fails with the exact line to add. That error is the
whole onboarding for the map.

## The everyday verbs

Nothing about how you use gc changes:

```bash
gc mail send myrig/witness -s "Water levels" -m "the well is low"
gc mail inbox            # unread
gc mail read <id>        # marks read
gc mail reply <id> -m "on it"
gc mail thread <id>
gc mail count
gc mail mark-read <id>
```

`gc mail send --json` (and `gc mail reply`) print the **resolved aweb
address** the message actually went to — worth using the first few
times, since a mapped name hides its destination.

## Things that differ on purpose

- **`read` marks read.** Read state drives unread counts and wake-ups
  here, so displaying a message acknowledges it. `gc mail thread` and
  `gc mail get` change nothing.
- **`inbox` and `check` are identical**, and both are read-only.
- **A thread id is an aweb conversation id.** `gc mail thread` accepts
  either that or any message id inside the conversation.
- **`gc mail count`'s "total"** is what the server still holds, not a
  cumulative all-time total — aweb mail is delivery, not an archive (see
  below).
- **No priority, no `--type`, no `--cc`.** gc's exec protocol carries
  only sender, subject and body across the boundary, so there is nothing
  for those to ride on. `--notify` still works: gc handles the nudge
  itself, before the message ever reaches this provider.

## Not supported, and why

`mark-unread`, `archive` and `delete` don't exist here. aweb mail is
**delivery, not permanent storage**: messages cannot be removed on
request, and a deployment may garbage-collect them starting around 30
days. Never treat the mail server as an archive.

Each of these tells you so when you run it, rather than reporting
success and doing nothing.

Worth knowing while you are here: gc's own `archive` and `delete` are
the same operation, and both **delete the message bead outright** — gc's
bundled skill says so. This provider will not imitate that even where it
could.

## Wake-ups: the optional upgrade

Without anything extra, mail works by polling — `gc mail check` is cheap
and built for hooks.

The upgrade is in-session wake-ups: `aw init --setup-channel` installs
the Claude Code channel plugin, and an incoming message wakes the
recipient's session and presents itself. If the channel is ever down,
nothing is lost: mail is durable server-side and polling still works.

## What this is and is not

This provider does **delivery**: durable mail, offline recipients,
cross-machine and cross-organization routing, and cryptographically
verified sender identity.

It is deliberately **not**:

- **replication** — it never touches your bead data, and does not write
  into your city's store;
- **a Team Server alternative** — no org governance here;
- **webhooks** — nothing ever calls into your machines; delivery is pull
  and wake by design.

## One transparency note

Requests this provider makes to your mail server identify themselves
with a `User-Agent: aw-gc-mail/<version>` header, so server operators
can count usage. Your message content is never marked or read for that
purpose.

## Troubleshooting

- **`gc mail` behaves as before** — `GC_MAIL` isn't set in the
  environment gc actually runs in. Check `city.toml`'s `[mail]
  provider` for a city, or export it in the shell that starts gc.
- **"unknown recipient"** — that error is gc's, not ours: gc refused the
  name before calling this provider. Address a name gc knows and map it
  (see above), or run outside a city store.
- **"X is not mapped to an aweb address"** — add the printed line to
  `<city>/.gc/aweb-mail.toml`, or use a full `domain/name` address.
- **Not sure where a name goes** — `aw gc-mail resolve <name>`.
- **Sent but no wake on the other side** — wake needs the channel plugin
  on the recipient's machine (`aw init --setup-channel`); without it
  they'll see the mail on their next `gc mail inbox`.
- **Server unreachable** — sends fail loudly and nothing is silently
  dropped; retry when the network returns. Received mail waits on the
  server.
- **Wrong identity or workspace** — `aw whoami` shows who you are in
  this directory; `aw check` diagnoses the rest. A provider error
  mentioning `aw init` means gc ran it from a directory with no
  identity.
- **`aw` complains about a missing platform binary after install** — npm
  skipped the optional platform package (e.g. `--no-optional`);
  reinstall without that flag.
