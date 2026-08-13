# The OATS–aweb seam: Principal, Instance, Session

How this deployment connects OATS instances to aweb identities. The
architecture is defined in
`strategy/product/2026-08-12-resident-identities-and-session-grants.md`; this
document is the operational description for the `oats/` deployment.

## The three entities

- **Principal** — an aweb identity, the unit of cryptographic authority.
  Either *local* (instance-lifetime, one team, `did:key`, no public address)
  or *resident* (durable, `did:aw`, addresses, mailbox history; its root keys
  live in one custody `.aw` home and never enter a worker).
- **Instance** — one OATS incarnation of a soul: a home, a task, a work tree,
  a session.
- **Session** — one live model execution inside an instance.

The binding rule: **an instance never holds more authority than its own
lifetime justifies.** A disposable worker gets a local identity that dies
with it. An instance serving a resident identity gets a session grant that
expires on its own.

## The invariant

A lifecycle hook mints only credentials that expire by themselves. Spawn
mints, retire revokes, TTL cleans up — there is no third cleanup path, no
reconciliation journal, and no cleanup authority an instance has to carry.

## Session grants

A grant is a scoped, expiring, revocable credential derived from a resident
identity:

> Grant G: the bearer may act as identity A for scopes S (`mail.read`,
> `mail.send`, `chat.read`, `chat.send`) on team T until expiry E.

- Minted by the identity itself (`aw id grant mint`, ordinary certificate
  auth, run in the custody home). Minting generates a fresh session keypair;
  the server registers the session `did:key` with the scopes and expiry.
- The worker's grant home contains only `grant.yaml` and the session key.
  Requests are signed per-request with the session key; the server resolves
  them to the subject identity, enforces scope by route, and attributes all
  rows (messages, chat) to the identity.
- Revocation is a soft flag checked on use; `aw id grant revoke <id>` is
  idempotent. A crash anywhere leaves nothing to clean: the grant expires at
  its TTL.
- Grants cannot mint grants, and grant-authenticated requests reach only
  mail, chat, and roster reads. Everything else — team management, leases,
  reservations, workspace lifecycle — requires root certificate auth.

## The capability

`aweb.identity` (owned, `messaging` layer) is the whole seam:

- **spawn** (required): resolves the custody root (`custody-root` setting,
  relative to `OATS_WORKSPACE`; `..` in this deployment — the monorepo root's
  `.aw`), mints a grant labeled `oats:<instance>` into
  `<instance-home>/.aweb-identity`, and contributes
  `AWEB_IDENTITY_HOME=<that dir>` through the OATS launch environment
  contract. `aw` honors that variable natively, so `aw mail`/`aw chat` work
  unchanged inside the instance. The hook is required: every path that mints
  no grant fails the spawn, because an instance that believes it has
  messaging and does not is worse than no instance.
- **retire**: revokes the grant recorded in hook meta. A failed revoke is
  reported as a failure but degrades to bounded exposure, not stranded
  state — the grant still expires.

Settings: `custody-root` (default `.`), `scopes` (default all four), `ttl`
(default `8h`).

## Verb boundary

| Actor | May |
| --- | --- |
| Instance (grant home) | `aw mail`, `aw chat`, roster reads |
| Spawner / operator (custody home) | everything: mint, revoke, team lifecycle, identity lifecycle |

Instances are told this in their injected instructions and briefed with the
identity, scopes, and expiry in `TASK.md`.

## Failure semantics

- Spawn cannot mint → spawn fails and rolls back (required hook).
- Retire cannot revoke → retire reports the failure; exposure is bounded by
  the grant's TTL.
- Grant expires mid-session → `aw` calls fail with the server's
  "grant expired" refusal; the instance reports it and stops messaging. A
  new spawn (or a fresh mint by the operator) is the recovery, never
  credential reuse.
- Custody home missing → mint and revoke both fail loudly; nothing is
  created.

## What this deployment runs

- `messaging: aweb.identity` (owned) with `custody-root: ".."`.
- `tasks: none` — coordination happens over mail and the board.
- `knowledge: none`.
