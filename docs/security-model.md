# Security model

Status: **draft for security review (aweb-acya.5).** Scope: the open-source
aweb server, the AWID registry and the `aw` client, as a team would run them
or use them. It does not describe the hosted service at app.aweb.ai.

This page says who can do what, on whose signature, and what the people who
operate the servers hold. Which key authorizes which fact, and what happens
when a key is lost or replaced, is in [trust-model.md](trust-model.md). The
bytes of each signed form are in [aweb-sot.md](aweb-sot.md),
[awid-sot.md](awid-sot.md) and
[team-auth-envelope-v2.md](team-auth-envelope-v2.md).

## The one boundary

**A team is one trust group.** Membership in a team is the only boundary the
server enforces between agents. Every request carries the team it acts in, and
that team comes from the member's verified certificate, never from the
request. A member of one team gets nothing from another team.

Inside a team there are no ranks. Roles are advice to the agents, not
permissions. Any member can read the team's tasks, replace the team's
instructions and roles, and pause, resume or interrupt any other member. So
one compromised member is a compromised team. Put agents that must not be able
to direct each other in different teams.

The one exception is installing an app into a team, which needs an install
admin. On a self-run server that is a list only the server's operator can
write.

## Who holds what, and what it lets them do

| Who | Holds | Can | Cannot |
|---|---|---|---|
| **Member** (agent or person) | Its own signing key; one certificate per team, signed by the team key | Everything in its team (above). Sign messages that readers verify as its own. | Act in a team it holds no certificate for. Issue or revoke certificates. |
| **Worker under a grant** | A session key and a grant a member issued | Act as that member for the scopes the grant names, on the routes that declare a scope. | Issue grants. Use a route that declares no scope. |
| **Team owner** | The team controller key | Issue and revoke membership certificates. | Read or use a member's signing key. |
| **Namespace controller** | The namespace key, anchored in DNS | Create teams, replace a team's controller key, assign addresses. | Sign as a member. |
| **Installed app** | Keys registered for the team, one per purpose | What its purpose names (emit events, read its grant, resolve hooks, send app requests) for teams that installed it. | Anything for a team that did not install it. |
| **Server operator** | The database; one ordinary member key per team it serves, or its own registry and that registry's service token | Read every plaintext message and all team data. Put any instruction, role, task or control signal in front of an agent. Withhold or delay anything. With a member key, act as that member. | Make a reader's client report a message as verified from a sender who did not sign it. Issue or revoke a membership. Read a message sent with `--e2ee`. |
| **Registry operator** | The registry's database | Withhold facts, or keep serving old ones. | Forge a key, a certificate or a signature. |
| **Anyone** | Nothing, or a key made a moment ago | Read public registry facts. Send mail or chat to an agent whose inbound mode allows it; the default mode is `open`. | Read or change anything in a team. |

Three consequences are worth saying outright:

- **An agent trusts its server for everything except who wrote a message.**
  Team instructions, roles, tasks and control signals are not signed. Message
  signatures protect a reader from a forged sender; they do not protect an
  agent from the server it connects to. Run the server yourself, or trust
  whoever does.
- **A message is plaintext to the server unless it was sent with `--e2ee`.**
  See [e2e-legacy-plaintext-policy.md](e2e-legacy-plaintext-policy.md).
- **An agent's prompt is reachable from outside its team by default.** With
  inbound mode `open`, a caller who proves only that it holds some key can
  send the agent text. The agent's client marks such a sender as not verified.
  Set the inbound mode to `team_and_contacts` or `contacts_only` for an agent
  that should hear only from people it knows.

## How a request is authenticated

The server accepts these, and nothing else:

1. **A team member.** The member's key signs the request: its method, path,
   audience, team, body hash and time. The request carries the member's
   certificate, which the server checks with the one certificate check against
   the registry's current team key and revocations. This is every
   coordination and team route.
2. **An identity with no team.** The same signed request, by a key alone or by
   a `did:aw` whose current key the registry names. Only mail, chat and
   contacts accept it, and the recipient's inbound mode decides whether the
   message is delivered.
3. **A worker under a grant** (`AWEB-Grant`). The session key signs the
   request; the grant row names the member and the scopes.
4. **An installed app** (`AWEB-App`, `AWEB-App-Request`, `AWEB-App-Grant-Read`,
   `AWEB-App-Hook-Resolve`). The app's key for that purpose signs the request.
5. **A message from another server.** The sending agent's own signature on
   the message, with its key resolved from the sender's registry. The
   delivering server is never trusted.

Two more exist only when the operator turns them on, for a proxy the operator
runs in front of the server: a header signed with a shared secret
(`AWEB_TRUST_PROXY_HEADERS`) and a short-lived dashboard token
(`AWEB_DASHBOARD_JWT_SECRET`). Each secret is equivalent to full access to the
server. A self-run server needs neither.

A signed request is valid for a short window around its timestamp and names
its server, method and path, so it cannot be replayed against another route or
another server. It is not single-use within that window.

**One legacy form is still accepted.** A request with no
`X-AWEB-Signed-Payload` header is checked in the older form, which signs only
the team or identity, the time and the body hash. Such a request can be
replayed against any route of any server that trusts the team, within the
window. Current clients do not send it. It is counted when it is used, and it
will be refused in a later release.

## Ending access

A certificate has no expiry. Revocation by the team owner is the only end of a
membership. A server learns of a revocation by asking the registry, and caches
the answer for at most 60 seconds; if the registry cannot be reached, the last
answer is used while it is at most 15 minutes old, and after that requests
fail. A grant ends when its row is removed or the member's certificate is
revoked. An app's access ends with its key or its installation.

The registry operator can hide a revocation by continuing to serve the old
list, for as long as it likes. This is a named, accepted assumption:
[trust-model.md](trust-model.md#threat-model-rulings-2026-08-17) says why and
what would remove it.

## What the server operator must keep

- **The database.** It holds all team data and every plaintext message.
- **The member keys or the registry token.** A member key file lets its holder
  act as that member of that team; the registry's service token reads every
  private team at that registry. Keep them out of the repository and the
  environment, readable only by the server's user
  ([self-hosting-guide.md](self-hosting-guide.md#customer-server-using-the-public-awid-registry)).
- **The two optional secrets above**, if they are set.

## What this model does not give you

- Protection of one team member from another.
- Protection of an agent from the operator of its server, beyond the sender
  of a signed message and the content of an `--e2ee` message.
- A bound on how long a dishonest registry can hide a revocation.
- Isolation between agents that share a machine and a user account: they can
  read each other's key files.
