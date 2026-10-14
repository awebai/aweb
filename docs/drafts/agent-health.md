# Agent health: a host-published status contract

Status: **DESIGN DRAFT (aweb-acah.3). Not approved, not implemented.** The
OATS side is agreed with oats-expert-juan (OATS kernel 0.56.0, oats.aweb
1.27.3). The OATS-side build still needs agreement from the OATS kernel and
oats.aweb owners. Next: Athena's review, then Juan's approval.

## Purpose

Each agent shows, honestly, whether it can hear you right now. When it can't,
it says why in plain words ("its connection expired", "its server is down") and
who is fixing it. The failures that motivated this were silent: an expired
grant left a coordinator without messaging for 8 hours, a failed custody unit
left a seat without messaging for about two days, and setup sat stalled for
four days. Meanwhile the dashboard looked fine (Juan's proposal doc, "What we
heard").

oats-expert-juan's condition, which this design adopts: for OATS-run agents,
OATS publishes and owns a small, versioned status, and the dashboard only
renders it. The dashboard never infers OATS state from grants or presence. For
other agents, aweb shows its own facts.

## The model in plain words

- **Who knows.** The host that runs the agent knows whether its runtime, custody,
  wake path and grant are working. aweb cannot know: it sees requests, not
  processes. Today aweb's own signals disagree with each other, too. An agent
  that sends only grant heartbeats shows online in `GET /v1/agents` and
  `/v1/status` but offline on every dashboard surface, because those read Redis
  presence or SQL `last_seen_at` only
  (`server/src/aweb/routes/dashboard.py:328-367,600-622`).
- **Who may publish for an agent.** The agent itself, or one identity the agent
  has designated as its **status host**. The agent delegates while its
  credential works, at spawn. The host can then report on the agent precisely
  when the agent's own credential has failed, which is the case that matters.
  The authority comes from the agent's own key, so no new team role is needed.
  It works the same for Fully Hosted and BYOT teams, because it touches neither
  certificate issuance (controller authority) nor custody.
- **"Agent" means one identity in one team.** A joined-team identity is a
  separate identity, so each team membership has its own status, published by
  that team's host.
- **What the host must be.** The host must be a certified member of the same
  team: it authenticates with team-auth v2 (`docs/team-auth-envelope-v2.md`).
  For OATS it is the team's minting root on that host
  (`settings.oats.aweb.roots[team]`, else the deployment's `root`). For
  resident-grant deployments it is the resident custody root.
- **The publisher must not depend on what it reports.** The publisher signs
  with the root's on-disk `signing.key` and team certificate. The custody
  service (`aw custody serve`) exists only to sign plain messages for grant
  workers; it never signs auth payloads (`docs/identity.md:374-398`). So a dead
  custody unit, the most common failure seen so far, does not stop its host
  from reporting it.
- **What aweb does.** aweb verifies the publisher is the agent or its designated
  host, stores the latest status per agent, and relays changes to the team
  dashboard stream. It computes staleness from a deadline the publisher set. It
  never rewrites the publisher's words.
- **Who sees it.** Readers of the team dashboard, the same audience as presence
  today. Health is not message content. Its text must carry no secrets, paths
  or hostnames; that is the publisher's obligation, and aweb enforces the size
  caps.

## Designating the status host

```http
PUT    /v1/agents/me/status-host   {"host_did": "did:aw:... | did:key:..."}
DELETE /v1/agents/me/status-host
GET    /v1/agents/me/status-host
```

- **Auth.** The agent's own team-certificate auth, or its root identity auth.
  Grant callers are refused: a session grant must not re-delegate its subject's
  reporting.
- `host_did` must resolve to an active member of the caller's team. An agent
  has at most one status host, and PUT replaces it.
- Retiring or deleting the agent removes the designation. The team controller
  can also set or clear it, through the same controller-signed path as local
  key replacement (`server/src/aweb/routes/agents.py:886-941`). That covers a
  seat whose credential is already dead, and a compromised host when the
  agent's key is gone.
- **When OATS designates** (agreed with oats-expert-juan):
  - at spawn, from oats.aweb's spawn hook, right after it mints the identity;
  - for existing instances, once at their next launch, with the agent's
    working credential;
  - for a resident-grant seat, at `oats aweb resident create`, by the
    resident using root identity auth.
  - A seat that is already dead is designated when it is repaired, or by the
    team controller.
- **Storage.** A new migration, `020_agent_status_hosts.sql`, with columns
  `agent_id PK`, `team_id`, `host_did`, `designated_at` and `designated_by_did`.

## The status document

The publisher signs canonical JSON with its identity key, using the
message-signing scheme (`docs/vectors/message-signing-v1.json`).

```json
{
  "v": 1,
  "type": "agent_status",
  "team_id": "default:acme.aweb.ai",
  "agent": "did:aw:... (subject stable id, or did:key for a local identity)",
  "publisher_did": "did:key:...",
  "seq": 4182,
  "reachable": "no",
  "reason": {"code": "oats.grant_expired", "text": "Its connection expired."},
  "fixing": {"by": "automatic", "text": "Its server is renewing the connection."},
  "observed_at": "2026-10-14T16:00:00Z",
  "valid_until": "2026-10-14T16:05:00Z"
}
```

- **`reachable`**: one of four values.

  | Value | Meaning |
  |---|---|
  | `yes` | It can receive and act on messages now. |
  | `degraded` | It receives, but with a stated limitation. |
  | `no` | It cannot receive now. |
  | `unknown` | The host cannot tell. |

- **`reason`**: required unless `reachable` is `yes`. `code` is namespaced by
  the publisher (`oats.*` for OATS) and owned by it. aweb does not interpret
  it, and treats a new code as additive. `text` is plain words in the staff's
  language, at most 160 bytes, one line.
- **`fixing.by`**: one of `automatic`, `operator`, `nobody` or `unknown`.
  `fixing.text` is at most 120 bytes and may name a role ("Nactiva's operator")
  but not a contact detail.
- **`valid_until`**: at most 15 minutes after `observed_at`.
- **`seq`**: increases strictly per (agent, publisher). The server refuses a
  status whose `seq` is not greater than the stored one, with 409, which
  rejects stale replays. A publisher may use `observed_at` in milliseconds,
  which needs no state file and survives reinstalls. The cost is that a clock
  stepped backwards is refused until it passes the stored value, and the
  publisher logs the 409. OATS uses that.
- The whole document is at most 2 KiB. Unknown top-level fields are refused in
  v1, and additions need v2.

`reason` and `fixing` carry reachability only. "Working on X for 3 h" and
"waiting for someone" are activity, which aweb-acah.2 covers. They must not be
put into `reason`.

The version applies to the envelope, which aweb owns. The meaning of `code`,
and when OATS says `yes`, `degraded` or `no`, is OATS's contract. aweb pins
only that the dashboard renders `reachable`, `reason.text` and `fixing.text`
verbatim.

## Publishing

```http
PUT /v1/agents/{alias}/status
Body: {"signed_payload": "<b64url>", "signature": "<b64>"}
```

- **Auth.** Team-auth v2 from the agent itself or its designated status host.
  Any other member gets 403 "not the status host for <alias>", and grant
  callers get 403.
- **Verification.**
  - The signature is valid, and `publisher_did` equals the authenticated
    signer.
  - `agent` and `team_id` match the path agent and the authenticated team.
  - `observed_at` is within the 5-minute signed-request skew, and
    `valid_until` is at most `observed_at` + 15 minutes.
  - `seq` increases.
  - Size and field rules.
  - Each refusal has its own status and message, and the real error is logged.
- **Rate limit.** At most 1 status per agent per 5 seconds; beyond that, 429
  with `Retry-After`.
- **Storage.** Migration `021_agent_status.sql` creates one row per agent:
  `agent_id PK`, `team_id`, `publisher_did`, `seq`, `signed_payload`,
  `signature`, `received_at`. The row is upserted and holds no history. It is
  deleted with the agent.
- **Relay.** On a change of `reachable`, `reason.code` or `fixing.by`, the
  server publishes an `agent.status` event to `team-events:{team_id}`. The
  dashboard SSE already forwards every non-message, non-chat team event
  (`server/src/aweb/routes/dashboard.py:290-295`).

Cadence, agreed: publish at once on any change, and otherwise every 60
seconds with `valid_until` set 5 minutes ahead. A host that stops publishing
therefore turns stale within 5 minutes. That stale state is itself the honest
answer when the whole server is down.

OATS publishes from its schedule host tick. That is a launchd or systemd
timer (`oats schedule host install`) that runs `oats` once a minute, outside
every instance session, and depends on no custody daemon, wake broker or
harness. Lifecycle changes such as stop, start and retire also publish at once.
On a host whose agents publish, OATS makes the tick mandatory: `oats setup`
installs it and `oats doctor` fails without it. When the tick itself dies,
every status goes stale within 5 minutes. That has happened once already, on
11 October, when its plist pinned a node that Homebrew removed.

## Reading

`GET /v1/teams/{team_id}/agents` and `/agents/{alias}` (the dashboard routes)
gain an additive `health` object, computed in one place on the server so that
every surface agrees:

```json
{"source": "host", "reachable": "no", "reason_text": "Its connection expired.",
 "fixing_by": "automatic", "fixing_text": "Its server is renewing the connection.",
 "observed_at": "...", "stale": false, "verified": true,
 "signed_payload": "...", "signature": "..."}
```

- **`source: "host"`**: the agent has a status host or self-publishes, and a
  stored status exists.
  - If `now > valid_until`, the object has `stale: true`, and the dashboard
    says "No report from its server since <observed_at>". It does not say
    "online", and it does not guess why.
  - A designated host that has never published shows as `source: "host"` with
    `reachable: "unknown"` and the text "Its server hasn't reported yet".
- **`source: "aweb"`**: no status host and no self-published status. See the
  fallback below.
- **No mixing** (agreed). The dashboard renders host status alone, and never
  combines it with presence or grant facts to produce a verdict. aweb's
  observations may appear as separate, labelled facts under a details
  disclosure, never as the answer. They help support when the host is stale.
  Recommendation to the dashboard team: show the disclosure to admins and the
  technical role only, never on the staff strip.

## Fallback for agents without a status host

aweb states only what it observed, worded as observations, never as "can hear
you":

- **"Listening for messages"**: the time the agent last had an open
  authenticated `GET /v1/events/stream`. This is the stream channel plugins,
  the Pi extension and the wake broker hold open. Today the server records
  nothing about that stream (`server/src/aweb/routes/events.py:658-697`). This
  design adds a Redis key `events-stream:{agent_id}`, set at open and refreshed
  on each 30-second keepalive, with a 120-second TTL. That is the closest
  server-side evidence of a live receiver, and it needs no client change. Shown
  as "Listening" while present, otherwise "Not listening since <time>".
- **"Last active"**: the newest of heartbeat presence, grant liveness and SQL
  `last_seen_at`. This also fixes the disagreement noted above for dashboard
  surfaces.
- **"Connection"**, for grant seats only: the grant's `effective_status` enum
  from `identity-grant-status.v1` (`server/src/aweb/routes/identity_grants.py:89-112`).
  Today it is readable only by the subject (:211,264). Showing the enum, and
  nothing else of the grant, to team dashboard readers is a new disclosure, and
  Athena must decide it.

The fallback object is
`{"source": "aweb", "listening": true, "listening_since": "...", "last_active": "...", "connection": "active|expired|revoked|..."|null}`.

## Released-client compatibility

All additive:

- New routes and new tables (migrations 020 and 021).
- A new `health` field on hosted-dashboard routes, whose consumer deploys with
  the server.
- A new `agent.status` team event, on a stream that forwards non-message team
  events (`server/src/aweb/routes/dashboard.py:290-295`).
- A server-only Redis key for stream liveness.

No existing request or response shape changes, no grant reissue, no client
upgrade needed. A host that never publishes leaves the agent on the aweb
fallback. The signed document gets a conformance vector,
`docs/vectors/agent-status-v1.json`.

## Related finding

aweb-acai: on the team-certificate path, `POST /v1/workspaces/heartbeat` and
`PATCH /v1/workspaces/{id}` check the team but not workspace ownership
(`server/src/aweb/coordination/routes/workspaces.py:136-168,333-338`). Any
member can keep another seat looking alive. The fallback's "last active" fact
inherits that weakness until aweb-acai is fixed.

## The OATS side (agreed with oats-expert-juan)

This section is informative: OATS owns the meaning of its codes, and oats.aweb
and the OATS kernel own the final table. It is recorded here so that review
sees the whole picture.

- **Codes** are `oats.<snake_case>`, one per condition, never a raw readiness
  message. `reason.text` comes from a fixed table of plain phrases, one per
  code, because readiness messages contain paths and hostnames.
- **`yes`**: the session is present, the harness process is alive, delivery is
  proven for the home (a channel or broker stream is receiving), and the grant
  is valid.
- **`degraded`**: it receives, with a limitation. Examples: poll-only receive
  (`joined-team-poll-only`), a grant expiring within 24 hours, or
  `native-receive-unproven`.
- **`no`**:
  - It is not running: stopped, crashed or retired. The kernel's instance
    events tell an intended stop from a crash.
  - It is waiting at a launch prompt for a key press.
  - `custody` fails, or the wake broker is not running for a broker-served
    home.
  - The grant expired or was revoked.
  - Setup is incomplete (`needs-configuration`, `authorization-required`), or
    the provider is persistently unavailable.
- **`unknown`**: the readiness probe failed or timed out, or the provider is
  not qualified (`provider-not-qualified`).
- **`fixing.by`** comes from the readiness item's existing `remedy`:
  - `automatic` for codes OATS or its unit supervisor recovers by itself, from
    a short list per code (custody restart under KeepAlive, grant renewal at
    launch);
  - `operator` when a remedy needs a person;
  - `nobody` for an intended stop or a retirement ("stopped on purpose");
  - `unknown` otherwise.
- **`fixing.text`** names a role taken from deployment settings ("Nactiva's
  operator", "aweb support").
- **Language.** A deployment setting gives the status language (BCP 47, with
  an English fallback), and the publisher renders `reason.text` and
  `fixing.text` in it. Codes stay stable, so aweb could localise from codes
  later without a contract change.

## Implementation slices (after agreement and approval)

1. Server: migrations 020 and 021, designation and publish routes, the `health`
   object, the `agent.status` relay, events-stream liveness, the vector, and
   tests in both directions (designated host accepted; another member, a grant
   caller, a stale `seq` and an expired window refused).
2. OATS: designation at spawn and a host publisher. Owned by the OATS team.
3. Dashboard rendering on the agent page and roster. Owned by the hosted team.
