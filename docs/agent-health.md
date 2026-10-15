# Agent health: a host-published status contract

Status: **approved by Juan on 2026-10-14 (aweb-acah.3).** Designating the
status host is implemented. Publishing, reading and the fallback follow in
order. The signed document's wire bytes are frozen in
[`docs/vectors/agent-status-v1.json`](vectors/agent-status-v1.json), agreed with
the OATS publisher before either side implemented it.

## Purpose

Each agent shows, accurately, whether it can hear you right now. When it can't,
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
PUT    /v1/agents/me/status-host   {"host_did": "did:key:z..."}
DELETE /v1/agents/me/status-host
GET    /v1/agents/me/status-host
```

- **Auth.** The agent's own team-certificate auth. A resident identity
  designates with its own team certificate, which its custody root holds.
  Grant callers are refused with 403 "outside grant scope": a session grant
  must not re-delegate its subject's reporting.
- `host_did` is the host's signing `did:key`, the only key the server verifies
  on publish. A `did:aw` is refused, so one host never has two names. When the
  host's key rotates, the agent or the controller designates the new key.
- `host_did` must belong to an active (not deleted) member of the caller's
  team. An agent has at most one status host, and PUT replaces it.
- Every route answers with the same object:

  ```json
  {"agent_id": "...", "team_id": "...", "alias": "alice",
   "host_did": "did:key:z... | null", "designated_at": "... | null",
   "designated_by_did": "did:key:z... | null", "host_active": true}
  ```

  `host_active` is null when no host is designated, and false when the host is
  no longer an active member. DELETE is idempotent.

  Refusals use the codes in "Refusal codes" below.
- **One publisher at a time.** While a status host is designated, only that
  host may publish for the agent. The agent self-publishes only when no host is
  designated. Replacing or clearing the designation deletes the stored status
  row, so the old publisher's last report does not survive and `seq` starts
  fresh for the new publisher.
- If the designated host is no longer an active member of the team, reads
  treat the agent as having no host (the aweb fallback). The dashboard does not
  show that host's last report.
- Retiring or deleting the agent removes the designation (the lifecycle
  cascade, `server/src/aweb/lifecycle.py`).
- **The team controller** can also set or clear it. That covers a seat whose
  credential is already dead, and a compromised host when the agent's key is
  gone. The request is signed by the team's controller `did:key`, as for local
  key replacement (`POST /v1/agents/{alias}/replace-key`):

  ```http
  PUT /v1/agents/{alias}/status-host
  Authorization: DIDKey <team controller did:key> <signature>
  X-AWEB-Timestamp: <RFC 3339>
  {"team_id": "...", "host_did": "did:key:z...", "previous_host_did": ""}
  ```

  The signature covers the canonical JSON of `operation`
  (`set_agent_status_host`), `team_id`, `agent_alias`, `host_did`,
  `previous_host_did` and `timestamp`. An empty `host_did` clears.
  `previous_host_did` must equal the current host (empty for none), otherwise
  409 `status_host_changed`, so a replayed controller request cannot undo a
  later designation. Any other signer gets 403 `controller_required`.
- **When OATS designates**:
  - at spawn, from oats.aweb's spawn hook, right after it mints the identity;
  - for existing instances, once at their next launch, with the agent's
    working credential;
  - for a resident-grant seat, at `oats aweb resident create`, by the
    resident with its own team certificate.
  - A seat that is already dead is designated when it is repaired, or by the
    team controller.
- **Storage.** Migration `020_agent_status_hosts.sql`: one row per agent with
  `agent_id` (primary key), `team_id`, `host_did`, `designated_at` and
  `designated_by_did`.

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

- **`agent`**: the subject's `did:aw` when it has one, otherwise its `did:key`.
  The server compares it with the path agent's own record, so each agent has
  exactly one accepted name.
- **`publisher_did`**: the signer's `did:key`. It must equal the authenticated
  signer and, while a host is designated, `host_did`.
- **`reason`**: required unless `reachable` is `yes`. `code` is namespaced by
  the publisher (`oats.*` for OATS) and owned by it: at most 64 bytes, matching
  `^[a-z][a-z0-9]*\.[a-z0-9_]+$`. aweb does not interpret it, and treats a new
  code as additive. `text` is plain words in the staff's language, at most 160
  bytes.
- **`fixing`**: required unless `reachable` is `yes`. `fixing.by` is one of
  `automatic`, `operator`, `nobody` or `unknown`. `fixing.text` is optional, at
  most 120 bytes, and may name a role ("Nactiva's operator") but not a contact
  detail.
- **Types**: a present field must have its type. An explicit `null` is not
  an absent field: it is refused as `invalid_value`, as is any non-string
  `reachable` or `fixing.by`.
- **Timestamps**: `observed_at` and `valid_until` are exactly
  `YYYY-MM-DDTHH:MM:SSZ`, with no fractional seconds.
- **`valid_until`**: at most 15 minutes after `observed_at`.
- **`seq`**: a JSON integer from 1 to 2^53-1, never a float or a boolean. It
  increases strictly for the agent's current publisher (there is
  only one; see "One publisher at a time"). The server refuses a
  status whose `seq` is not greater than the stored one, with 409, which
  rejects stale replays. A publisher may use `observed_at` in milliseconds,
  which needs no state file and survives reinstalls. The cost is that a clock
  stepped backwards is refused until it passes the stored value, and the
  publisher logs the 409. OATS uses that.
- The whole document is at most 2 KiB. Unknown fields are refused in v1, at
  the top level and inside `reason` and `fixing`, and additions need v2. Every
  text field is one line with no control characters. The server enforces the
  byte caps after UTF-8 encoding.
- **Check order** matters only when a document has several faults: size is
  checked before parsing, canonical bytes before fields, and `type` before any
  other field. The vector gives each refusal its code.

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

Response: `{"agent_id": "...", "alias": "alice", "seq": 1792080000000}`.

- **Auth.** Team-certificate auth from the agent's designated status host, or
  from the agent itself only when no host is designated. Any other member, and
  the agent itself while a host is designated, gets 403 `not_status_host`. Grant callers get 403 `outside grant scope`. A host that is no
  longer a member cannot authenticate at all.
- **Verification**, in this order: the document rules of the vector
  (canonical bytes, type, fields, caps), `publisher_did` equals the
  authenticated signer, the signature verifies with that key, the validity
  window, the clock skew and expiry; then `team_id` is the authenticated team,
  `agent` names the path agent, and `seq` is greater than the stored one. The
  authority check is repeated inside the storing transaction, which locks the
  agent row as designation changes do, so a report cannot land after its
  publisher lost the designation.
- **Refusals** use the codes in "Refusal codes" below. Each is logged with
  the signer and the reason.
- **Rate limit.** At most 1 publish attempt per agent per 5 seconds, counted
  in Redis (`agent-status-rate:{agent_id}`) after the authority check, so
  another member cannot use up the agent's window. Status publishes and
  designation calls are not messages: they do not count against message
  allowances or message-rate counting, as for agent activity (aweb-acah.2).
- **Storage.** Migration `021_agent_status.sql`: one row per agent with
  `publisher_did`, `seq`, `reachable`, `reason_code`, `fixing_by`,
  `observed_at`, `valid_until`, `signed_payload`, `signature` and
  `received_at`. The copied fields serve change detection; the signed payload
  is the authority. The row is upserted and holds no history. It is deleted
  when the agent is retired, deleted or archived, and when the designation
  moves to a different publisher or is cleared.
- **Relay.** When `reachable`, `reason.code` or `fixing.by` differs from the
  stored row, including the agent's first status, the route fires the
  `agent.status` mutation hook ([hook seam](aw-hooks-sot.md)). The built-in
  handler publishes it to `team-events:{team_id}` as:

  ```json
  {"type": "agent.status", "team_id": "...", "agent_id": "...", "alias": "alice",
   "reachable": "no", "reason_code": "oats.grant_expired",
   "reason_text": "Its connection expired.", "fixing_by": "automatic",
   "fixing_text": "Its server is renewing the connection.",
   "observed_at": "...", "valid_until": "...", "timestamp": "..."}
  ```

  The dashboard SSE forwards every non-message, non-chat team event
  (`server/src/aweb/routes/dashboard.py`).

### Refusal codes

Every refusal the status routes own has the body
`{"detail": "<code>: <message>"}`. The code is the text before the first
`": "`, matches `^[a-z_]+$`, and is stable; the message is plain words and may
change. Refusals from shared authentication (certificate failures, grant
callers' 403 `outside grant scope`) and FastAPI request validation (a 422
whose detail is a list) carry no code: clients treat those as auth or request
shape errors.

| Code | Status | Routes | Meaning |
|---|---|---|---|
| `host_not_did_key` | 422 | status-host | `host_did` is not a `did:key` |
| `host_not_member` | 422 | status-host | `host_did` is not an active member of the team |
| `status_host_changed` | 409 | controller status-host | `previous_host_did` is not the current host |
| `controller_required` | 403 | controller status-host | the signer is not the team controller |
| `invalid_request` | 422 | controller status-host | the alias is empty |
| `invalid_team_id` | 422 | controller status-host | `team_id` does not parse |
| `team_not_found` | 404 | controller status-host | unknown team |
| `agent_not_found` | 404 | controller status-host, status | unknown agent alias in the team |
| `not_status_host` | 403 | status | the caller is not the agent's publisher |
| `rate_limited` | 429 | status | more than one publish in 5 seconds; `Retry-After` gives the wait |
| `publishing_unavailable` | 503 | status | the server has no Redis for rate limiting and relay |
| `malformed_payload` | 422 | status | `signed_payload` is not unpadded base64url of a JSON object |
| vector codes | 422 | status | every `error` in `docs/vectors/agent-status-v1.json` except `stale_seq` |
| `team_mismatch` | 422 | status | `team_id` is not the authenticated team |
| `agent_mismatch` | 422 | status | `agent` does not name the path agent |
| `stale_seq` | 409 | status | `seq` is not greater than the stored one |

Cadence, agreed: publish at once on any change, and otherwise every 60
seconds with `valid_until` set 5 minutes ahead. A host that stops publishing
therefore turns stale within 5 minutes. That stale state is itself the correct
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
 "observed_at": "2026-10-14T16:00:00Z", "valid_until": "2026-10-14T16:05:00Z",
 "stale": false, "verified": true, "signed_payload": "...", "signature": "..."}
```

- **`source: "host"`**: the agent has a status host or self-publishes, and a
  stored status exists.
  - Every key above is always present. `reachable`, `reason_text`,
    `fixing_by`, `fixing_text`, `observed_at` and `valid_until` are the signed
    document's values, verbatim; the three optional ones are `null` when the
    document omits them (a `yes` report carries no reason). `signed_payload`
    and `signature` are exactly what the publisher sent, so a reader can check
    the signature itself. `verified: true` says the server verified them when
    it stored the report.
  - If `now > valid_until`, the object has `stale: true`, and the dashboard
    says "No report from its server since <observed_at>". It does not say
    "online", and it does not guess why.
  - The `agent.status` event fires only on a change, so nothing fires when
    `valid_until` passes. The dashboard therefore computes staleness from
    `valid_until` on its own clock, and the server computes it again on every
    read.
  - A designated host that has never published shows as `source: "host"` with
    `reachable: "unknown"`, `reason_text` "Its server hasn't reported yet",
    `stale: false`, `verified: false`, and `null` for every other key.
- **`source: "aweb"`**: no status host and no self-published status, or a
  designated host that is no longer an active member of the team (a host that
  left speaks for no one, even if a report it published is still stored). See
  the fallback below.
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
  Today it is readable only by the subject (:211,264). Athena approved this new
  disclosure, with limits:
  - only the enum, and only on the team dashboard routes;
  - nothing else from the grant: no grant id, label, scopes, issuer or expiry
    time;
  - when a seat holds several grants for the team, it is `active` if any
    non-revoked grant is active, otherwise the status of the newest grant.

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
`docs/vectors/agent-status-v1.json`. It includes cross-type negatives: a signed
mail payload is refused as a status, and a status payload is refused by
message verification.

## The OATS side

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
