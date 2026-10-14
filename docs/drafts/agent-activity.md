# Agent activity: a signed, ephemeral, opt-in status stream

Status: **DESIGN DRAFT for review (aweb-acah.2). Not approved, not
implemented.** Security review by Athena, then approval by Juan. Nothing in this
document is a shipped contract.

## Purpose

A person chatting with an agent in the dashboard sees nothing during the agent's
turn, which can run from tens of seconds to minutes. This contract lets the agent's
host publish a short, signed account of what the agent is doing ("reading
files", "running tests", "writing reply"). The other participants of the chat
the agent is serving see it live.

Athena's constraints (epic aweb-acah, task aweb-acah.2) are the design's
boundaries:

- it is a new signed aweb event type, opt-in per agent by the host owner;
- status comes first: a phase, a tool name and a one-line summary;
- partial output comes later, as a narrower explicit opt-in with host-side
  redaction (out of scope here; see "Not in this contract");
- it is ephemeral, with a short TTL, and is never stored as mail;
- it is size-capped and rate-limited;
- it is readable by the server, like dashboard chat; nothing claims or implies
  end-to-end protection.

## The model in plain words

- **Custody.** The agent's signing key stays where it is today: in the agent's
  home on the host, or with the resident custody for a grant seat. The host
  produces activity from the agent runtime's own lifecycle hooks and signs it
  with the agent's existing credential. aweb receives no new key, and no new
  authority over the host.
- **Who decides publishing.** Only the host owner, through host-side
  configuration in the agent's home. Nothing in aweb, the team controller or the
  dashboard can turn publishing on. aweb cannot instruct a host to start
  emitting: no route, flag or control signal does that. This is the property
  that makes the stream safe to show (Juan's proposal doc, Athena: "it grants
  no authority over the host").
- **Who sees it.** The participants of the chat session the turn is serving.
  This is the same set that may read that session's messages
  (`server/src/aweb/routes/chat.py:2370-2397`, participant check at :2395-2397).
  Team or dashboard access alone is not participation (`docs/aweb-sot.md`,
  "Dashboard auth": "dashboard team access is not participation"), and that
  rule holds here unchanged.
- **What the server does.** It authenticates the emitter, verifies the
  signature binds to that emitter, enforces size and rate limits, and relays
  the event to open opted-in chat streams. It keeps only the latest event per
  agent, in Redis, for at most 60 seconds, so a viewer who opens the chat
  mid-turn sees the current state. Nothing is written to Postgres, mail, chat
  history or app events.

## Event shape

The emitter builds a canonical JSON object and signs it exactly as a chat
message from the same caller is signed: Ed25519 over sorted-key, no-whitespace
canonical JSON, the scheme pinned by `docs/vectors/message-signing-v1.json`.
For a grant seat it uses the grant session key, as in
`test-vectors/identity-grant-auth-v1.json`.

```json
{
  "v": 1,
  "type": "agent_activity",
  "from_did": "did:key:z6Mk...",
  "from_stable_id": "did:aw:...",
  "team_id": "default:acme.aweb.ai",
  "session_id": "uuid-of-chat-session-or-null",
  "turn_id": "opaque emitter turn id",
  "seq": 17,
  "phase": "tool",
  "tool": "Bash",
  "summary": "Running pytest",
  "timestamp": "2026-10-14T16:20:00Z",
  "expires_at": "2026-10-14T16:21:00Z"
}
```

Fields:

- `phase`, required, one of the following. An unknown phase is refused at
  ingress, and new phases are additive.

  | Phase | Meaning |
  |---|---|
  | `turn_started` | The turn has started. |
  | `thinking` | The model is reasoning; no tool is running. |
  | `tool` | A tool is running; `tool` is required. |
  | `waiting_permission` | Blocked on a permission prompt on the host. |
  | `writing` | Composing the reply. |
  | `turn_ended` | The turn is over; clears the live state. |

- `tool`: optional. The runtime's tool name, at most 64 bytes, matching
  `[A-Za-z0-9_.:-]+`. MCP tool names keep their server prefix.
- `summary`: optional. One line, at most 120 bytes, with no control
  characters. See "What a summary may contain".
- `session_id`: the chat session the turn serves, or `null` when the turn
  cannot be attributed to a chat session (see "Attribution").
- `turn_id` and `seq`: `seq` increases monotonically within `turn_id`.
  Consumers discard an event whose `seq` is not greater than the last one they
  showed for that `turn_id`. This tolerates reordering and replay.
- `expires_at`: at most 60 seconds after `timestamp`. A consumer stops showing
  an event at `expires_at` even if `turn_ended` never arrives, for example
  after a host crash.
- The signed object is at most 1 KiB, and the request body at most 2 KiB.
- There is no output, transcript, file-content or argument field. Version 1
  refuses unknown fields, so partial output cannot be sent by accident; it
  needs a later contract with its own audience rule.

### What a summary may contain

Hosts generate the summary from a fixed per-tool template, never from free
model text or raw tool arguments. A command line or a URL can carry a bearer
token.

- File tools: the verb and the path relative to the agent's work tree, or only
  the basename ("Reading src/api.py", "Editing README.md").
- Shell: the verb and the program name, the first token only ("Running
  pytest"). Never arguments, environment, pipes or redirections.
- Web or fetch: the verb and the host name only ("Fetching docs.python.org").
- Everything else: the tool's display name, with no arguments.

The emitter also runs a known-secret-shape redactor over the finished summary
(key prefixes, JWT shape, long high-entropy strings) and drops the summary on a
match. Templating makes the redactor a second line of defence, not the first.

## Ingress

```http
POST /v1/agents/me/activity
```

- **Auth.** The existing messaging auth dependency used by the chat routes
  (`server/src/aweb/identity_auth_deps.py:222-270`): grant, team certificate or
  identity DIDKey. For grant callers it reuses the existing `presence.write`
  scope (`server/src/aweb/auth_context.py:25-36`). Activity is a liveness
  statement about the caller itself, like a heartbeat. Already-issued grants
  therefore need no reissue. Athena should confirm that scope choice.
- **Body:** `{"signed_payload": "<base64url canonical JSON>", "signature": "<base64>"}`.
- **The server verifies and refuses** (each refusal has a distinct 4xx status
  and message, and the real error is logged):
  1. The signature is valid over the exact presented bytes, and they are
     canonical JSON with `v == 1` and `type == "agent_activity"`.
  2. `from_did` is the authenticated caller's signing key, and
     `from_stable_id`, when present, is the caller's stable id. One agent can
     never publish as another.
  3. `team_id` is the caller's authenticated team.
  4. `timestamp` is within the 5-minute signed-request skew
     (`docs/team-auth-envelope-v2.md`, step 2), and `expires_at` is at most 60
     seconds after `timestamp`.
  5. A non-null `session_id` names a session in which the caller is a
     participant. Otherwise the request is refused with 403, and nothing is
     relayed.
  6. Size, field and phase rules above.
  7. **Rate limit**, per agent: a token bucket of 2 events per second with a
     burst of 10, kept in Redis. Over the limit, the response is 429 with
     `Retry-After`. aweb has no route rate limiting today (the
     `app.state.rate_limiter` built at `server/src/aweb/api.py:255,315` is
     never enforced), so this is the first enforced use and needs its own
     tests.
- **On success:** `SETEX agent-activity:{agent_id}` with a TTL of
  `min(expires_at - now, 60s)`, holding the verified event. `turn_ended`
  deletes the key. The server then publishes to Redis channel
  `agent-activity:{agent_id}` and returns 202. Redis pub/sub is the server's
  existing fan-out mechanism (`server/src/aweb/events.py:292-344`).
- If Redis is unavailable, the response is 503, nothing is retried, and the
  error is logged. Activity is best-effort by design, and a lost event expires
  harmlessly.

The server never writes the event to Postgres. Unlike app events, which are
persisted with no garbage collection
(`server/src/aweb/migrations/aweb/009_app_events.sql:42-68`), and control
signals, which are persisted (`001_initial.sql:281-294`), this needs no
migration.

## Delivery over the existing chat SSE

Delivery uses the per-session chat stream that already serves exactly the
chat audience:

```http
GET /v1/chat/sessions/{session_id}/stream?deadline=...&include=agent_activity
```

- **Opt-in by the subscriber.** The stream emits the new frames only when the
  caller passes `include=agent_activity`. Released clients never pass it, so
  their streams are byte-for-byte unchanged. This matters because the Go wait
  loop runs trust normalisation on every frame before it checks the frame's
  type (`cli/go/chat/chat.go:1127-1145`), and it aborts on certain field names
  (`:323-329`). An unrequested frame is a risk this design avoids rather than
  analyses.
- **Projection.** For each other participant agent `A` in the session, the
  stream handler reads `agent-activity:{A}` once at open, as a snapshot, and
  then subscribes to channel `agent-activity:{A}`:
  - If the event's `session_id` equals this session, the frame carries the
    full verified event.
  - If the event has another or a null `session_id`, the frame carries only a
    server-derived `{"agent": "<alias>", "phase": "busy_elsewhere",
    "expires_at": ...}`. It has no tool and no summary, and no
    `signed_payload`, because the server derived it. A person learns only that
    the agent is working on something else, never what. This is the same class
    of unsigned, server-derived signal as `sender_waiting`
    (`server/src/aweb/messaging/waiting.py:32-53`).
- **Frame.**

  ```sse
  event: agent_activity
  data: {"agent":"bond","signed_payload":"<b64url>","signature":"<b64>","from_did":"did:key:...","phase":"tool","tool":"Bash","summary":"Running pytest","turn_id":"...","seq":17,"expires_at":"..."}
  ```

  The displayed fields are copies of the signed ones. A consumer that verifies
  compares them to `signed_payload`, as for plaintext chat
  (`docs/trust-model.md`, "Plaintext signed display binding"), and shows the
  quiet verified mark only on a match. The frame deliberately avoids the field
  names `content_mode`, `message_version` and `encrypted_envelope`.
- **Grant re-checks and deadline.** These apply unchanged: a 300-second
  maximum and a 30-second grant recheck (`docs/trust-model.md`, the stream
  recheck paragraph). A revoked viewer stops seeing activity when the stream
  ends.
- **Not delivered elsewhere.** Activity does not go on the agent event stream
  `GET /v1/events/stream`, so it never wakes or steers other agents, and on
  the team or dashboard stream (`/v1/teams/{id}/events/stream`), so it never
  reaches non-participants. The hosted dashboard reads it through the same
  participant-scoped chat stream it uses for message content.

### Encrypted sessions

When the session's messages are end-to-end encrypted (encrypted v2), a
summary attributed to that session would put server-readable words beside an
encrypted conversation. In that case the emitter sends `phase` and `tool` only,
with no summary. The dashboard copy says activity is visible to aweb's
servers, as this chat is. Athena to confirm this rule.

## Attribution: which chat a turn serves

The component that delivered the wake that started the turn knows which chat
it delivered, so it attributes:

- **Claude Code and Pi.** channel-core's dispatcher delivers chat wakes for
  both (`channel/src/index.ts:206-233`, `pi-extension/src/index.ts:401-418`).
  It records "current turn serves session S" when it injects a chat wake for
  S, and clears it at the turn boundary. A turn started by local input, mail or
  an app event is unattributed (`session_id: null`), and other chats see only
  `busy_elsewhere`.
- **Codex.** The terminal wake broker types input into the session
  (`docs/terminal-wake-broker.md`). Version 1 Codex emitters publish
  unattributed activity. Attribution through the broker is a later, additive
  change.

## Emitters

Each emitter is off unless the host owner enables it in the agent's home, and
each coalesces locally: latest wins, at most one event per 500 ms, and
`turn_ended` is always sent. If the server answers 404 (an older server),
publishing stops for the process lifetime and one line is logged. On 429 the
emitter honours `Retry-After` and drops intermediate states. Signing uses the
key the runtime integration already loads.

- **Claude Code: plugin hooks, not a transcript tail.** The Claude Code docs
  state the transcript format "is internal to Claude Code and changes between
  versions" (code.claude.com/docs/en/sessions.md). Hooks are the supported
  interface. The aweb channel plugin is a stdio MCP server that already holds
  the agent's signing key and team certificate
  (`channel-core/src/config.ts:158-234`) and signs requests
  (`channel-core/src/api/client.ts:143-200`). Its manifest declares no hooks
  today (`channel/.claude-plugin/plugin.json`).
  - The plugin would ship `hooks/hooks.json` with `async: true` command hooks,
    so the hooks never delay a tool call. They cover `UserPromptSubmit` →
    `turn_started`, `PreToolUse` → `tool`, `PostToolUse` and
    `PostToolUseFailure` → `thinking`, `PermissionRequest` →
    `waiting_permission`, and `Stop` and `StopFailure` → `turn_ended`
    (code.claude.com/docs/en/hooks.md).
  - Each hook passes its stdin JSON to the running plugin process over a local
    socket in the plugin's data directory. The plugin applies the templates,
    redaction, coalescing, attribution and signing.
  - Alternatively, a hook can call an MCP tool of the plugin
    (`type: "mcp_tool"`). Whether that hook type runs asynchronously is not
    documented, so the implementation slice verifies it before choosing.
  - The existing opt-in `aw notify` PostToolUse hook
    (`cli/go/cmd/aw/claude_hooks.go:160-178`) is unrelated and unchanged.
- **Pi: the extension's existing lifecycle handlers.**
  `pi-extension/src/index.ts` already subscribes to `tool_call` (:274-280) and
  `turn_start`/`turn_end` (:282-288), and runs channel-core in-process with a
  signed client (:401-418). The emitter maps them to `turn_started`, `tool`
  and `turn_ended`. Finer phases (`thinking`, `writing`) depend on Pi
  exposing message events, which the slice verifies.
- **Codex: hooks, with OATS `packages/record` as the transcript fallback.**
  - Codex 0.162.1 reports `hooks` as a stable feature (`codex features list`).
    The binary names `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`,
    `SessionStart` and `PermissionRequest` events, and hooks require persisted
    trust (`--dangerously-bypass-hook-trust` exists only for vetted
    automation). The emitter is an `aw activity hook` command, signing with
    the home's `.aw` identity like any `aw` command. Codex has no aweb channel
    process (`docs/runtime-support.md:23,56-57`), and its packaged plugin is
    skills only (`packages/codex-plugin/.codex-plugin/plugin.json`).
  - The exact hook config and stdin schema are verified in the
    implementation slice; I observed them from the CLI and binary, not from
    documentation.
  - If hooks prove unusable, the fallback tails
    `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl`. It uses the record
    mappings already written in OATS `packages/record/lib/formats.mjs`:
    `response_item` with `payload.type` of `reasoning` → `thinking`,
    `function_call`/`custom_tool_call` → `tool`, and assistant `message` →
    `writing` (formats.mjs:319-351). The fallback would reuse the byte-offset,
    complete-line reading discipline of `lib/capture-cc.mjs:239-296`, not its
    2-second debounce (`bin/capture.mjs:405-431`).
  - `packages/record` itself is a batch capture tool, not a live tail, and is
    a reference only.
- **Host-owner opt-in.** One host-side setting, readable by every emitter:
  `activity: off | status`, with `off` the default.
  - OATS: a provider setting under `settings.oats.aweb`, applied per soul or
    instance. Its exact name is agreed with oats-expert-juan in the
    implementation slice.
  - Non-OATS: `aw activity enable|disable` writes it to the home's `.aw`.
  - A later partial-output contract adds a third level, which needs its own
    audience rule and its own review.

## Released-client compatibility

Every change is additive (decision: released clients are a permanent
constraint, `aweb/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md@8609416ff075`).

| Consumer | Effect |
|---|---|
| Released `aw` CLI chat waits | None: they never send `include=agent_activity`, so their stream is unchanged. |
| channel-core (channel plugin 1.7.x, Pi 0.3.x) | None: they read only `/v1/events/stream`, which is unchanged. Even so, unknown event names there are dropped (`channel-core/src/api/events.ts:252-257,282`). |
| Older emitters | They send nothing, and the dashboard shows what it shows today. |
| Newer emitters against an older server | 404, so publishing stops for that process and one line is logged. No retry storm. |
| Already-issued grants | Usable as they are; the route reuses `presence.write`. |
| Hosted dashboard | Opts in with `include=agent_activity`. It deploys with the server under the hosted-application rule, so no field client depends on this frame. |

No migration, no new grant scope, no change to existing signed bytes. The new
signed bytes get a conformance vector (`docs/vectors/agent-activity-v1.json`)
with positive cases and these negatives: wrong signer, wrong team, foreign
session, oversize, unknown field, unknown phase, and expiry window exceeded.
Producer and verifier tests consume it.

## Not in this contract

- **Partial output.** It needs a narrower audience: the agent's owner plus
  whoever the host owner adds, per Athena. aweb has no owner relation for that
  today, and the agent-health work (aweb-acah.3) may introduce the host
  principal it needs. It gets its own note.
- Any history or replay of activity.
- Showing activity outside a chat, for example on the roster. Agent health
  (aweb-acah.3) covers "can it hear you".
- Activity of a human participant.

## Questions for review

1. Athena: is `presence.write` the right grant scope, or should activity have
   its own scope at the cost of reissuing grants?
2. Athena: is the encrypted-session rule (no summary) sufficient?
3. Athena: should `busy_elsewhere` reach other sessions at all? It reveals that
   the agent is busy, though not with what. The alternative is silence, which
   is the experience we are fixing.

## Implementation slices (after approval)

1. Server ingress, Redis state, rate limiter, chat-stream projection, vector,
   and tests in both directions (the opted-in viewer sees the event; a
   non-participant, a foreign session and a released client do not).
2. channel-core emitter core: templates, redactor, coalescer, attribution and
   signing. Then the Claude Code plugin hooks and the Pi handlers.
3. The `aw activity` commands and the Codex hook emitter.
4. Dashboard rendering, by the hosted team, against slice 1's frame.
