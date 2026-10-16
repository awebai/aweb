# Agent activity: a signed, ephemeral, opt-in status stream

Status: **approved by Juan on 2026-10-14 (aweb-acah.2); not yet implemented.**
The amendments in "Amendments after approval" are under review by Athena.
The signed event's wire bytes are pinned in
[`docs/vectors/agent-activity-v1.json`](vectors/agent-activity-v1.json), which
is frozen when that review closes.

## Purpose

A person chatting with an agent in the dashboard sees nothing during the
agent's turn, which can run from tens of seconds to minutes. This contract lets
the agent's host publish a short, signed account of what the agent is doing
("reading files", "running tests", "writing reply"). The other participants of
the chat the agent is serving see it live.

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
  home on the host, or the grant session key in a grant seat's home. The host
  produces activity from the agent runtime's own lifecycle hooks and signs it
  with the credential the runtime already loads. aweb receives no new key, and
  no new authority over the host.
- **Who decides publishing.** Only the host owner, through one file in the
  agent's identity root (see "Host-owner opt-in"). Nothing in aweb, the team
  controller or the dashboard can turn publishing on. No route, flag or control
  signal instructs a host to start emitting. This is the property that makes the
  stream safe to show (Juan's proposal doc; Athena: "it grants no authority over
  the host").
- **Who sees it.** The participants of the chat session the turn is serving.
  That is the set that may read that session's messages
  (`server/src/aweb/routes/chat.py:2370-2397`). Team or dashboard access alone
  is not participation (`docs/aweb-sot.md:1030`), and that rule holds here
  unchanged.
- **What the server does.** It authenticates the emitter, verifies that the
  signature binds to that emitter, enforces size and rate limits, and relays
  the event to open opted-in chat streams. It keeps only the latest event per
  agent, in Redis, for at most 60 seconds, so a viewer who opens the chat
  mid-turn sees the current state. Nothing is written to Postgres, mail, chat
  history or app events.

## The signed event

The emitter builds a JSON object, encodes it canonically and signs the bytes:

- canonical bytes: UTF-8 JSON, keys sorted by code point, separators `,` and
  `:`, no ASCII escaping (`awid/src/awid/signing.py:44-47`, the same encoding
  as message and status signing);
- signature: Ed25519 over the canonical bytes, raw standard base64 without
  padding;
- `signed_payload`: the canonical bytes, base64url without padding.

```json
{
  "v": 1,
  "type": "agent_activity",
  "from_did": "did:key:z6Mk...",
  "from_stable_id": "did:aw:...",
  "team_id": "default:acme.aweb.ai",
  "session_id": "6f1c2b3a-4d5e-4f60-8a7b-9c0d1e2f3a4b",
  "turn_id": "turn-01J9Z8Q4",
  "seq": 17,
  "phase": "tool",
  "tool": "Bash",
  "summary": "Running pytest",
  "timestamp": "2026-10-16T16:20:00Z",
  "expires_at": "2026-10-16T16:21:00Z"
}
```

Fields. Version 1 refuses any other field.

| Field | Rule |
|---|---|
| `v` | Required; the integer `1`. |
| `type` | Required; `"agent_activity"`. |
| `from_did` | Required; the `did:key` that signed the request carrying the event: the agent's key, or the grant session key for a grant caller. |
| `from_stable_id` | Optional; a `did:aw`. When present it must be the stable id the caller is attributed to; it is absent for an identity without one. |
| `team_id` | Required; the caller's authenticated team. |
| `session_id` | Required key; `null`, or a lowercase hyphenated UUID naming the chat session the turn serves (see "Attribution"). |
| `turn_id` | Required; an opaque emitter turn id, 1 to 64 bytes of `[A-Za-z0-9_.:-]`. |
| `seq` | Required; a JSON integer from 1 to 2^53-1, increasing within `turn_id`. |
| `phase` | Required; one of the phases below. |
| `tool` | Required when `phase` is `tool`, optional otherwise. The runtime's tool name, at most 64 bytes of `[A-Za-z0-9_.:-]`; MCP tool names keep their server prefix. |
| `summary` | Optional; 1 to 120 UTF-8 bytes, no control characters (U+0000-U+001F, U+007F-U+009F). See "What a summary may contain". |
| `timestamp`, `expires_at` | Required; `YYYY-MM-DDTHH:MM:SSZ`. `expires_at` is after `timestamp` and at most 60 seconds after it. |

| Phase | Meaning |
|---|---|
| `turn_started` | The turn has started. |
| `thinking` | The model is reasoning; no tool is running. |
| `tool` | A tool is running; `tool` names it. |
| `waiting_permission` | Blocked on a permission prompt on the host. |
| `writing` | Composing the reply. |
| `turn_ended` | The turn is over; clears the live state. |

New phases are additive and need a new vector version; an unknown phase is
refused at ingress. `busy_elsewhere` is a server-derived frame (see
"Delivery"), never a signed phase.

Consumers discard an event whose `seq` is not greater than the last one they
showed for that `turn_id`, which tolerates reordering and replay. A consumer
stops showing an event at `expires_at` even if `turn_ended` never arrives, for
example after a host crash.

The canonical bytes are at most 1024 bytes and the request body at most 2048.
There is no output, transcript, file-content or argument field, and unknown
fields are refused, so partial output cannot be sent by accident; it needs a
later contract with its own audience rule.

### Domain separation from messages

Activity is signed with the same key as the agent's chat messages, so neither
signature may verify as the other. Message verification rebuilds its canonical
payload from `SIGNED_FIELDS` only (`awid/src/awid/signing.py:14-33,50-52`). An
activity event always carries `v`, `team_id`, `phase` and other fields outside
that set, so its bytes never equal a message's canonical bytes. A message's
bytes offered as activity fail the `type` check, which runs before any other
field. The vector pins both directions.

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
The server cannot tell whether a summary was templated; that is why ingress
needs the authority that already gates putting text into chats.

## Ingress

```http
POST /v1/agents/me/activity
Content-Type: application/json

{"signed_payload": "<base64url canonical bytes>", "signature": "<base64>"}
```

**Authentication** is the messaging dependency the chat routes use
(`server/src/aweb/identity_auth_deps.py:222-272`): grant, team certificate or
identity DIDKey. Grant callers need the existing `chat.send` scope
(`server/src/aweb/auth_context.py:24-36`). A grant without `chat.send` cannot
reach a session's participants through activity. `chat.send` is already on the
seat grants that matter, so no grant is reissued and no scope is added.

**Verification order.** Each step refuses with its own code (see "Refusal
codes"), and the server logs the real error.

1. The request body is at most 2048 bytes, and `signed_payload` decodes from
   unpadded base64url to a JSON object.
2. The event, in the vector's order: size before parsing, canonical bytes
   before the signature, the signature (verified with the authenticated
   request's signing key) before fields, `type` before any other field, field
   shapes before caller bindings, and bindings before time. The bindings are:
   `from_did` equals the request's signing key, `team_id` equals the caller's
   team, and `from_stable_id`, when present, equals the caller's stable id. One
   agent can never publish as another. The time rules are the 60-second
   validity window, the 300-second clock skew of signed requests
   (`docs/team-auth-envelope-v2.md:45`) and expiry.
3. The server has Redis; without it the answer is 503 and nothing is retried.
   Activity is best-effort by design, and a lost event expires harmlessly.
4. Rate limit, per authenticated agent. The key is the caller, so no one else
   can spend an agent's budget. It runs before the session lookup, so a flood
   costs no database read. See "Amendments after approval" for its shape.
5. A non-null `session_id` names a session in which the caller is a
   participant. An absent session and a session the caller is not in get the
   same response: the shared 404 `{"detail":"Not found"}`, matching status,
   body and content type (`docs/aweb-sot.md:268-291`). Nothing is relayed.

**On success** the server stores the verified event with
`SETEX agent-activity:{agent_id}` and a TTL of `min(expires_at - now, 60s)`;
`turn_ended` deletes the key instead. It publishes the event on Redis channel
`agent-activity:{agent_id}` and returns 202. Redis pub/sub is the server's
existing fan-out (`server/src/aweb/events.py:320-371,396`). The per-session
channel `chat-session:{session_id}` (`events.py:315-371`) is a wake hint for
message delivery, and activity does not use it: the `busy_elsewhere`
projection needs the per-agent view.

The server never writes the event to Postgres. This needs no migration, unlike
app events (`server/src/aweb/migrations/aweb/009_app_events.sql:42`) and control
signals (`001_initial.sql:281`), which are persisted.

### Refusal codes

Every refusal this route owns has the body `{"detail": "<code>: <message>"}`,
as in [agent health](agent-health.md#refusal-codes). The code is the text
before the first `": "`, matches `^[a-z_]+$`, and is stable; the message is
plain words and may change. Refusals from shared authentication (401, and grant
callers' 403 `outside grant scope`), FastAPI request validation (a 422 whose
detail is a list), and the shared 404 carry no code.

| Code | Status | Meaning |
|---|---|---|
| `request_too_large` | 413 | the request body exceeds 2048 bytes |
| `malformed_payload` | 422 | `signed_payload` is not unpadded base64url of a JSON object |
| vector codes | 422 | every `error` in `docs/vectors/agent-activity-v1.json` |
| `publishing_unavailable` | 503 | the server has no Redis for rate limiting and relay |
| `rate_limited` | 429 | over the per-agent limit; `Retry-After` gives the wait |
| (none) | 404 | `session_id` names no session the caller participates in |

The vector codes are `document_too_large`, `non_canonical`, `bad_signature`,
`wrong_type`, `unknown_field`, `missing_field`, `invalid_value`,
`text_too_long`, `control_character`, `signer_mismatch`, `team_mismatch`,
`stable_id_mismatch`, `validity_window`, `clock_skew` and `expired`. Those
shared with agent health have the same meaning there.

## Delivery over the existing chat SSE

Delivery uses the per-session chat stream, which already serves exactly the
chat audience:

```http
GET /v1/chat/sessions/{session_id}/stream?deadline=...&include=agent_activity
```

- **Opt-in by the subscriber.** The stream emits activity frames only when the
  caller passes `include=agent_activity`. Released clients never pass it, so
  their streams are byte-for-byte unchanged. This matters because the Go wait
  loop decrypts and normalises sender trust on every frame before it checks the
  frame's type (`cli/go/chat/chat.go:1127-1146`), and it reads
  `content_mode`, `message_version` and `encrypted_envelope` from any frame
  (`:160-174`). An unrequested frame is a risk this design avoids rather than
  analyses.
- **Projection.** At stream open, for each other participant agent `A` of the
  session, the handler reads `agent-activity:{A}` once as a snapshot and then
  subscribes to channel `agent-activity:{A}`. The participant set is fixed at
  open; streams last at most 300 seconds
  (`server/src/aweb/routes/chat.py:109`), and a reopened stream sees the
  current set.
  - If the event's `session_id` is this session, the frame carries the full
    verified event.
  - If the event names another session or `null`, the frame carries only a
    server-derived `{"agent": "<alias>", "phase": "busy_elsewhere",
    "expires_at": ...}`, with no tool, no summary and no `signed_payload`. A
    person learns only that the agent is working on something else, never
    what. This is the same class of unsigned, server-derived signal as
    `sender_waiting` (`server/src/aweb/messaging/waiting.py:32-53`).
- **Frame.**

  ```sse
  event: agent_activity
  data: {"agent":"bond","signed_payload":"<b64url>","signature":"<b64>","from_did":"did:key:...","phase":"tool","tool":"Bash","summary":"Running pytest","turn_id":"...","seq":17,"expires_at":"..."}
  ```

  The displayed fields are copies of the signed ones. A consumer that verifies
  compares them to `signed_payload`, as for plaintext chat
  (`docs/trust-model.md:568`), and shows the quiet verified mark only on a
  match. A grant-session signature is attributed by the server, exactly as a
  grant-signed chat message is (`docs/identity.md:374-381`). The frame
  deliberately avoids the field names `content_mode`, `message_version` and
  `encrypted_envelope`.
- **Grant rechecks and deadline** apply unchanged: a 300-second maximum and a
  30-second grant recheck (`docs/trust-model.md:549`). A revoked viewer stops
  seeing activity when the stream ends.
- **Not delivered elsewhere.** Activity is not put on the agent event stream
  `GET /v1/events/stream`, so it never wakes or steers other agents. It is not
  put on the team or dashboard stream (`/v1/teams/{id}/events/stream`) either,
  so it never reaches non-participants. The hosted dashboard reads it through
  the same participant-scoped chat stream it uses for message content.

### Encrypted sessions

When a session's messages are end-to-end encrypted (encrypted v2), a summary
attributed to that session would put server-readable words beside an encrypted
conversation. There the emitter sends `phase` and `tool` only, with no summary.
This is an emitter rule; the server does not enforce it. The dashboard copy
says activity is visible to aweb's servers, as this chat is, and that in an
encrypted chat the tool name itself remains visible to aweb.

## Attribution: which chat a turn serves

The component that delivered the wake that started the turn knows which chat
it delivered, so it attributes:

- **Claude Code and Pi.** channel-core's dispatcher delivers chat wakes for
  both (`channel/src/index.ts:246-272`; Pi runs the same loop in-process,
  `pi-extension/src/index.ts:411`). It records "the current turn serves
  session S" when it injects a chat wake for S, and clears it at the turn
  boundary. A turn started by local input, mail or an app event is unattributed
  (`session_id: null`), and other chats see only `busy_elsewhere`.
- **Codex.** The terminal wake broker types input into the session
  (`docs/terminal-wake-broker.md`). Version 1 Codex emitters publish
  unattributed activity. Attribution through the broker is a later, additive
  change.

## Host-owner opt-in

Agreed with oats-expert-juan on 2026-10-16.

- **The file.** `<identity root>/activity.yaml`, beside `workspace.yaml` and the
  signing key in the identity root the emitter signs with. For a grant seat
  that is the grant home, which the running emitter loads; the resident custody
  `.aw` never carries per-instance state. The file holds one key:

  ```yaml
  activity: status   # or: off
  ```

  A missing file, or any other value, means off: the emitter does not publish.
  The file is separate from `workspace.yaml`, which `aw` rewrites on many
  operations, so its ownership stays obvious. It holds no secret.
- **Readers.** Every emitter reads the file at each turn start, so a change
  takes effect at the next turn without a restart.
- **Non-OATS hosts.** `aw activity enable` and `aw activity disable` write the
  file (mode 0644, atomic replace).
- **OATS hosts.** The oats.aweb provider owns the file. The provider setting
  `settings.oats.aweb.activity: off | status` (default `off`) resolves like the
  provider's other settings (manifest default, deployment, soul, instance). The
  provider's launch hook writes the file at spawn and at every launch, always,
  `off` included, so an instance never keeps a stale `status` from an earlier
  launch. A hand edit, or `aw activity enable`, in an OATS home lasts until the
  next launch: OATS configuration is the host owner's statement. The effective
  value is recorded in the provider's launch metadata and reported by
  `oats readiness --json` as information, with no warning.
- **Scope.** Version 1 covers the instance's primary identity. Joined-team
  identity homes get no file, so they stay off; no version 1 emitter publishes
  as them.
- A later partial-output contract adds a third value, with its own audience
  rule and review. Emitters treat unknown values as off.

## Emitters

Each emitter is off unless the opt-in file says `status`. Each coalesces
locally: latest wins, at most one event per 500 ms, and `turn_ended` is always
sent. On a 404 from the route itself (an older server), publishing stops for
the process lifetime and one line is logged. On 429 the emitter honours
`Retry-After` and drops intermediate states. Signing uses the key the runtime
integration already loads.

- **Claude Code: plugin hooks, not a transcript tail.** The Claude Code docs
  state the transcript format "is internal to Claude Code and changes between
  versions" (code.claude.com/docs/en/sessions.md). Hooks are the supported
  interface. The aweb channel plugin is a stdio MCP server that already loads
  the agent's signing key and team certificate
  (`channel-core/src/config.ts:160-320`) and signs requests
  (`channel-core/src/api/client.ts:18-34`). Its manifest declares no hooks
  today (`channel/.claude-plugin/plugin.json`).
  - The plugin ships `hooks/hooks.json` with `async: true` command hooks, so
    the hooks never delay a tool call: `UserPromptSubmit` to `turn_started`,
    `PreToolUse` to `tool`, `PostToolUse` and `PostToolUseFailure` to
    `thinking`, `PermissionRequest` to `waiting_permission`, and `Stop` and
    `StopFailure` to `turn_ended` (code.claude.com/docs/en/hooks.md).
  - Each hook passes its stdin JSON to the running plugin process over a local
    socket in the plugin's data directory. The plugin applies the templates,
    redaction, coalescing, attribution and signing.
  - Alternatively, a hook can call an MCP tool of the plugin
    (`type: "mcp_tool"`). Whether that hook type runs asynchronously is not
    documented, so the implementation verifies it before choosing.
  - The existing opt-in `aw notify` PostToolUse hook
    (`cli/go/cmd/aw/claude_hooks.go:14,129`) is unrelated and unchanged.
- **Pi: the extension's existing lifecycle handlers.**
  `pi-extension/src/index.ts` already subscribes to `tool_call` (:276) and
  `turn_start`/`turn_end` (:284-288), and runs channel-core in-process with a
  signed client (:411). The emitter maps them to `tool`, `turn_started` and
  `turn_ended`. Finer phases (`thinking`, `writing`) depend on Pi exposing
  message events, which the implementation verifies.
- **Codex: hooks, with a transcript tail as the fallback.**
  - Codex 0.162.1 reports `hooks` as a stable feature (`codex features list`).
    The binary names `PreToolUse`, `PostToolUse`, `UserPromptSubmit`, `Stop`,
    `SessionStart` and `PermissionRequest` events, and hooks require persisted
    trust. The emitter is an `aw activity hook` command, signing with the
    home's identity like any `aw` command. Codex has no aweb channel process
    (`docs/runtime-support.md:23,56-57`), and its packaged plugin is skills
    only (`packages/codex-plugin/.codex-plugin/plugin.json`).
  - The exact hook config and stdin schema are verified on the installed
    binary before implementation; they were observed from the CLI and binary,
    not from documentation.
  - If hooks prove unusable, the fallback tails
    `$CODEX_HOME/sessions/YYYY/MM/DD/rollout-*.jsonl`, using the record
    mappings in the OATS repository's `packages/record/lib/formats.mjs`
    (`response_item` with `payload.type` of `reasoning` to `thinking`,
    `function_call`/`custom_tool_call` to `tool`, assistant `message` to
    `writing`) and its byte-offset, complete-line reading discipline
    (`lib/capture-cc.mjs`), not its 2-second debounce. `packages/record` itself
    is a batch capture tool, not a live tail, and is a reference only.

## Released-client compatibility

Every change is additive (decision: released clients are a permanent
constraint,
`aweb/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md@8609416ff075`).

| Consumer | Effect |
|---|---|
| Released `aw` CLI chat waits | None: they never send `include=agent_activity`, so their stream is unchanged. |
| channel-core (channel plugin 1.7.x, Pi 0.3.x) | None: they read only `/v1/events/stream`, which is unchanged. Unknown event names there are dropped anyway (`channel-core/src/api/events.ts:297`). |
| Older emitters | They send nothing, and the dashboard shows what it shows today. |
| Newer emitters against an older server | 404, so publishing stops for that process and one line is logged. No retry storm. |
| Already-issued grants | Usable as they are; the route reuses `chat.send`. |
| Hosted dashboard | Opts in with `include=agent_activity`. It deploys with the server under the hosted-application rule, so no field client depends on this frame. |

There is no migration, no new grant scope and no change to existing signed
bytes.

## Conformance vector

[`docs/vectors/agent-activity-v1.json`](vectors/agent-activity-v1.json) pins
the canonical bytes, `signed_payload` and signature for fixed test keys: the
agent key (the same seed as agent-status-v1), another key, and a grant session
key. Each case carries its evaluation time and, where it differs from the
default, the authenticated caller (signing key, stable id, team).

- Valid: each phase, an unattributed `null` session, a tool without a summary
  (the encrypted-session form), every byte cap at its limit with multibyte
  text, the 60-second validity edge, a timestamp 300 seconds ahead, a local
  identity without a stable id, and a grant session signer.
- Invalid, each with exactly one fault and one expected code: oversize,
  non-canonical bytes, a signature by another key, a chat message's signed
  bytes and a status type offered as activity, an unknown field, missing
  fields (including the `session_id` key and the tool of a `tool` phase), each
  shape rule, `busy_elsewhere` offered as a signed phase, `from_did` not the
  signer (including a grant caller naming the resident key), a foreign team, a
  wrong or unexpected stable id, the validity window, clock skew and expiry.
- Route refusals: an absent session and a session the caller is not in, both
  the shared 404.
- Cross-type: an activity signature does not verify as a message.

The server's verifier and every emitter's producer consume it.

## Not in this contract

- **Partial output.** It needs a narrower audience: the agent's owner plus
  whoever the host owner adds, per Athena. It gets its own note and review.
- Any history or replay of activity.
- Showing activity outside a chat, for example on the roster. Agent health
  ([agent-health.md](agent-health.md)) covers "can it hear you".
- Activity of a human participant.

## Review decisions (Athena, before approval)

1. Grant scope: `chat.send`, not `presence.write`.
2. Encrypted sessions: `phase` and `tool` only, no summary, is sufficient; the
   dashboard copy says the tool name is visible to aweb.
3. `busy_elsewhere`: acceptable. It reveals only that the agent is busy in
   another chat, and it stays server-derived.
4. Activity does not count against message allowances; the rate limit and
   size caps bound it.

## Amendments after approval

Under review by Athena. The coordinator accepted amendment 1 (msg 1b587051).

1. **A foreign session gets the shared 404.** The approved draft refused a
   `session_id` the caller is not in with 403. Since then the refused-resource
   rule (aweb-acdc, `docs/aweb-sot.md:268-291`) requires a private resource the
   caller cannot see to be indistinguishable from a missing one. Ingress step 5
   follows it.
2. **Rate limit shape.** The approved draft specified a token bucket of 2
   events per second with a burst of 10, and said aweb enforced no route rate
   limit. Agent health has since added one: a fixed window per agent, with
   Redis `SET NX` (`server/src/aweb/routes/agent_status.py:300-309`). The
   `app.state.rate_limiter` built at `server/src/aweb/api.py:257,317` is still
   not enforced by any route. Proposed: a fixed-window counter in the same
   style, `INCR` plus `EXPIRE` on `agent-activity-rate:{agent_id}`, at most 10
   events per 5-second window, 429 `rate_limited` with `Retry-After` set to
   the window's remaining TTL. It gives the same sustained bound (2 per second)
   and the same burst (10), is simpler, and needs no clock arithmetic to test.
   Whether the bucket stays is Athena's call.
3. **Binding details the draft left implicit.** `from_did` binds to the
   request's signing key, which is the grant session key for a grant caller.
   `from_stable_id` binds to the identity the caller is attributed to. Refusals
   carry stable codes, shared with agent health where the meaning is the same.
   The rate limit runs before the session lookup. The host-owner opt-in is the
   agreed file.

## Implementation slices

1. Server: ingress, Redis state, rate limit, chat-stream projection, and tests
   in both directions (an opted-in participant sees the event; a
   non-participant, a foreign session, a released client and a dashboard-only
   viewer do not).
2. channel-core emitter core (templates, redactor, coalescer, attribution,
   signing), then the Claude Code plugin hooks and the Pi handlers.
3. `aw activity enable|disable|hook`, and the Codex hook emitter.
4. Dashboard rendering, by the hosted team, against slice 1's frame.
