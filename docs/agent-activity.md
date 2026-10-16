# Agent activity: a signed, ephemeral, opt-in status stream

Status: **approved by Juan on 2026-10-14 (aweb-acah.2); not yet implemented.**
The amendments in "Amendments after approval" are approved by Athena and the
independent protocol reviewer. The signed event's wire bytes are frozen in
[`docs/vectors/agent-activity-v1.json`](vectors/agent-activity-v1.json), ACKed
at `4502edac0` before the server or any emitter implemented them.

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
refused at ingress. `busy_elsewhere` and `cleared` are server-derived frames
(see "Delivery"), never signed phases.

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
kind of signed bytes may be accepted as the other. A raw signature check alone
does not separate them: `verify_signature` verifies whatever bytes it is given
(`awid/src/awid/signing.py:87-99`), and the server's read-side message verifier
checks the stored raw `signed_payload` (`server/src/aweb/messaging/verification.py:33-53`).
What separates them is a required, distinct `type` at every ingress:

- Message ingress refuses activity bytes. Signed chat requires `type` `chat`
  (`server/src/aweb/routes/chat.py:173-174`), and signed mail requires `mail`
  (`server/src/aweb/routes/messages.py:509-510`). Both refuse with 422.
- Activity ingress refuses message bytes. `type` must be `agent_activity`, and
  it is checked before any other field (vector case
  `chat_message_bytes_as_activity`).

The vector's `cross_type` entry is a construction check for producers: an SDK
that builds message bytes with `canonical_payload` (`signing.py:50-52`), which
keeps only `SIGNED_FIELDS` (`:14-33`), never produces activity bytes, because
activity always carries `v`, `team_id` and `phase`. It is not a claim that every
verifier rebuilds those bytes. S1 pins the message-ingress refusal of an
activity payload as conformance evidence.

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

**Authentication** is a team certificate, or an identity grant carrying the
existing `chat.send` scope, through the route-declared grant scope
`team_identity_with_grant_scope("chat.send")`
(`server/src/aweb/team_auth_deps.py:295-306`), the same mechanism the agent
heartbeat uses. The caller is always one authenticated team member, local or
global. For a grant, the subject is the member, and the grant's session key
signs (`server/src/aweb/identity_grant_auth.py:227-239`). Other grants get 403
`outside grant scope`, with no rate, state or relay side effect. Every bare
identity-DIDKey request is refused with the existing 401 of certificate
authentication, including one whose identity resolves to a single team member:
an event's `team_id` alone never establishes membership. No version 1 emitter
uses that path. `chat.send` is already on the seat grants that matter, so no
grant is reissued and no scope is added.

**Verification order.** Each step refuses with its own code (see "Refusal
codes"), and the server logs the real error.

1. The request body is at most 2048 bytes, and `signed_payload` decodes from
   unpadded base64url to a JSON object.
2. The event, in the vector's order: size before parsing, canonical bytes
   before the signature, the signature (verified with the authenticated
   request's signing key) before fields, `type` before any other field, field
   shapes before caller bindings, and bindings before time. The bindings are:
   `from_did` equals the request's signing key, `team_id` equals the caller's
   team, and `from_stable_id`, when present, equals the caller's stable id.
   For a grant caller the signing key is the grant's session key
   (`GrantContext.session_did_key`), not the subject key the request is
   attributed to (`MessagingAuth.did_key`; `server/src/aweb/identity_grant_auth.py:200-224`).
   The signature is verified with the session key; membership and the stable
   id come from the subject. One
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

**On success** the server relays the verified event in one atomic Redis
script, then returns 202. The script:

1. increments the agent's relay revision, `agent-activity-rev:{agent_id}`, and
   sets that counter's TTL to 3600 seconds;
2. stores `{rev, event}` as the agent's latest state,
   `agent-activity:{agent_id}`, with a TTL of `min(expires_at - now, 60s)`.
   `turn_ended` is stored like any other phase, as a short-lived end marker,
   so the latest state always carries the current revision;
3. publishes `{rev, event}` on channel `agent-activity:{agent_id}`.

Because the three steps run as one script, revision order, latest-state order
and publish order are the same for every agent, even when two requests for one
agent race. The revision is internal relay metadata: it is not signed, and it
is not sent in frames. Signed bytes are unchanged. The counter outlives any
stream (3600 seconds against a 300-second maximum), so a stream never sees it
restart. Redis pub/sub is the server's
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
- **Order at open: subscribe, then snapshot, then drain.** At stream open, for
  each other participant agent `A` of the session, the handler first
  subscribes to channel `agent-activity:{A}` and confirms the subscription.
  Only then does it read `agent-activity:{A}` as a snapshot, and then it
  processes the events queued meanwhile. Reading the snapshot first would lose
  any event published between the read and the subscription: a `turn_ended`
  there would leave the viewer showing a finished turn until its `expires_at`.
  The participant set is fixed at open; streams last at most 300 seconds
  (`server/src/aweb/routes/chat.py:109`), and a reopened stream sees the
  current set.
- **Ordering and deduplication by relay revision**, per agent, in the stream
  handler and before projection. The handler takes the snapshot's `rev` as the
  last projected revision (0 when there is no snapshot), and then projects a
  queued or live event only if its `rev` is greater, after which that becomes
  the last. A snapshot and a queued copy of the same event therefore give one
  frame, and an event published before the snapshot can never replace it,
  whatever its turn or timestamp. A snapshot or event whose phase is
  `turn_ended` projects as the end of that turn (below), never as live work.
  Timestamps, with their one-second precision, are not used for ordering.
- **Projection.**
  - If the event's `session_id` is this session, the frame carries the full
    verified event. Its `turn_ended` clears the agent's display.
  - If the event names another session or `null` and is not `turn_ended`, the
    frame carries only a server-derived `{"agent": "<alias>", "phase":
    "busy_elsewhere", "expires_at": ...}`, with no tool, no summary and no
    `signed_payload`. A person learns only that the agent is working on
    something else, never what. This is the same class of unsigned,
    server-derived signal as `sender_waiting`
    (`server/src/aweb/messaging/waiting.py:32-53`).
  - If the event names another session or `null` and is `turn_ended`, the
    frame is the server-derived `{"agent": "<alias>", "phase": "cleared"}`:
    no session, turn, tool, summary or signature. It tells the viewer to stop
    showing the agent as busy elsewhere. A stored end marker alone would not
    reach an open stream. The frame is derived from that `turn_ended` and
    carries its relay revision through the handler's check: it is projected
    only when that revision is greater than the last projected one, so a stale
    end can never clear a newer turn.
  - `busy_elsewhere` and `cleared` exist only as server-derived frames; a
    signed event naming either phase is refused at ingress.
  - S1 tests these interleavings: an event published between subscribe and
    snapshot is not lost; a snapshot and its queued copy give one frame; busy
    elsewhere, then that turn's end, then the display is cleared; and the
    equal-timestamp cross-turn case. In that case the snapshot is turn B,
    seq 2, at second T, and queued before it are turn A, seq 9, and turn B,
    seq 1, both at T. Neither queued event is projected, and a stale A
    `turn_ended` does not clear live B. S1 also tests two racing publishes for
    one agent, where latest state and channel order agree.
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

When a chat's messages are end-to-end encrypted (encrypted v2), a summary
attributed to that session would put server-readable words beside an encrypted
conversation. So when the chat message whose wake started the turn is
`encrypted_v2`, the emitter sends `phase` and `tool` only, with no summary, for
the whole turn. The emitter knows that mode because it delivered the wake.

**Known limit: the server does not enforce this.** A chat session has no
encryption mode on the server. Encryption is chosen per message
(`chat_messages.content_mode`, `server/src/aweb/migrations/aweb/004_chat_messages_encrypted_v2.sql`),
one session can mix modes, and the mode given at session creation governs only
the first message (`server/src/aweb/routes/chat.py:1244-1251`). A server check
would first need a new rule for when a session counts as encrypted, plus a
query per event, so version 1 leaves it to the emitter. Tool names stay
visible in an encrypted chat; they are low-information, and nothing here claims
end-to-end protection. The dashboard copy says activity is visible to aweb's
servers, as this chat is, and that in an encrypted chat the tool name itself
remains visible to aweb.

## Attribution: which chat a turn serves

The component that delivered the wake that started the turn knows which chat
it delivered, so it attributes:

- **Claude Code and Pi.** channel-core's dispatcher delivers chat wakes for
  both (`channel/src/index.ts:246-272`; Pi runs the same loop in-process).
  Just before it presents a chat message of session S, it calls the loop's
  `onChatPresented(S, {encrypted})` (`channel-core/src/channel.ts`, the chat
  dispatch), and the emitter attributes the next turn to S; the turn after it
  is unattributed again. If any presented message of S was encrypted, that
  turn sends no summaries. A turn started by local input, mail or an app event
  is unattributed (`session_id: null`), and other chats see only
  `busy_elsewhere`.
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
- **What `status` shows.** The session's other participants see each phase,
  the tool name and the template summary. A file summary names the file's path
  relative to the work tree ("Editing secrets/prod.env"), so the names of the
  files the agent touches are visible to them, and to aweb's servers.
- **Non-OATS hosts.** `aw activity enable` and `aw activity disable` write the
  file (mode 0644, atomic replace); `aw activity show` reports the value the
  emitters apply. Each refuses a directory that holds neither a signing key nor
  a grant.
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

Each emitter is off unless the opt-in file says `status`. Turn boundaries,
`turn_started` and `turn_ended`, are always sent and in order; a turn that a
runtime opens with its first tool call is announced with `turn_started` too.
Intermediate phases coalesce locally: the latest wins, at most one event per
500 ms, and `turn_ended` replaces its turn's pending state. On 429 the emitter
honours `Retry-After`: a boundary that drew the 429 is sent after the pause,
a state that drew it is dropped, and states queued during the pause coalesce
to the latest, which is sent after it. Signing uses the key that signs the
runtime's requests: the agent's own, or the grant session key for a grant seat.

The route answers 404 for two different reasons, and the emitter tells them
apart by the body:

- `{"detail":"Not found"}` (lower-case `f`, the shared resource answer,
  `server/src/aweb/service_errors.py:6`): the session is absent, or the caller
  is not in it. This is a normal refusal on a supported route. The emitter
  drops that one event and keeps publishing; later events, attributed or not,
  are sent as usual.
- Any other 404 body, including the framework's absent-route
  `{"detail":"Not Found"}`: the server does not have the route (an older
  server). Publishing stops for the process lifetime, and one line is logged.

Emitter tests cover both: a refused session does not suppress a following
valid or unattributed event, and an absent route stops publishing.

- **Claude Code: plugin hooks, not a transcript tail.** Hooks are Claude
  Code's documented interface for observing a session; the transcript is
  written asynchronously and may lag the conversation
  (code.claude.com/docs/en/hooks). The aweb channel plugin is a stdio MCP
  server that already loads the agent's identity and signs requests; it owns
  the session's emitter (`channel/src/activity.ts`). Verified on Claude Code
  2.1.300, headless, with the packaged plugin.
  - The plugin ships `hooks/hooks.json`. `UserPromptSubmit` is
    `turn_started`, `PreToolUse` is `tool`, `PostToolUse` and
    `PostToolUseFailure` return to `thinking`, `PermissionRequest` is
    `waiting_permission`, and `Stop` and `StopFailure` are `turn_ended`. The
    hooks are command hooks with `async: true`, so they never delay a tool
    call, except `Stop` and `StopFailure`, which run synchronously (5 s
    timeout): an async hook still running at a headless session's end is
    killed. Each runs `dist/activity-hook.js`, a 3 KiB script that never writes
    to stdout and always exits 0.
  - The hook reaches its own session's plugin over a Unix socket. Both are
    children of the same Claude Code process, so the plugin listens on
    `<dir>/<that pid>.sock` and the hook connects to its parent's socket (or
    a nearer ancestor's). `<dir>` is `/private/tmp/aweb-activity-<uid>` on
    macOS and `/tmp/aweb-activity-<uid>` elsewhere, created mode 0700 and
    refused if it is a symlink, another user's, or open to others; the socket
    file is 0600. The directory is what keeps other users out: Node has no
    peer-credential check for Unix sockets.
  - A hook forwards only the event name, Claude Code's `prompt_id`, the tool
    name, and the tool-input fields the summary templates read (`file_path`,
    `notebook_path`, `path`, `command`, `url`), each cut to 4 KiB; a file's
    content never crosses the socket. The plugin caps a line at 64 KiB and
    ignores malformed ones.
  - Each hook is its own process, so their events can arrive out of order.
    The plugin puts each in its prompt's turn: an event of a prompt that has
    stopped is dropped, a submit for a prompt whose turn a tool event already
    opened is ignored, and an event of a new prompt first closes a turn whose
    stop never arrived. A turn need not start with `UserPromptSubmit`: a turn
    woken by a channel event opens with its first tool event.
  - The plugin replaces a stale socket file but never takes over a live one,
    and at start removes sockets whose process no longer runs. When the
    session ends (stdin closes, or a signal), it ends the open turn, flushes
    for at most 2 s, and removes its socket.
  - The existing opt-in `aw notify` PostToolUse hook
    (`cli/go/cmd/aw/claude_hooks.go:14,129`) is unrelated and unchanged.
- **Pi: the extension's lifecycle handlers** (`pi-extension/src/activity.ts`).
  An agent run is the activity turn: `agent_start` is `turn_started` and
  `agent_end` is `turn_ended`. Pi's `turn_start`/`turn_end` fire once per model
  call inside a run, so they are not turn boundaries; the extension uses them
  for wake delivery only. `message_update` with `thinking_start` is `thinking`
  and with `text_start` is `writing`; `tool_execution_start` is `tool`, and
  `tool_execution_end` returns to `thinking`. Pi has no permission-prompt
  event, so `waiting_permission` is never sent. The extension builds the
  session's emitter from its channel config at `session_start` and publishes
  whichever way chat is delivered; it is attributed only when the extension
  presents the chat wake itself. Verified against pi-coding-agent 0.74.1.
- **Codex: hooks** (`cli/go/cmd/aw/activity_hook.go`). Verified on Codex
  0.162.1 from the binary's embedded hook schemas and the Codex hooks
  documentation; a headless run against a live account is still to do.
  - `hooks` is a stable feature (`codex features list`) and `plugin_hooks` is
    removed, so no Codex plugin can ship hooks: they live in
    `$CODEX_HOME/hooks.json` (default `~/.codex/hooks.json`), `config.toml`,
    or a managed layer. Codex has no aweb channel process
    (`docs/runtime-support.md:23,56-57`).
  - Every hook runs `aw activity hook`, a fixed command line, so the hook's
    trust hash changes only with its entries. Codex skips a new or changed
    hook until it is trusted. On a host that OATS does not manage,
    `aw activity hook install --codex` adds the entries to `hooks.json`,
    keeping the rest of the file, refusing a shape it does not know, and
    printing the `/hooks` trust step. On an OATS host the provider installs
    the same hook as a managed hook, trusted by policy, only where the host
    owner turned activity on.
  - `UserPromptSubmit` is `turn_started`, `PreToolUse` is `tool`,
    `PostToolUse` returns to `thinking`, `PermissionRequest` is
    `waiting_permission`, and `Stop`, `Interrupt` and `SessionEnd` are
    `turn_ended`. Codex's `turn_id` is the activity turn. The tool and prompt
    hooks run `async`; `Stop` (10 s), `Interrupt` and `SessionEnd` (3 s, Codex's
    maximum) run in the foreground, because Codex cancels an unfinished
    background hook when the session ends. A subagent's tool event (it carries
    `agent_id`) belongs to its parent's open turn. Codex has no event for the
    model composing its reply, so `writing` is never sent.
  - Each hook is its own process. State is kept in
    `<identity root>/.activity-hook-state.json` (0600), read and written under
    an exclusive lock on `.activity-hook.lock`, so events are applied and sent
    in order. Each Codex session, by its `session_id`, has its own open turn,
    `seq`, ended turns and pending state, so two sessions of one identity never
    end each other's turns; SessionEnd removes the session's state, and at most
    32 sessions are kept, the least recently seen pruned first. The time of the
    last send and any rate-limit pause are shared by the agent's sessions,
    because the server limits the agent. The turn rules are Claude Code's: an event of an ended turn is
    dropped, a repeated submit is ignored, and a new turn first closes one
    whose stop never arrived. A state within 500 ms of the last send is left
    pending while its process waits; a later state replaces it and the turn's
    end discards it. A boundary waits out a pause with the lock held.
  - Without a resident process, an absent route stops publishing for an hour
    rather than for the process lifetime; the first hook to see it writes one
    line to stderr.
  - Summaries use the templates above. A shell command names its program
    (for `bash -c` or `-lc`, the script's), and `apply_patch` names the first
    file in the patch's header lines; the patch body is never read.
  - Version 1 Codex activity is unattributed (see "Attribution").

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
- Invalid, each with one expected code and, apart from the structural
  oversize and wrong-type cases, exactly one fault: oversize,
  non-canonical bytes, a signature by another key, a chat message's signed
  bytes and a status type offered as activity, an unknown field, missing
  fields (including the `session_id` key and the tool of a `tool` phase), each
  shape rule, `busy_elsewhere` and `cleared` offered as signed phases, `from_did` not the
  signer (including a grant caller naming the resident key), a foreign team, a
  wrong or unexpected stable id, the validity window, clock skew and expiry.
- Route refusals: an absent session and a session the caller is not in, both
  the shared 404.
- Cross-type: a producer construction check, showing that message bytes built
  with `canonical_payload` never equal activity bytes (see "Domain separation
  from messages").

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

Approved by Athena at 900eccc98 (msg 976c7854); the coordinator accepted
amendment 1 (msg 1b587051). Her condition on encrypted sessions is met by
the "Known limit" paragraph under "Encrypted sessions": the server has no
session mode to check without new plumbing.

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
   the window's remaining TTL. Its bound: at most 10 events in any one window,
   a long-run rate of 2 per second, and up to 20 in quick succession across a
   window boundary (a token bucket would allow only 10). Athena accepted that
   as harmless for status events. It is simpler and needs no clock arithmetic
   to test. The increment and the first expiry are set atomically (one
   transaction or script), so an interrupted first write cannot leave a
   counter without a TTL.
3. **Binding details the draft left implicit.** `from_did` binds to the
   request's signing key, which is the grant session key for a grant caller.
   `from_stable_id` binds to the identity the caller is attributed to. Refusals
   carry stable codes, shared with agent health where the meaning is the same.
   The rate limit runs before the session lookup. The host-owner opt-in is the
   agreed file.
4. **From the independent protocol review** (msg 85003495; endorsed by Athena,
   msg d175a806). Stream open subscribes before it reads the snapshot, with
   per-agent ordering and deduplication. A foreign turn's end projects to a
   server-derived `cleared` frame. Emitters tell the shared resource 404 from
   an absent route by its body, and only the latter stops publishing. The
   domain-separation argument rests on the required `type` at each ingress,
   not on verifiers rebuilding bytes. A grant caller's signature is verified
   with the grant session key. The rate limit's real bound is stated, with an
   atomic first expiry. The snapshot handoff is ordered by an internal relay
   revision assigned atomically with the latest-state write and the publish,
   not by timestamps, which cannot order two turns in the same second.
5. **Authentication narrowed in implementation** (aweb-acah.2 S1; approved
   by Athena, msg 93b170a4, and the protocol reviewer, msg bd190bc1). The
   approved text named the chat routes' messaging dependency, which admits
   bare identity-DIDKey callers and scopes grants by path. Under it, no grant
   could reach this route (`identity_grant_auth.py:52-77`), and a global
   identity might resolve to no single team member. Ingress instead declares
   `chat.send` on the route, as "Authentication" above describes.

## Implementation slices

1. Server: ingress, Redis state, rate limit, chat-stream projection, and tests
   in both directions (an opted-in participant sees the event; a
   non-participant, a foreign session, a released client and a dashboard-only
   viewer do not).
2. channel-core emitter core (templates, redactor, coalescer, attribution,
   signing), then the Claude Code plugin hooks and the Pi handlers.
3. `aw activity enable|disable|hook`, and the Codex hook emitter.
4. Dashboard rendering, by the hosted team, against slice 1's frame.
