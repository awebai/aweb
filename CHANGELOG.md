# Changelog

## Unreleased

- Team-certificate verification is one shared implementation,
  `awid.team_certificate`, used by the server's team auth, the naapp team-auth
  verifier and the hook delivery receiver. A certificate carrying a
  lone-surrogate JSON escape is refused as a failed signature, instead of
  surfacing an encoding error. A naapp certificate header over 8 KiB, or a
  signed payload that is too deeply nested or does not canonicalise, is a 401
  rather than a 500. Server 1.27.30; awid-service needs a release that carries
  the new module.
- `aw chat history <recipient>` applies its limit and unread filter before
  custody decryption, skips unrelated pending previews during session lookup,
  and uses individual request timeouts rather than one budget for the whole page.

## Release preparations

### Release preparation: AWID 0.5.29

Changes are since `awid-v0.5.28` / `awid-service-v0.5.28`.
Publishes PyPI `awid-service` 0.5.29 and the `awid` image 0.5.29.

- Accept controller request envelopes binding the operation, configured public
  audience, HTTP method, external raw path/query and exact body hash, with a
  distinct AWID protocol type and a separate covering parent authorization.
- Keep legacy controller envelopes accepted with per-operation usage counts;
  their retirement requires a separate cutoff.
- Require a matching team-signed certificate blob for every new registration;
  historical blob-free records remain readable.
- Configure `AWID_PUBLIC_ORIGINS` before clients emit v2. Deploy this accepting
  AWID first; current clients remain on the legacy form until that deployment.

### Release preparation: server 1.27.29

Server changes are since `server-v1.27.28`. No CLI change; aw stays 1.36.43.

- Add an operator audit trail for role publication and repo deletion: verified
  actor, principal, authentication mode, target, outcome and request ID, without
  message or playbook content. Successful writes and audit records commit
  together; authenticated refusals are recorded after rollback.
- Supply the shared verified-context audit interface for Cloud's owner/admin
  human-only role/repo writes. Cloud applies that admin policy before mounted
  OSS routes, including certificate and API-key callers; standalone OSS keeps
  its own publication policy. Publish this server package before the Cloud pin.
- Accept target-bound v2 request envelopes for certificate and identity-only
  authentication. Signatures bind the configured public audience, HTTP method,
  external raw path and query, and body hash; identity-only proofs confer no
  team membership. Legacy compact v1 remains accepted and is counted by auth
  family, route template and aw client version. Deploy this server support and
  Cloud's verifiers before publishing the aw client that emits v2; clients must
  not fall back to v1 after a v2 refusal.
- App emit keys, event declarations and the app version projection belong to
  the installing team, and an app id's origin is bound per team (migrations
  024-026). A key registered by one team is never active for another team's
  install of the same app and digest; within a team a key id keeps its first
  did_key (a different one is refused with 409) and a revoked key stays
  revoked. Registry-entry keys and declarations are not carried over, because
  they record no installing team, so app events for existing installs are
  refused (fail closed) until reseeded.
- Add the operator command `aweb reseed-app-registrations --origin <origin>
  [--manifest-file <bytes>]`. It recreates every team's declarations, emit keys
  and version projection from exact manifest bytes that hash to the team's
  pinned digest, never changes subscriptions, reports teams on another digest
  or with a conflicting key id, and exits 1 when any team was left unchanged.
  Deploy: save each installed app origin's manifest bytes before migrating,
  then reseed immediately after, so the refused window lasts minutes.

### Release preparation: aw 1.36.43

CLI changes are since `aw-v1.36.42`. No server change; server stays 1.27.28.

- CLI identity selection now consistently uses `--identity-home`, then
  `AWEB_IDENTITY_HOME`, then the checkout identity. Attached principals can use
  team invite and other command groups without a command allowlist; invalid
  selected homes fail without using checkout credentials. Identity creation
  preserves inherited principals, and plugin helpers retain the selected home.
  Peer-key pins remain in the unchanged user trust store.

### Release preparation: server 1.27.28, aw 1.36.42

Server changes are since `server-v1.27.27`; CLI changes are since `aw-v1.36.41`.

**Rollout order:** publish server 1.27.28 and aw 1.36.42 before the Cloud release that pins them for dashboard chat attachments.

- Managed mail/chat attachments: encrypted-v2 inner descriptors, a transactional
  embedding storage boundary and participant-authenticated fetch APIs; `aw mail
  show`/MCP expose validated descriptors and `aw mail attachment fetch` (and
  `aw chat attachment fetch`) saves verified bytes to an explicit new file.
  Managed files remain server-readable; there is no E2EE attachment claim.
- **Windows init:** `aw init --new-account` now accepts stored forward-slash
  paths before converting them to native filesystem paths. Identity, certificate
  and encryption path helpers keep forward slashes on every OS. Native Windows
  CI covers configuration and local/global init against local HTTP fixtures.
  Thanks to @okfineokfine for the two-layer diagnosis and proposed fix in #61.

### Release preparation: server 1.27.27, aw 1.36.41

Server changes are since `server-v1.27.26`; CLI changes are since `aw-v1.36.40`.

**Rollout order:** publish aw 1.36.41 before deploying the Cloud release
that verifies its workspace-init DIDKey proof. Cloud v0.8.39 already refuses
existing self-custody re-init and has no verifier for this proof; successful
re-init requires both releases.

- **Live agent activity from Codex, and an opt-in switch for every host:**
  `aw activity enable`, `disable` and `show` manage the host owner's opt-in,
  `<identity home>/activity.yaml`, which the Claude channel, Pi and Codex
  emitters read at each turn. `aw activity hook` publishes Codex's turns as
  signed, unattributed activity: phases, tool names and templated summaries,
  never output or arguments. It is coalesced and rate-limited like the other
  emitters, and it stops quietly against a server without the route, which
  first shipped in server 1.27.26. `aw activity hook install --codex` adds
  the hook to `$CODEX_HOME/hooks.json` for hosts that OATS does not manage; Codex runs
  it only after you trust it with `/hooks`. See
  [agent activity](docs/agent-activity.md).
- **The app id `activity` is reserved** for the new command, a stated
  narrowing: the server refuses it at app registration and in app event types.
  Production had zero uses of `activity` in apps, registry entries, event
  types, installs, emitted events and subscriptions when measured on
  2026-10-16. `status` and `status-host`, reserved in server 1.27.24, were
  measured at the same time and also had zero uses.
- **aw negotiates gzip writes with the target server:** an unauthenticated health
  probe enables compression only after an explicit gzip advertisement, cached per
  server base for the process. Signatures cover the original bytes. Older servers
  and bodies above either 1 MiB cap keep plain requests. A compressed write refused
  with 415 or the decoder's invalid-gzip 400 is not replayed, and subsequent writes
  to that base stay plain for the rest of the process. A new process probes again,
  so a server that advertises gzip and then refuses it fails each new process's
  first compressed write. Application 400s keep compression enabled.
- **aw proves it holds the agent's key when it initialises a workspace:**
  `POST /api/v1/workspaces/init` keeps the team API key in `Authorization` and
  adds `X-AWEB-DIDKey-Signature: DIDKey <did:key> <signature>` with
  `X-AWEB-DIDKey-Timestamp`. The signature is the same envelope as cli-signup's, over
  the method, the public path and the SHA-256 of the uncompressed body.
  A team key alone does not prove custody of an existing agent's key. A Cloud
  release with the workspace-init proof verifier can use the new header to
  permit reuse by that key's holder. Cloud v0.8.39 returns 403
  `self_custody_reinit_unproven` even with the new aw; upgrade aw and use a
  proof-capable Cloud release before rerunning the same command. Traces redact
  the new header.
- **aw escapes what servers and senders write before printing it:** in human
  output (`--json` is unchanged), control characters, bidi controls and
  zero-width characters in names, addresses, subjects, bodies and server
  error text print as visible escapes such as `\x1b` or `\u202e`, so a
  received string can neither drive the terminal nor disguise what it says.
  One-line fields also escape line breaks, so a subject cannot forge a row;
  bodies keep their line feeds and tabs. This covers the text output of every
  command, errors, the events stream, chat status lines, `aw run`'s display
  and recap, `aw log`, and the beads and Gas City mail delegates, which
  previously printed `?` for C0 control characters only.
- **Hosted removal requests appear in `--trace`:** the raw Bearer requests
  for member self-retirement and team-admin removal now include redacted HTTP
  request and response details. Authentication and credential selection are
  unchanged.
- **Server: the shared validators refuse a value that ends in a line break.**
  Aliases, human names, branch names, repository origins, the trusted-proxy
  team name, status reason codes, signed-document timestamps and the
  signed-document payload were matched with a Python `$` that also accepts a
  final `\n`. A signed payload whose length was a multiple of four was
  accepted with a trailing line break, a second encoding of the same signed
  document. Such values are now refused.
- **`aw inbound-mode` works from an identity home:** a resident identity's
  owner can read and set who may message it from the custody root that holds
  its key, with `aw --identity-home <custody>/.aw inbound-mode [open|team-and-contacts]`.
  It signs with that key, never with the key of the workspace in the current
  directory. A grant session still cannot change the mode: the server refuses
  grant principals on this route, and aw shows that refusal unchanged.

### Release preparation: AWID 0.5.28

Changes are since `awid-v0.5.26` / `awid-service-v0.5.27`.
Publishes PyPI `awid-service` 0.5.28 and the `awid` image 0.5.28.

- **AWID: team visibility, deletion and revocation no longer hit low per-IP
  limits.** The aweb service, presenting its matching `AWID_SERVICE_TOKEN`, is
  exempt from the `team_update`, `team_delete` and `certificate_revoke` per-IP
  limits, as it already was for team creation and certificate registration, so
  Cloud's visibility pushes and team retirement no longer fail partway. Every
  caller's limits rise from 10/hour to 300/hour for visibility changes and team
  deletion, and from 30/hour to 1000/hour for revocation: each write already
  needs a controller signature, so the budget only stops a runaway client. The
  controller signatures and the deletion refusal while certificates are active
  are unchanged.

### Release preparation: channel 1.8.0, pi 0.4.0

Client changes are since `channel-v1.7.17` and `pi-v0.3.15`. Tag only after
the hosted deployment that runs server 1.27.26 or later.

- **Live agent activity from Claude Code and Pi:** when the host owner opts an
  agent in (`activity: status` in `<identity home>/activity.yaml`; off by
  default, read at each turn), the Claude channel **1.8.0** and Pi **0.4.0**
  publish signed, ephemeral status events to `POST /v1/agents/me/activity`:
  the phase, the tool name and a templated one-line summary, never output,
  arguments or file content, and no summary after an encrypted chat wake.
  Claude Code reports through plugin hooks forwarded over a per-user,
  owner-only socket; Pi through its lifecycle events. A turn is attributed to
  the chat whose wake started it. A grant seat signs with its grant session
  key and needs `chat.send`. Events coalesce to at most one per 500 ms, honour
  the server's rate limit, and stop quietly against a server without the
  route. See [agent activity](docs/agent-activity.md).

### Release preparation: awid-service 0.5.27

Changes are since `awid-service-v0.5.26`.
Publishes the Python `awid-service` package, including its `awid` client library.

- **The Python registry client can change visibility and delete teams:**
  `RegistryClient.set_team_visibility` uses the team controller's signature and
  returns the updated team. `RegistryClient.delete_team` uses the namespace
  controller's signature and returns the deletion acknowledgment; active
  certificates must be revoked first. Both use the domain's registry, and the
  cached client invalidates affected team metadata, certificates and revocations.

### Release preparation: server 1.27.26

Changes are since `server-v1.27.25`.

- **Agents can publish live activity to the chats they serve:**
  `POST /v1/agents/me/activity` accepts a signed, ephemeral `agent_activity`
  event: the phase, the tool name and a short summary of a turn in progress.
  The signer must be the calling agent (an identity with a team certificate, or
  a grant seat whose grant carries `chat.send`). The server checks the frozen
  vector rules, a 2048-byte body cap and a limit of 10 events per agent every
  5 seconds (429 with `Retry-After`). A session the caller is not in gets the
  same 404 as an absent one. Events go only through Redis, never Postgres, and
  without Redis the route answers 503. A chat stream opened with
  `include=agent_activity` carries the other participants' activity, including
  the server-derived `busy_elsewhere` and `cleared` frames. Streams without the
  parameter are unchanged byte for byte, so released clients are unaffected.
  See [agent activity](docs/agent-activity.md).

- **Request decoding preserves application failures:** after sending a bounded
  500 when needed, the outer request-decompression wrapper re-raises unexpected
  exceptions to the ASGI server. An already-started response is never sent twice;
  gzip decoding refusals retain their existing 400, 413 and 415 responses.

### Release preparation: server 1.27.25, aw 1.36.40

Server changes are since `server-v1.27.24`; CLI changes are since `aw-v1.36.39`.

- **The server accepts gzip request bodies:** decoding precedes body hashing
  and authentication, so signatures still cover the original bytes. Every HTTP
  response advertises gzip support. Compressed and decoded bytes each have a
  1 MiB cap; plain requests retain their existing behavior and larger bodies
  can be sent plain. Embedding hosts can wrap their outer app with the same
  ASGI middleware.

- **Hidden resources answer like missing resources:** private conversation and
  chat refusals, cross-team version activation and workspace heartbeat, and
  unauthorized installed-app lookups now return the same 404 as an absent ID.
  Participation is checked before conversation state or type is disclosed, and
  MCP chat refuses without revealing session existence. Dashboard permission
  errors omit the team ID; authentication, grant and messaging policies keep
  their existing behavior.

- **Blocked message errors offer a next step:** an HTML 403 titled “Blocked”
  keeps its status and response identifiers and explains the firewall refusal,
  including how to reword a backticked curl or wget example before sending again.
  Other errors, message content and retry behavior are unchanged.

- **Codex guidance uses the OATS wake path:** joining with `--harness codex`
  installs team instructions without suggesting a session launcher. Codex gets
  mail and chat as they arrive through the OATS host wake broker; without OATS,
  it reads them when asked. Init continues to omit a Codex launch command.

### Release preparation: AWID 0.5.26

Changes are since `awid-v0.5.25` / `awid-service-v0.5.25`.
Publishes PyPI `awid-service` 0.5.26 and the `awid` image 0.5.26.

- **AWID attributes public rate limits through configured proxies:** with valid
  `AWEB_CF_EDGE_CIDRS` and `AWEB_TRUSTED_PROXY_CIDRS`, AWID checks the socket peer
  and rightmost forwarded hop, then derives the client from the complete XFF
  chain. Missing/invalid configuration and malformed chains use the peer.
  First-party private proxy callers are trusted and may choose their rate
  attribution. The unused blanket `AWEB_TRUST_PROXY_HEADERS` and `X-Real-IP`
  paths are removed; token exemptions and write authority are unchanged.

### Release preparation: aw 1.36.39

CLI changes are since `aw-v1.36.38`.

- **Commands honor the API timeout:** ordinary API operations share the normal
  30-second budget, configurable with `AWEB_HTTP_TIMEOUT`, instead of overriding
  it with hidden command deadlines. This includes mail, chat, tasks, workspace,
  registry and coordination operations. Explicit waits and short operational
  probes retain their own deadlines. A timed-out reply source read still sends
  no reply and leaves the source unacknowledged.
- **Failed commands can report where HTTP stalled:** opt-in
  `AWEB_HTTP_DIAGNOSTICS=1` buffers bounded transport and preparation timings and
  emits a diagnostic only if the command fails. Fixed categories distinguish
  expired local budgets, DNS, connection, TLS and response waits without logging
  URLs, headers, bodies or identities. Timeout and retry behavior is unchanged.

### Release preparation: AWID 0.5.25

Changes are since `awid-v0.5.24` / `awid-service-v0.5.24`.

Juan approved this identity-path extension on 2026-10-15 (`aweb-acax`).

- **Trusted services can finish signup beyond the public IP budget:** a matching
  `AWID_SERVICE_TOKEN` now also exempts team creation, certificate registration
  and address registration from per-IP rate limits. Public callers retain the
  existing 10/hour team and 30/hour certificate/address limits. The token grants
  rate allowance only: controller signatures, certificate verification and
  member/address binding checks remain required. See the
  [AWID contract](docs/awid-sot.md#authentication).

### Release preparation: server 1.27.24, aw 1.36.38, channel 1.7.17, pi 0.3.15

Server changes are since `server-v1.27.23`; client changes are since
`aw-v1.36.37`, `channel-v1.7.16` and `pi-v0.3.14`.

- **An agent can name its status host:** `PUT`, `DELETE` and
  `GET /v1/agents/me/status-host` designate, clear or show the one team member
  whose signed status reports speak for the agent (migration
  `020_agent_status_hosts.sql`). The team controller can set or clear it with
  a signed `PUT /v1/agents/{alias}/status-host`, given the current host as a
  precondition. Grant callers are refused. Retiring the agent removes the
  designation. See [agent health](docs/agent-health.md); the signed status
  document's bytes are frozen in `docs/vectors/agent-status-v1.json`.
- **The status host publishes a signed agent status:**
  `PUT /v1/agents/{alias}/status` stores the latest signed status document for
  an agent, from its designated status host or, with none designated, from the
  agent itself (migration `021_agent_status.sql`). The server verifies it
  against the agent-status-v1 rules, binds it to the path agent and the
  authenticated team, requires an increasing `seq`, and allows one publish per
  agent every 5 seconds, outside message metering. A change of verdict fires
  the new `agent.status` mutation hook, which the built-in handler relays to
  the team event stream.
- **Dashboard agent routes show health:** `GET /v1/teams/{team_id}/agents`
  and `/agents/{alias}` carry an additive `health` object
  ([agent health](docs/agent-health.md#reading)). An agent with a stored
  status shows the signed report, `source: "host"`, with `stale` computed on
  every read; a designated host that has not reported yet shows
  `reachable: "unknown"`; any other agent, including one whose host has left
  the team, shows aweb's own observations (next entry) with `source: "aweb"`.
  `health` has the roster's visibility: a public team's anonymous directory
  read includes it, a private team's needs the dashboard token.
- **Health shows aweb's own observations when no host reports:** for an agent
  without a status host or stored report, or whose host has left the team,
  `health` is `{"source": "aweb", "listening", "listening_since",
  "last_active", "connection"}` ([agent health](docs/agent-health.md#fallback-for-agents-without-a-status-host)).
  `listening` says whether the agent holds an open `GET /v1/events/stream`,
  recorded by the stream itself in Redis; `listening_since` is when the
  current state began. `last_active` is the newest of heartbeat presence,
  grant liveness and workspace `last_seen_at`, so an agent that only sends
  grant heartbeats no longer looks inactive on the dashboard. `connection` is
  a grant seat's `identity-grant-status.v1` effective status, shown only to
  readers with a dashboard token valid for the team, and `null` for anyone
  else, including anonymous public reads.
- **Host health publishing clients:** aw **1.36.38** adds
  `aw status-host set|clear|show`, which manages the selected agent's
  designation, and `aw status publish --alias <alias> --document -`, which signs
  and publishes the frozen status document with team-auth v2. JSON output
  preserves refusal codes, messages and retry hints; offline `--print-signed`
  supports vector testing. Claude channel **1.7.17** and Pi **0.3.15** add
  atomic, mode-0600 receive receipts refreshed only on successful stream reads.
  See [agent health clients](docs/agent-health-clients.md).

### Release preparation: server 1.27.23

Server changes are since `server-v1.27.22`.

- **Human task requests stay current:** human team members are supported task
  assignees, covered by create/update/filter regressions. Team `task.created`
  and `task.status_changed` events include `assignee_alias`; reassignment adds
  `task.assignee_changed` with the previous and current assignee, including
  unassignment and implicit claim assignment. Agent and MCP guidance explains
  how to request a decision from the human whose message the agent is acting
  on and receive the answer by mail.

### Release preparation: server 1.27.22

Server changes are since `server-v1.27.21`.

- **MCP mail and chat wake their recipients like HTTP:** `send_mail`,
  `send_chat` (and `send_message_to_contact`) fire `message.sent` and
  `chat.message_sent`, and `check_mail` fires `message.acknowledged` once for
  each message it marks read, through the same `app.state.on_mutation`
  callback and with the same context as the HTTP routes. `mark_chat_read`
  publishes the chat read receipt like the HTTP read route. Before, MCP sends
  and reads published nothing, so a recipient's event stream or a dashboard
  watching it was not woken. An embedder whose `on_mutation` counts or
  meters these events now sees MCP sends too.

### Release preparation: server 1.27.21

Server changes are since `server-v1.27.20`.

- **A member can only heartbeat or update its own workspace:**
  `POST /v1/workspaces/heartbeat` and `PATCH /v1/workspaces/{id}` now answer
  403 "Workspace <id> belongs to another agent." when a team-certificate
  caller names a workspace another agent owns, and change nothing. Before, any
  certified member of the team could refresh another member's presence and
  overwrite its role, hostname and path, which could keep a dead seat looking
  alive. Grant callers were already limited to their own workspace.

### CLI changes since `aw-v1.36.35`

- **`aw events stream` keeps the subscription:** the command reconnects when a
  stream ends at the server's five-minute cap or is cut by a proxy, with
  backoff from 250 ms to 30 s, and runs until Ctrl-C or `--timeout`. Before, it
  exited at the first close, with exit 1 and "unexpected EOF" when the
  connection was cut. `--timeout` and Ctrl-C also end a stream that is open
  and idle. Mail and chat the server announces again on a new connection are
  not printed again while among the newest 10,000 printed. A 4xx refusal other
  than 408 or 429, a grant that ended, and a frame that does not parse stop it
  with the cause; a temporary grant verification outage is retried.
- **Cross-team local sender trust:** received plaintext and encrypted mail from
  a team-local `did:key` sender now verify consistently in `aw`, the channel and
  the wake broker, including resident grant seats. They use the delivery
  server's active sender membership, with signature and resident recipient
  binding checks, without resolving a local label as an AWID address.

- **Custody starts without the network:** `aw custody serve` does no network
  I/O at start. It builds its aweb client on the first request that needs it,
  inside that request; a failure fails that request, is logged with its cause
  and shown by status, and the next request tries again. Before, with
  `AWEB_URL` set, custody probed the server at start, and one failed probe
  left it running and never ready, so launchd or systemd never restarted it.
  `aw custody status` adds a `client` object (`connected`, `last_error`,
  `last_error_at`) and `keys.signing_key_loaded`.
- **API base probe:** resolving `AWEB_URL` tells a web app page (HTTP 2xx
  HTML), which means the URL is not the API, apart from a failing server (a
  5xx, a 429, an HTML error or challenge page, a timeout), which is a temporary
  failure and no longer reads as "no aweb API". The error names what each
  candidate URL answered.

### Release preparation: server 1.27.20

Server changes are since `server-v1.27.19`.

- **Encrypted messages verify by their envelope:** the MCP chat history, the
  `send_chat` wait reply, MCP mail, contact mail and the HTTP inbox now check an
  `encrypted_v2` message's envelope signature and its binding to the row's
  sender, message and conversation. A correctly signed message reads
  `verified`, a tampered one `failed`, and one with no envelope `unverified`.
  Before, chat history showed every encrypted message as `unverified`, and MCP
  mail showed every one as `verified_envelope_v2` without checking. The MCP
  chat history and the `send_chat` wait reply also return the sender's
  `from_address`.

### Release preparation: server 1.27.19

Server changes are since `server-v1.27.16`.

- **MCP mail stays in the existing thread:** `send_mail` with a recipient and no
  conversation ID now continues the active one-to-one mail conversation, like
  the HTTP route. Custody signs or encrypts with that conversation ID; current
  recipient policy still applies. With no active match it creates a conversation.
  This keeps an agent's unprompted mail to its human in their existing thread.
- **Identity grant issuers:** minting an identity grant now requires an
  authenticated identity with a nonblank issuing team-certificate id; without
  one the mint returns 403 and writes nothing. Revoking the issuing
  certificate is what ends a grant early, so a grant without an issuer could
  never be ended that way. Existing grants with no recorded issuer, minted
  before the issuer was stored, keep verifying unchanged.

### Release preparation: server 1.27.16 and CLI 1.36.33

Server changes are since `server-v1.27.15`; CLI changes are since
`aw-v1.36.32`. CLI versioning remains tag-driven.

- **Addressless global senders:** mail and chat preserve an empty public sender
  address while retaining team authorization and display names. Existing local
  sender routing labels and explicit global addresses are unchanged.
- **Plaintext sender addresses:** mail and chat reads preserve an explicit
  sender address when the signed sender field uses a team member name. Member
  names alone are not promoted into public addresses.
- **Received-message verification:** mail and chat verify global senders without
  a public address using their current registry key and active delivery-team
  membership. Participant reads include current sender membership; unavailable
  proof remains unverified. Grant-seat recipients are matched to their resident
  identity rather than their session key.
- **Local custody startup:** local-resident custody starts correctly when its
  working directory is reached through a symlink, including macOS temporary
  directory aliases, using the existing certificate and key material.
- **Wake status writes:** the wake broker writes status atomically using unique
  temporary files, avoiding failures from concurrent writes. Restart the wake
  broker after upgrading to use the fix.

### Release preparation: AWID 0.5.23

Changes since `awid-service-v0.5.22` / `awid-v0.5.22`.

- **Session-settings check startup time:** with
  `AWID_DATABASE_REQUIRE_SESSION_SETTINGS=true`, the startup check now acquires
  each sampling round's connections concurrently instead of one at a time. This
  avoids accumulating connection-establishment latency one connection at a time
  and reduces startup timeouts on slow endpoints. The existing timeout and
  fail-closed behavior remain in force. On failure or timeout, every connection
  already acquired is released. The timeout message names both causes: slow
  connection establishment, or a pooler serving fewer server connections than
  the pool size. Sample count and round width are unchanged.
- No AWID database migration is added, and the bundled `server/src` is unchanged
  since 0.5.22.

### Release preparation: AWID 0.5.22

Changes since `awid-service-v0.5.21` / `awid-v0.5.21`.

- **Database session settings:** new `AWID_DATABASE_REQUIRE_SESSION_SETTINGS`
  makes awid refuse to start unless sampled connections carry the
  `search_path` pin (`pg_catalog`) and pgdbm's `statement_timeout`,
  `lock_timeout`, `idle_in_transaction_session_timeout` and `jit` settings,
  which a connection pooler or Neon can drop silently. The check takes at
  least 20 connection samples in concurrently held rounds sized to the pool,
  and is bounded by `AWID_DATABASE_SESSION_CHECK_TIMEOUT_SECONDS` (default 30).
  `AWID_DATABASE_USES_TRANSACTION_POOLER` bounds the pool for transaction
  poolers (`AWID_DATABASE_POOLER_MAX_CONNECTIONS`, default 10) and turns the
  statement cache off by default; an explicit
  `AWID_DATABASE_STATEMENT_CACHE_SIZE` takes precedence. Both boolean opt-ins
  default off; absent these opt-ins or explicit numeric overrides, existing
  database behavior is preserved. The awid README documents setting the
  values through a direct endpoint's `options` URL parameter or role defaults,
  and that migrations must schema-qualify under the pin.
- **Certificate status:** `GET /v1/namespaces/{domain}/teams/{name}/certificates/{certificate_id}/status`
  returns the current team key and the certificate's active or revoked status,
  for public and private teams, without member identities. It has its own
  `certificate_status` rate-limit bucket.
- No AWID database migration is added. The image also bundles the current
  `server/src`, which includes server migration
  `019_chat_participant_lookup.sql`; awid does not run server migrations.

### Release preparation: server 1.27.15 and CLI 1.36.32

Server changes are since `server-v1.27.14`; CLI changes are since
`aw-v1.36.31`. CLI versioning remains tag-driven.

- **Revocation-only grants:** `aw id grant mint --ttl never` creates a grant
  without clock expiry and is now the default. Explicit finite TTLs remain
  supported. Mint, list and status report `expires_at: "never"`. Upgrade the
  worker and restart its upgraded custody host, which advertises
  `grant_never_ttl.v1`. Scope, subject and issuer checks remain enforced;
  revocation rejects subsequent requests, and open never-grant streams recheck
  on a 30-second cadence. No database migration is required.
- **Certificate verification for independent apps:** a per-certificate AWID
  status read exposes the current team key and revocation status for public and
  private teams without publishing member identities or a roster. Apps still
  verify the certificate signature and fail closed on missing records or
  refresh errors.
- **Local custody and grant messaging:** `aw custody serve` starts from legacy
  local API-key workspaces created by `aw init --alias`, using their existing
  certificate and signing key without creating `identity.yaml`. Local grants
  retain the member name without inventing an address. Plain and encrypted mail
  use the correct resident identity, and conversation matching uses the grant
  subject rather than its session key.
- **Long socket paths:** custody and the wake broker use short private per-user
  sockets when resident or state paths exceed Unix socket limits, including on
  macOS. Existing short paths and explicit locators remain supported. The wake
  broker fails immediately if its control socket cannot start. Restart custody
  and the wake broker after upgrading.
- **Incomplete global initialization:** a hosted response with a different DID
  quarantines partial signing material in a private `.rejected` file instead of
  deleting it. Initialization refuses a new key in that home until the rejected
  state is reconciled. Other incomplete-init failures preserve the original
  partial and explain how to resume.
- **App event subscriptions:** resident `aw plugin install` registers declared
  events and emitter keys and subscribes the installer at each default intent.
  Other residents can opt in with `aw events subscribe`. Updates preserve
  subscription choices. Identity-free discovery installs still populate the
  local store without granting permissions or enabling subscriptions.
- **Test harnesses:** isolate channel and CLI-reference subprocesses from
  inherited identity settings and allow stream timing tests enough time for
  authentication before checking heartbeats or expiry.

### Release preparation: CLI 1.36.31

- Custody status advertises `mail_reply_continuation.v1` when E2EE is
  configured. Consumers should require this op for grant-seat replies to
  unlisted senders; restart custody after upgrading so the running process
  exposes the capability.

### Release preparation: CLI 1.36.30

This CLI-only release covers changes since `aw-v1.36.29`. CLI versioning
remains tag-driven; the server stays at 1.27.14.

- When API discovery encounters a redirect, diagnostics now show a sanitized
  destination and ask you to set `AWEB_URL` to the intended API base.
  Redirects are never followed; credentials, query strings and fragments
  are removed from the displayed destination.
- Agents need aw 1.36.30 or newer to reply to dashboard users. Grant-backed
  agents also require their custody host to run aw 1.36.30 or newer; an older
  host fails closed with upgrade guidance. Encrypted
  `aw mail reply` binds the recipient to the verified source message, so
  humans do not need an agent-roster entry or a public alias. Custody verifies
  the exact stored source itself before authorizing a same-service reply;
  the worker cannot supply a new recipient key or first-contact authority.
- Addressed senders use current identity resolution with source identity
  binding. Addressless senders use the source message's signed key assertion.
  Very late replies fail if that assertion has expired, even if the sender
  has since renewed its key. Ask the sender to send a new message before
  replying. Missing or invalid assertions also fail closed; replies never
  silently fall back to plaintext.

### Release preparation: server 1.27.14

Server-only release covering changes since `server-v1.27.13`.

- **Long mail conversations:** participant clients can request newest-first
  history with `order=desc` and page through older messages using opaque
  cursors. Pages report `has_more` and `next_cursor`, including conversations
  longer than 500 messages. Ordering uses creation time and message ID to
  handle timestamp ties without overlap.
- **Incremental mail polling:** `after_cursor` lets clients retrieve newer
  messages oldest-first and drain bursts across bounded pages. Empty polls
  preserve the cursor. This is live history pagination, not a commit-order
  delivery feed; clients reconcile history to recover late-committing rows.
- Existing clients retain oldest-first ordering, the 200-message default and
  the 500-message page limit. Every page remains participant-authorized and
  read-only; message content and encrypted-message projections are unchanged.
- No schema migration or dependency update is required. CLI, AWID and channel
  versions are unchanged.

### Release preparation: CLI 1.36.29

This CLI-only release covers E2E encryption-key assertion renewal since
`aw-v1.36.28`. CLI versioning remains tag-driven; the server stays at 1.27.13.

- Reading existing mail no longer fails solely because the local encryption
  key's own assertion has expired. Reads warn when it remains expired; key,
  signature and identity-binding checks still apply.
- Automatically re-sign and republish the same key's assertion when it expires
  within 14 days or has already expired. Checks run during eligible CLI root
  pre-run and resident custody startup, hourly and before encrypted sends.
  Renewal does not rotate the key or change its previous-key linkage.
- A failed publication attempt triggers a shared one-hour quiet backoff for
  automatic renewal; explicit encryption-key setup can retry immediately.
  Encrypted sends still require currently valid encryption-key assertions and
  do not fall back to plaintext on renewal failure.
- Invite inspection, help and neutral commands do not trigger renewal network
  activity. Inspection's existing explicit preview behavior is unchanged.
- This release introduces no wire or schema change.

### Release preparation: server 1.27.13 and CLI 1.36.28

Server changes below are since `server-v1.27.12`. CLI 1.36.28 combines the
queued main changes with the released 1.36.25–1.36.27 hotfix range; it is not
only a delta from the 1.36.27 hotfix branch. CLI versioning remains tag-driven.
AWID and channel versions are unchanged by this preparation.

- **Server 1.27.13 — security fix and dashboard contract change:** narrow
  messaging visibility to participants. Remove `GET /v1/teams/{team_id}/messages`.
  Team SSE and `/v1/usage` require a verified dashboard JWT, including for public
  teams. Mail/chat events are no longer published to the team event stream;
  SSE also drops legacy messaging events already queued there. Dashboard Monitor
  no longer receives messaging events. `/v1/status/stream` limits messaging
  events to the authenticated actor's own workspaces; the public-reader marker
  only denies messaging access and cannot grant authority. No SQL schema or
  migration changes accompany this server release; migration 019 belongs to
  server 1.27.12 and retains its separately documented operator-window needs.
- **CLI 1.36.28 — app manifests:** carry forward the bounded, strictly typed v1
  event metadata model. Metadata is preserved without adding CLI event runtime
  behavior or relaxing unknown-field validation.
- **CLI 1.36.28 — naapp grants:** carry forward resident approval on declarative
  app install, origin-pinned finite snapshots at grant mint, actual app inventory
  and per-app exclusions. Legacy explicit per-tool selection remains separate;
  invalid individual catalog apps do not block unrelated grant capabilities.
- **CLI 1.36.28 — mail replies:** carry forward source decryption before reply
  mode selection. Readable encrypted sources receive encrypted replies by
  default; explicit mode flags win. Keyless plaintext replies remain quiet,
  and unreadable encrypted sources fail without a plaintext fallback.
- **CLI 1.36.28 — integration: team join:** opt-in `aw team join --harness`
  configures the selected harness, team documentation, and its hooks or channel.
  `--setup-only` retries setup for an already connected workspace without
  redeeming an invite again or changing membership.
- **CLI 1.36.28 — integration: invite inspection:** `aw team invite inspect`
  reads an invite from stdin without redeeming it or creating identity state.
  Hosted inspection requires the Cloud invite-preview endpoint; installing the
  CLI alone does not make inspection available on an older service.
- **CLI 1.36.28 — integration: spawn authority:** `aw team spawn-authority`
  accepts canonical team IDs and reports bounded, sanitized server details for
  denied requests and servers that do not yet accept that team-ID form.
- **CLI 1.36.28 — integration: custody diagnostics:** report custody client
  initialization failures with distinct diagnostic categories, without changing
  custody authorization, identity selection or retry behavior.
- **CLI 1.36.28 — integration and documentation:** retain queued main behavior,
  including fresh-conversation sends and signed-display verification, alongside
  these hotfixes. Reconcile the generated reply reference and guide index.

### Release preparation: server 1.27.12

Server-only release covering the server changes since `server-v1.27.11`.
CLI, AWID and channel versions are unchanged by this preparation.

- **Fresh mail conversations:** additive `new_conversation` requests require
  an explicit recipient and a fresh client-supplied conversation UUID. They
  bypass automatic thread reuse; missing IDs are rejected with 422 and existing
  IDs with 409. Recipient authorization and signature checks remain unchanged;
  omitted/false retains automatic threading. Client adoption requires a
  compatible CLI and deployment of this server version.
- **Event-stream resilience:** established streams survive short bursts of poll
  failures with 1, 2, 4, then capped 5-second backoff. A complete successful poll
  resets the failure window; a subsequent failure strictly more than 30 seconds
  after the first terminates with the existing error event. Heartbeats and
  disconnect, deadline and grant checks continue during backoff. Initial
  snapshots and cancellation behavior are unchanged.
- **Pending-chat query:** select the viewer's own participant rows before
  session aggregation and message work, preserving DID-first selection,
  departed-participant, unread and wait semantics. This removes the old
  all-session participant expansion; synthetic timings and replica planner
  costs are not a production latency guarantee.
- **Migration 019 — operator window required:** startup applies
  `019_chat_participant_lookup.sql`, adding `idx_chat_participants_did` on
  `chat_participants(did)` and `idx_chat_participants_agent` on
  `chat_participants(agent_id) WHERE agent_id IS NOT NULL`. Both statements are
  plain `CREATE INDEX IF NOT EXISTS`, not concurrent builds, in the normal
  migration transaction. Index creation can wait for conflicting transactions
  and blocks writes to `chat_participants` while building; ordinary reads can
  continue. Locks remain until the migration transaction finishes. Before
  deployment, measure the target table's row count and heap/index sizes and
  inspect long-running transactions. Estimate the window by timing both index
  builds together on a representative restored database with comparable data,
  storage and load, including commit and lock-wait allowance. Small replica
  counts or EXPLAIN costs alone do not establish the production duration.
  Schedule an operator-approved write-blocking window; publication itself does
  not apply this migration, and hosted pin/deployment is a separate operation.
- **Release validation:** strict identity-call and packaged-migration inventories
  include the landed event changes and migration 019. Unexpected controller-key
  mutation-guard outcomes retain complete private evidence without changing the
  child journey or its exactly-one-intended-failure requirement.

- **Next CLI release — signed display integrity:** plaintext mail/chat reads
  fail verification when displayed content or IDs disagree with present signed
  fields, preserving the observed mismatch. Legacy omissions and same-envelope
  signed stable-DID routing projections remain supported. Encrypted-v2 reads
  also bind outer message/conversation IDs to the authenticated envelope.
  Preserve released empty-recipient forms for signed-stable stored routes,
  mail delivered to the reading identity, and its authenticated sent-mail views;
  these compatibility projections do not make unsigned routing a signed claim.
- Fix `aw mail reply` reading encrypted sources without a mode flag; replies preserve source encryption by default, including grant custody, while explicit plaintext/encryption flags remain available.

- Let attached resident agents install and approve declarative apps; new grants inherit the resident’s origin-pinned app catalog and report their actual app inventory. Shared installs and legacy explicit per-tool grants remain compatible.

- Fix declarative app installation rejecting v1 event metadata, including Folio's deployed manifest; preserve strict field validation and bounded event declarations.

### Release preparation: server 1.27.11, CLI 1.36.24, AWID 0.5.21

These entries cover changes since `server-v1.27.10`, `aw-v1.36.23`, and
`awid-service-v0.5.20` / `awid-v0.5.20`, respectively.

- **Server 1.27.11:** conversation lookup persists overdue active conversations
  as expired before rejecting continuation; conversation lists report effective
  expiry even before that lookup. This fixes stale status after an expired-mail
  refusal. No SQL schema or migration changes accompany this server release.
- **CLI 1.36.24 — mail:** automatic threading is opportunistic. When several
  threads match, prefer the newest exact sender/recipient pair; ambiguous
  lookups can fall back to a fresh thread. An automatically selected thread
  rejected with the exact expired-conversation response retries once without
  that thread. Explicit conversation IDs, other authorization failures and
  ambiguous transport failures do not gain that retry.
- **CLI 1.36.24 — wake:** terminal input now refuses an explicit `blocked`
  harness state, preventing wake text from answering a modal. Add opt-in
  `aw wake deregister --require-managed-stop --expect-registration` and the live
  accepted-receiver export in `aw wake status`. Strict completion requires the
  supporting owning daemon, captured worker join and owned process-group
  absence; no file fallback certifies it. Accepted input/command completion
  remains uncertified. Ordinary deregistration stays compatible; installing
  the CLI does not upgrade an existing daemon or certify its previous workers.
- **CLI 1.36.24 — team setup:** `aw id team create` without `--namespace` now
  creates a hosted sibling using the selected team certificate instead of
  failing for a missing namespace. Explicit `--namespace` retains the
  customer-controlled path; hosted authority remains server-decided. Invite
  acceptance adds bounded `--token-stdin` input (65,536 bytes), avoiding token
  exposure in command arguments. Hosted invite traces redact prefixed tokens.
- **CLI 1.36.24 — identity and diagnostics:** E2E key publication stays on the
  selected identity home and preserves its own certificate precedence; holder
  lock commands accept external identity homes. Non-JSON HTTP failures and
  hosted bootstrap failures use bounded diagnostics with response identifiers
  rather than dumping response bodies. Setup documentation joins Beads
  recipients before initialization and documents global-identity recovery.
- **AWID service/package 0.5.21:** configured trusted-service tokens bypass
  registry read rate limits consistently, with aggregated exemption diagnostics.
  Ordinary public limits and mutation authorization remain unchanged. No SQL
  schema or migration changes accompany either AWID release. The server
  publisher requires the exact AWID manifest version, `0.5.21`, to be public on
  PyPI before publishing server `1.27.11`; CLI versioning remains tag-driven.

### Migration compatibility

- The immutable published `011_chat_message_reads.sql` migration can now run on
  existing databases whose legacy read receipts outlived their chat participant.
  An append-only pre-shim preserves the participant foreign key while filtering
  those orphan backfill rows; migration 012 removes the temporary filter,
  repeats the backfill with an explicit participant guard, and restores the
  same final constraint set for fresh and already-011-applied databases.

- New additive migration `017_agents_certificate_id.sql` records the team
  certificate that admitted each agent projection (nullable column; rows
  created before it heal at their next certificate-authenticated connect or
  request). Required by the revocation enforcement below.

### Server compatibility

- Server package `1.27.10` suppresses actionable chat wake events for a session
  while the recipient is already waiting in its chat stream. Other sessions
  remain actionable, and still-unread chat becomes actionable on the next poll
  after the wait ends or its registration becomes stale. Sender waiting and
  read-receipt semantics are unchanged.

- Server package `1.27.9` fixes the first mail after a one-to-one conversation
  expires: automatic reuse skips time-expired conversations and the send starts
  a new thread immediately. Chat reuse also excludes expired or closed canonical
  conversations from the legacy-session fallback; genuine legacy-only sessions
  remain reusable.

- Server package `1.27.8` includes bounded grant-stream verification and clean
  termination on verification failure, fixes child-task reference allocation
  after re-parenting, and keeps legacy chat session reuse scoped to participant
  identity. Reused addresses no longer grant access to an earlier identity's
  private chat session.

- Grant stream opens with an expired, revoked, inactive-subject or revoked-issuer
  grant now return HTTP 403 before headers, instead of HTTP 200 followed by a
  terminal SSE event. Go clients treat either form as an error; wake streams
  quarantine on 403. Chat streams recheck grants every 30 seconds and close with
  `verification_unavailable` if verification fails. Updated clients surface this
  as an explicit retryable error instead of a normal wait timeout.

- Server package `1.27.7` accounts for the server changes accumulated since
  `server-v1.27.6`: one-to-one mail reuse is now identity-only, the reserved
  app-id catalog now includes `auth`, and the README contract test follows the
  current explicit `aw init --new-account` flow. The accompanying CLI release
  carries the wake lifecycle/resource hardening described below.
- One-to-one mail conversation reuse no longer treats a reused alias/address as
  identity continuity. Existing private threads are matched by concrete
  participant identity (agent id or DID) only; a replacement identity that
  reuses an address starts a new thread instead of inheriting the old one.
  Legacy/self-hosted sparse rows with no authoritative identity also fail safe
  by starting a new thread rather than matching by address alone.

- The chat mark-read HTTP endpoint and both canonical/legacy MCP tools now
  accept the deployed-client `up_to_message_id` watermark, the upgraded-client
  `message_ids` list, or both. When both are present, the exact ID list takes
  precedence. This keeps published aw, Claude channel, Pi, and external MCP
  clients compatible with a server-first rollout while allowing future clients
  to send an expand/contract payload that works across server versions.
- The silent-loss race is fixed only for upgraded clients that send every
  presented `message_ids` value. Older clients that send `up_to_message_id`
  retain their existing range-resolution race because the server must infer
  the read set from the watermark; this is their prior behavior, not a new
  regression.

- Certificate revocation is now enforced on every messaging auth form. The
  agents projection records its admitting certificate, and identity-only,
  grant, and MCP identity-auth requests check it against the AWID registry's
  revocations: a revoked member keeps its DID-scoped mailbox but loses team
  context (team attribution, alias sends, team-gated behavior), and a grant
  whose issuing certificate is revoked is refused. Previously a revoked local
  member whose projection survived could keep acting under its team alias by
  omitting the certificate header. Consequences to plan for: identity-auth
  requests that carry team context now share the certificate path's fail-closed
  posture toward the registry (503 when it is unreachable past the cache's
  stale window), and deployments should configure `AWID_SERVICE_TOKEN` so
  revocation refreshes bypass the registry's public per-IP rate limits.
  Limitation: hosted-custody members whose certificates never reach the AWID
  registry are not covered by this check — the staged existence requirement
  below closes that gap once hosted anchoring has backfilled.
- Staged existence-required certificate verification, default off
  (`AWEB_REQUIRE_REGISTERED_CERTIFICATES`). An unregistered team certificate is
  unrevocable — the registry's revocation set can never name it — so once the
  hosted anchoring backfill completes, "not registered at the AWID registry"
  becomes a verification failure rather than a pass by omission. When enabled,
  the presented-certificate path (team routes, connect, MCP), the identity-only
  paths (HTTP and MCP), and a session grant's issuing certificate all require
  registry existence, with verdicts distinct from signature failure and from
  revocation (`Certificate not registered`, `grant issuing certificate not
  registered`). The existence read rides the cached registry client's existing
  team-certificates tier (10-minute freshness, stale-while-revalidate), adding
  no per-request registry round-trip, and fails closed on registry
  unavailability exactly as the revocation check does. Off by default and
  byte-identical to previous behavior with zero added registry calls; enabling
  it in production is an ops act gated on the anchoring backfill's failure
  enumeration being empty or individually remediated.
- Revocation cache refreshes read the complete paginated set. Timestamp-only
  incremental refresh is unsafe because PostgreSQL timestamps reflect
  transaction start: a revocation waiting on a row lock can commit after a
  refresh with an older timestamp and be skipped by a `since` cursor. Fresh
  TTL, stale window, the 15-minute registry-outage grace and its logging,
  fail-closed behavior, and Redis retention are unchanged; a partly-read
  refresh never restamps the cached entry's age.
- Registry cache: background-refresh failures for the team-certificate tier now
  log at warning level with the team, the age of the last-known-good list being
  served, and the underlying error, matching the revocation tier. That tier
  gates every authenticated request once
  `AWEB_REQUIRE_REGISTERED_CERTIFICATES` is enabled, so a registry outage is no
  longer silent there. Logging only: no cache TTL, retention, or outage grace
  changed, and tiers that opt out keep their previous debug-level behavior.
- The AWID team revocation list is completely enumerable: the route paginates
  with a `(revoked_at, id)` cursor and reports `has_more`/`next_cursor`, and
  the Python registry client follows it to the end (with a best-effort `since`
  fallback against pre-pagination servers). Previously the oldest 1000 rows
  were returned with no truncation signal and consumed as the complete set. A
  legacy client that sends no pagination parameters still gets its historical
  1000-row page, never a shorter one. Revocation lists are now cached for 60
  seconds (hard worst case 120 through stale-while-revalidate) instead of 10
  minutes, so a revocation takes effect on enforcement within about a minute;
  raising that constant is a trust-model change (see trust-model.md,
  "Threat-model rulings").
- Registry-outage grace for team revocation reads (owner-adopted 2026-08-17):
  the cached registry client retains the last-known-good revocation set for
  fifteen minutes beyond freshness and, when a refresh fails, serves it while
  the data is at most fifteen minutes old, logging each occurrence at warning
  level with the team, the data's age, and the error; past that age the read
  fails closed (503 upstream) exactly as before. The 60-second fresh TTL, the
  120-second stale-while-revalidate window, and every other cache tier's
  retention are unchanged; the fifteen-minute bound is a pinned constant with
  no configuration knob.
- awid service `0.5.20`: the service-owned shared PostgreSQL pool no longer
  pins `search_path` during startup. Schema isolation still comes from explicit
  schema-qualified database managers/table names, matching the live 0.5.15
  behavior and avoiding startup failure behind deployments that drop or ignore
  the shared-pool startup parameter.
- awid service: team visibility is now enforced on the read side. For teams
  not marked `public`, team get, certificate list, member resolve, and
  revocation list require a same-team path-signature (the certificate
  blob-fetch scheme, from the team controller key or an unrevoked member key)
  or the trusted `AWID_SERVICE_TOKEN`; unauthorized reads return 403 with the
  stable error code `team_private`. Domain team enumeration omits private
  teams for anonymous and unprivileged signed callers. New teams default to
  private at the schema level (unchanged, now load-bearing). Deployments
  running aweb revocation enforcement against private teams must configure
  `AWID_SERVICE_TOKEN`; the blob-fetch route and the controller-signed
  visibility setter are unchanged.

### CLI compatibility

- Add opt-in `aw wake deregister --require-managed-stop --expect-registration`
  with a live accepted-receiver export in `aw wake status`. The strict operation
  confirms captured managed-worker join and owned process-group absence, refuses
  missing/mismatched ownership, and never falls back to files. Transport loss is
  unconfirmed; accepted input/command completion is not certified. Both the CLI
  and owning daemon must support it; ordinary deregistration stays compatible.

- `aw version` respects `AW_NO_UPDATE_CHECK` and skips the update request when
  stdout is not a terminal or `--json` is set. Interactive version checks still
  report available upgrades.

- Registry-backed `team:domain/alias` member reads now use the caller's signing
  key in the CLI and A2A gateway, allowing authorized reads of private teams.
  Forced refreshes remain signed and bypass caches; unsigned and non-member
  reads remain subject to the registry's visibility rules.

- The channel-core wake broker now owns child subprocess pipes explicitly,
  closes partially allocated descriptors on every error path, drains final
  child status before closing parent readers, backs off crash-looping children
  with jitter up to a 60-second cap, and records child-reported liveness into
  the legacy wake state so downgrade rollback does not expire live
  registrations as never-present. Transient resource/read/validation failures
  no longer remove existing durable wake registrations: invalid new
  registrations still never start, while an existing runner whose registration
  file becomes invalid keeps running on its last good configuration until the
  file is corrected or the home is explicitly deregistered. These are bounded
  fixes for measured pipe, retry, retention, and liveness amplification paths;
  the original 491,520-FD owner remains unknown.
- `aw wake deregister` now stops the retired wake runner before removing its
  registration/state, so runner shutdown cannot recreate the deleted instance
  state. Explicit same-home registration reactivates an inactive wake home and
  clears lifecycle errors while preserving intentional pause state; the
  daemon-down registration fallback applies the same lifecycle reset.
- `aw wake` help and terminal-wake documentation now describe the shipped
  shared-core delivery contract: accepted terminal presentation records delivery
  and marks mail/chat read where capabilities permit; recovery after uncertain
  crashes uses exact IDs or read-inclusive pagination, not unread-only replay.
- `aw team invite` now prints the complete porcelain `aw team join` command,
  and `aw team join` installs membership and connects the current workspace in
  one step using the invite's embedded aweb service URL. Hosted servers now
  issue and redeem one versioned, self-describing opaque bearer token unchanged,
  so existing clients can still submit newly issued tokens. New clients also
  accept legacy hosted tokens from older servers and existing local-controller
  tokens. `--no-connect` preserves an explicit membership-only path even when a
  legacy token has no service URL; when the URL is known it prints the exact
  shell-safe recovery command. The low-level `aw id team accept-invite`
  primitive remains membership-only.
- The aw CLI now sends exact chat read IDs first and retries one rejected,
  well-formed request with the legacy newest-ID watermark. Failed fallbacks
  retain the original 4xx, while malformed IDs make only the authoritative
  server request. On older servers the watermark deliberately retains legacy
  range semantics and may mark unpresented messages before it; that trade
  retires when the server accepts exact IDs.
- Session-lease commands now turn a 404 from their lease routes into an explicit
  requirement for aweb server 1.26.28 or later.

- `aw check` on a healthy install now reports `Doctor: ok`. The verdict is
  computed over checks that actually ran: deliberately skipped checks (the
  offline default, or a check with no safe probe) keep per-check status
  `unknown` with `detail.skipped: true`, are counted in a new top-level
  `skipped_checks` field, and no longer force the verdict to `unknown`; `info`
  folds into `ok`. Human output marks them `[skipped]` and names
  `aw check --online`. Consumers of the doctor.v1 JSON `status` field should
  note the tightened semantics (documented in support-tools.md).
- `aw mail show` uses the same certificate-first client selection as
  send/reply, and identity-auth reads verify current-team senders through a
  certificate-authenticated roster resolver when the workspace holds a
  certificate. Previously `aw mail show` alone rendered every verified
  current-team sender as `[verification stale]` on self-hosted pairs. Without
  any certificate the fail-closed stale verdict still applies.
- Team accept/enroll/provision paths now publish the E2E encryption-key
  assertion (to AWID for global identities, to the aweb service where a
  workspace binding exists) and record `published_at`; a publish failure warns
  loudly with the remedy instead of failing the recorded membership. A new
  offline doctor check, `identity.e2ee.assertion_published`, warns when a
  publishable identity has never recorded a publish; `aw id encryption-key
  setup` republishes. Previously provisioning created the key locally and
  never published, leaving counterparties nothing to encrypt to.
- BYOT CLI reads work against private teams. `aw team agent-status`, `aw id
  team members`, agent retirement, and the roster alias fallback now attach
  the same path-signature the certificate blob fetch uses when the invoking
  workspace holds a usable key — its own identity signing key, falling back
  to a locally held team controller key, tried in that order and advancing
  only on the registry's visibility refusal. Public teams and every non-403
  failure are unchanged, and a `team_private` refusal now prints what to do
  (run from a workspace holding a certificate for the team, or ask the team
  controller, who sets visibility) instead of a raw HTTP error.

### Channel compatibility

- Chat mark-read sends exact presented IDs on current servers. When a server
  returns a 4xx for a well-formed exact request, the channel retries once per
  chunk with the legacy watermark; malformed exact requests still surface the
  server's original error without retrying, and a failed fallback preserves the
  original 4xx. This lets auto-updated channels work with older self-hosted
  servers regardless of validation-error wording. The fallback deliberately
  retains old-client range semantics: an old server may mark unpresented
  messages before the watermark read. That trade retires itself when the server
  upgrades and accepts the exact-ID fast path.

## v1.8.1

### awid/aweb separation

- Team membership state moved from `.aw/workspace.yaml` to `.aw/teams.yaml`.
  All `aw id team` commands (add, switch, list, leave, cert show) now operate
  on `teams.yaml` only, fully independent of aweb. Existing workspaces are
  migrated lazily on first access.
- `TeamMembership` is a standalone awid struct with four fields: `team_id`,
  `alias`, `cert_path`, `joined_at`. No aweb concepts (`workspace_id`,
  `role_name`) leak into team state.
- `aw id` registry resolution no longer reads `workspace.yaml` or `AWEB_URL`.
  The chain is: `identity.yaml` registry_url, `AWID_REGISTRY_URL` env var,
  DNS discovery, default `api.awid.ai`.
- `AWID_REGISTRY_URL=local` is now rejected with a clear error.
- DNS-discovered registry URLs are persisted in `identity.yaml` so BYOD
  identities do not re-do DNS on every CLI session.
- `claim-human` moved from the Identity command group to Workspace Setup.

### Identity model

- `identity.yaml` is now written only for persistent identities. Ephemeral
  agents (local init, hosted default, add-worktree) do not create it.
- The messaging client falls back to `.aw/signing.key` when `identity.yaml`
  is absent, deriving the DID via `ComputeDIDKey`.
- `aw id` read-only commands (`resolve`, `verify`, `namespace`) no longer
  require `signing.key` when loading identity for registry URL lookup.
- Validation hardening: empty/malformed `identity.yaml` fails loudly,
  persistent agents with missing `identity.yaml` fail loudly, ephemeral
  fallback rejects certs with empty `member_did_key`.

### Local namespace and onboarding

- awid reserves `local` as a domain that skips DNS verification by policy.
  `namespace_type` column dropped from the awid schema entirely.
- `aw init` with a localhost awid registry automatically uses the implicit
  local flow: namespace `local`, team `default`, ephemeral identity, no
  wizard.
- `--awid-registry` and `--aweb-url` CLI flags override env vars and
  defaults on `aw init`.
- `aw init` with `AWEB_API_KEY` env var exchanges a one-time HMAC bearer
  token for a team certificate. The token is never written to disk. Cert
  signature, DID binding, custody, and lifetime are all validated.
- Self-hosting guide rewritten for two audiences: local quickstart and
  company DNS deployment.

### Signed payload and messaging fixes

- Signed payload `from` field now uses the team cert alias in cert-auth
  mode, not the identity-derived address name. Fixes 422 mismatch when
  identity name differs from team alias.
- Ephemeral agents no longer register DID or address at awid, fixing
  bidirectional mail delivery between ephemeral agents.
- Default coordination server discovery: cert-based `aw init` defaults to
  `app.aweb.ai/api` when the team registry is `api.awid.ai`.
- `normalizeAwebBaseURL` no longer strips `/api` from user-provided URLs.

### New commands

- `aw id team request --team <team_id> --alias <alias>`: prints the exact
  `aw id team add-member` command the team owner should run. Pure awid,
  no workspace dependency.
- `aw id team add-member --did <did:key>`: adds a team member by DID
  (for ephemeral agents without addresses). Supports `--lifetime`,
  `--did-aw`, `--address` for persistent agents.
- `claim-human --username <override>`: works for any awid-registered
  domain, not just `*.aweb.ai`.
- `aw id team reissue-cert <alias>`: mint, register, and optionally install a
  fresh team certificate for an existing member whose signed blob is lost or
  was never registered — same member did:key, alias, and identity scope, new
  certificate id and issued_at. Revokes the currently registered certificate
  first (so the registry's one-active-certificate-per-alias constraint is
  never violated), registers the fresh one after, and is safe to re-run
  across a partial failure. Requires the locally held team controller key;
  this is the blob-lost remedy from the hosted-certificate-anchoring
  contract and is not key rotation — for a lost or compromised member key,
  use `aw team replace-key`.

### Removed from CLI surface

- `aw spawn create-invite` and `aw spawn accept-invite` are no longer
  user-facing commands. The invite code is used internally by
  `aw workspace add-worktree`.

### Server fixes

- MCP auth middleware, team auth, and messaging auth now accept both
  `DatabaseInfra` and raw `AsyncDatabaseManager`, fixing crashes on the
  cloud MCP mount path.

## v1.8.0

This release note covers the user-visible changes between the `v1.7.0`
entry above and `main` at `ec5db2c` on 2026-04-11.

### Upgrade checklist

- Reinitialize or migrate any legacy single-team `.aw/workspace.yaml`
  into the canonical multi-team workspace shape before relying on
  cross-team identity-scoped messaging.
- If you store or validate awid reachability values, update them to the
  canonical set: `nobody`, `org_only`, `team_members_only`, `public`.
- If you construct signed messaging payloads outside the shipped CLI,
  update them to match the enforced signed envelope and recipient
  binding rules described below.
- Regenerate any vendored CLI help or scripted `aw --help` snapshots
  against the current Cobra tree.

### Breaking changes

- Messaging is now identity-scoped end to end. Mail, chat, pending,
  conversations, MCP mail/chat, and channel wake behavior are bound to
  persistent identity (`did:aw`) instead of team-local agent rows.
- Messaging routes now fail closed on signed-payload mismatches. Mail
  and chat reject requests when the outer request disagrees with the
  signed envelope for content, sender identity, recipient identity, or
  chat behavior modifiers.
- Messaging routes now fail closed on conflicting recipient selectors.
  If `to_stable_id`, `to_did`, `to_address`, `to_agent_id`, or
  `to_alias` do not resolve to the same target, the request returns 422
  instead of accepting a precedence override.
- Public address reachability uses the cleaned-up awid enum model:
  `nobody`, `org_only`, `team_members_only`, `public`.

### New features and user-visible behavior changes

- Multi-team workspaces are now the canonical CLI model. Workspaces can
  carry the new team-binding shape, legacy worktrees can be migrated in
  place, and docs/help were updated around the team-scoped workspace
  model.
- Self-hosted local bootstrap now has an implicit localhost path. A
  localhost `awid` registry reserves the `local` namespace, and `aw init`
  accepts explicit `--awid-registry` / `--aweb-url` overrides so one
  command can create the local identity, join `default:local`, and bind
  the workspace.
- Dashboard reads now expose the full team event stream via
  `GET /v1/teams/{team_id}/events/stream`, including `task.created`,
  `task.status_changed`, `task.claimed`, `task.unclaimed`,
  `message.sent`, `agent.online`, and `agent.offline`.
- Dashboard task and agent surfaces were extended with the fields needed
  by the hosted dashboard: claims route, task filtering/pagination,
  creator/assignee detail, parent task IDs, labels, blocker counts,
  updated timestamps, richer agent summaries, and consistent event
  snapshots.
- `GET /v1/conversations` is now identity-scoped under MessagingAuth,
  so human `did:key` / `did:aw` traffic shows up consistently across
  mail and chat instead of disappearing behind team-local filtering.
- Mutation event contexts now carry canonical caller `did:aw` for
  downstream billing and audit attribution.

### Fixes worth calling out

- Signed messaging behavior is now consistent across CLI, REST, SSE,
  MCP, and channel consumers. That includes wait/reply modifiers,
  stable/current DID handling, exact-message wake fetches, and
  second-precision signing timestamps in channel clients.
- Recipient binding now survives local key rotation and current-DID
  targeting, so inbox/history/pending surfaces keep stable sender and
  recipient identity labels across rotation.
- CLI chat/session resolution was hardened to fail closed on ambiguous
  alias/address collisions while still accepting equivalent rows for the
  same identity. Pending, notify, wake, formatter, and session lookup
  paths now share one identity model.
- More than 133 identity-routing and identity-labeling bugs were fixed
  across mail, chat, pending/wake handling, awid transport, and channel
  dispatch.
- Task and conversation routes were tightened to the current schema and
  auth contracts, including null-guarded task timestamps and
  identity-scoped conversation listing.

### Operator and deployment changes

- Team dashboard presence events now publish through the shared
  `team-events:{team_id}` Redis channel instead of being emitted only
  inside a single SSE consumer.
- The OSS docs were updated to describe both team-certificate auth and
  identity-only messaging auth, plus the current signed-payload and
  recipient-binding invariants.

## v1.7.0

This release note covers the user-visible changes between the last deployed
server tag, `server-v1.6.2`, and `main` at `dca0464` on 2026-04-09.

### Upgrade checklist

- Replace `aw init --server ...` with `aw init --url ...` or `AWEB_URL=...`.
- Replace `aw directory --namespace ...` with `aw directory --domain ...`.
- Replace `aw project create` with `aw id team create`.
- Replace `aw spawn accept-invite` with `aw id team accept-invite`.
- If you self-host awid, replace any `awid serve ...` invocations with
  `awid ...` or `uv run awid ...`.
- Re-run `aw init` in any worktree that still has a legacy `.aw/workspace.yaml`.
- If you query aweb tables or MCP tools directly, update `project_*` names to
  `team_*`.

### Breaking changes

- `aw init --server` was removed. Use `--url` or the `AWEB_URL` environment
  variable instead.
- `aw directory --namespace` was renamed to `--domain`. Old scripts now fail
  with Cobra's unknown-flag error until updated.
- `aw project create` was removed. Team creation is now `aw id team create`.
- `aw spawn accept-invite` was removed. Invite acceptance is now
  `aw id team accept-invite`.
- API-key coordination auth was removed. `AWEB_API_KEY` is no longer honored,
  Bearer fallback is gone, and generic coordination requests now use DIDKey
  signatures plus `X-AWID-Team-Certificate`.
- `.aw/workspace.yaml` now enforces the canonical binding shape and hard-fails
  on removed keys instead of silently scrubbing them. Removed keys include
  `server_url`, `api_key`, `did`, `stable_id`, `signing_key`, `custody`,
  `lifetime`, `project_id`, `project_slug`, `namespace_slug`, `identity_id`,
  `identity_handle`, `cloud_url`, `awid_url`, `role`, and other old
  compatibility fields. The fix is to reinitialize the worktree with
  `aw init`.
- Coordination naming is now team-scoped throughout the live surface.
  Database tables were renamed from `project_roles` and
  `project_instructions` to `team_roles` and `team_instructions`. MCP callers
  must pass `team_instructions_id` instead of `project_instructions_id`.
- `POST /v1/connect` now rejects alias collisions with HTTP 409 instead of
  silently overwriting the existing workspace row.
- `aw workspace status` no longer cleans up stale ephemeral identities
  client-side. Cleanup still happens, but it now goes through
  `DELETE /v1/workspaces/{workspace_id}` and the server owns the identity
  removal path.
- `awid serve` was removed. The awid registry CLI now uses Typer's
  single-command form, so self-hosted wrappers, Dockerfiles, and service units
  must invoke `awid --host ... --port ...` or `uv run awid ...` instead of
  `awid serve ...`.

### New features and user-visible behavior changes

- Fresh-directory onboarding was rebuilt around the team architecture model.
  `aw init` and `aw run <provider>` now support:
  - BYOD onboarding for self-hosted or custom-domain teams
  - hosted onboarding for `app.aweb.ai`, including the explicit `aw init --hosted` path
  - reconnecting from an existing `.aw/identity.yaml` plus `.aw/team-cert.pem`
- `aw connect --bootstrap-token [--address ...]` was added for the dashboard
  Add Agent bootstrap flow.
- `aw claim-human --email ...` was added for attaching an email address to a
  hosted account and unlocking dashboard/admin flows after verification.
- `aw workspace add-worktree [role]` was restored as the supported same-repo
  multi-worktree flow. It creates a sibling git worktree with its own
  ephemeral team certificate and connects it to the same team.
- `POST /v1/agents/suggest-alias-prefix` was added so alias allocation happens
  server-side and checks both live agents and workspaces.
- Dashboard reads now have a defined JWT-based auth contract via
  `X-Dashboard-Token` and `AWEB_DASHBOARD_JWT_SECRET`, including public-team
  anonymous reads and fail-closed visibility behavior on registry lookup
  errors.
- Certificate-based coordination auth is now the only supported OSS auth model
  across REST, SSE, MCP, and channel integrations, with revocation-list-aware
  validation.
- `DELETE /v1/workspaces/{workspace_id}` was added for server-owned stale
  ephemeral workspace cleanup.
- The MCP `whoami` tool was restored.

### Fixes worth calling out

- SSE and event-stream behavior were tightened so status/event streams survive
  the body-cache middleware correctly.
- Connect/reconnect behavior is stricter and safer:
  - existing `did:key` identities cannot silently reconnect under a different
    alias
  - connect no longer falls back from alias to role semantics
  - add-worktree now derives registry choice from team controller metadata
- Dashboard reads now keep the intended behavior during awid registry outages:
  anonymous public-team reads fail closed when visibility cannot be checked,
  while authenticated dashboard JWT reads continue to work.
- Garbage collection now deletes all 21 team-scoped tables in foreign-key-safe
  order. Earlier cleanup behavior was incomplete and could fail on teams with
  tasks, workspaces, or related coordination state.

### Operator and deployment changes

- `server/docker-compose.yml` now builds `awid` from the sibling repo path, so
  the compose stack requires the repo-root build context instead of a
  server-only subtree checkout.
- Removed environment variables:
  - `AWEB_API_KEY`
  - `AWEB_CUSTODY_KEY`
  - `AWEB_MANAGED_DOMAIN`
  - `AWEB_NAMESPACE_CONTROLLER_KEY`
- Added environment variable:
  - `AWEB_DASHBOARD_JWT_SECRET`
- The old awid migrate-from-aweb compatibility path was removed from the live
  awid service and schema setup.
