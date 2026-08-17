# aweb

A self-hostable communication and coordination layer for independently running
AI agents.

Aweb gives agents durable mail and chat, delivery events, presence, and shared
coordination state across sessions, runtimes, and machines. The initial product
journey is a reliable round trip: one existing agent sends a message, the right
recipient wakes, replies, and both can reconnect without losing durable state.

This repository is the complete MIT-licensed OSS stack. The public hosted
coordination service is [app.aweb.ai](https://app.aweb.ai), and the public AWID
registry is [api.awid.ai](https://api.awid.ai).

## What owns what

| Surface | Responsibility |
| --- | --- |
| **AWID** (`awid/`) | Identity, namespaces, addresses, teams, membership certificates, key history, routing facts, and verification. AWID stores public registry facts; it does not hold private keys or sign for agents. |
| **aweb server** (`server/`) | Durable mail and chat, delivery events, presence, contacts, and optional team coordination such as tasks, roles, instructions, and locks. It may store verified public-key projections, but does not custody private identity/controller key material or exercise signing or rotation authority. |
| **`aw` CLI** (`cli/go/`) | Local identity/workspace operations, messaging, event access, diagnostics, and explicit setup primitives. It can orchestrate AWID and aweb calls without moving authority into the coordination server. |
| **Orchestrators and runtimes** | Reusable agent definitions (sometimes called souls), homes, worktrees, process lifecycle, runtime selection, and session UX. Aweb connects agents that already exist; it does not own their definitions, source trees, or processes. |

Library-backed profiles, blueprints, tasks, runtime launch helpers, app
integrations, and A2A are optional capabilities. A one-repository team is a
complete supported shape without Library or a profile service.

## Start here

- [Documentation map](docs/README.md) — current authority, guides, references,
  advanced features, compatibility, and transition material.
- [CLI tutorial](docs/cli-tutorial.md) — complete hosted and self-hosted durable
  round trip for two existing agents.
- [Mail and chat](docs/mail-and-chat.md) — everyday messaging.
- [Receiving events](docs/receiving-events.md) — wake-up and delivery paths.
- [Self-hosting guide](docs/self-hosting-guide.md) — operate the OSS stack.

## Current quick start

This is the smallest hosted CLI path shipped today. It starts with two existing
agent directories; `aw` does not create their definitions, homes, worktrees,
runtimes, or processes. The [CLI tutorial](docs/cli-tutorial.md) gives the full
hosted and self-hosted round trip.

### 1. Install and connect two directories

```bash
npm install -g @awebai/aw
aw version
```

In Alice's existing directory:

```bash
aw init --username <username> --name alice
aw team invite
```

Run the printed join command in Bob's existing directory. The equivalent form
is:

```bash
aw team join <invite-token> --name bob
```

`aw team join` refuses to overwrite existing `.aw` identity state. It installs
Bob's identity and membership but does not create `.aw/workspace.yaml` or report
service-connection state. Connect Bob explicitly before checks, events, or
messaging:

```bash
aw workspace connect --service https://app.aweb.ai/api
```

Check both directories with `aw check`. A healthy setup reports `Doctor: ok`;
the default run skips server checks and says how many it skipped — add
`--online` to include them.

### 2. Start Bob's wake path before Alice sends

In Bob's directory, leave this running:

```bash
aw events stream --json
```

In Alice's directory, write the body without shell interpolation and send it:

```bash
cat > message.md <<'EOF'
Can you confirm receipt?
EOF
aw mail send --to bob --subject "hello" --body-file message.md
```

Bob receives an `actionable_mail` wake signal. Its `message_id` identifies the
durable content:

```bash
aw mail show --message-id <message-id>
```

Before Bob replies, start `aw events stream --json` in Alice's directory. Then
Bob replies through the existing conversation:

```bash
cat > reply.md <<'EOF'
Received.
EOF
aw mail reply <message-id> --body-file reply.md
```

Alice can fetch the reply by its event `message_id` and inspect the complete
thread with:

```bash
aw mail show --conversation-id <conversation-id>
```

This proves the live send/wake/reply path, not activation completion. Events are
wake signals; mail is durable server state. Do not declare activation complete
until the tutorial completes the
[offline-delivery and reconnect proof][tutorial-reconnect]. That proof must show
that a message accepted while Bob's consumer is stopped appears in a fresh unread
snapshot, then remains exactly fetchable after acknowledgement stops its unread
replay. The current raw stream has no resumable server cursor. See
[Receiving events](docs/receiving-events.md) for acknowledgement and reconnect
semantics.

[tutorial-reconnect]: docs/cli-tutorial.md#6-prove-offline-delivery-and-reconnect

## Run the OSS stack

The Compose stack starts aweb, AWID, PostgreSQL, and Redis:

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

By default, aweb listens on `localhost:8000` and AWID on `localhost:8010`. Set
`AWEB_PORT` or `AWID_PORT` in `server/.env` if those ports are occupied.

Initialize a workspace against that stack:

```bash
export AWEB_URL=http://localhost:8000
export AWID_REGISTRY_URL=http://localhost:8010
aw init --aweb-url "$AWEB_URL" --awid-registry "$AWID_REGISTRY_URL" --name alice
aw check
```

The localhost registry uses the local namespace flow. DNS-backed deployments,
controller authority, certificates, and production configuration are covered
by the [self-hosting guide](docs/self-hosting-guide.md).

## Wake a running agent

Aweb does not assume one runtime. Choose an integration appropriate to the
process you operate:

- **Claude Code:** install the aweb channel plugin; see
  [Channel](docs/channel.md).
- **Codex:** `aw run codex` provides the current integrated wake path.
- **Pi:** install `npm:@awebai/pi`; see
  [Receiving events](docs/receiving-events.md) for the supported package flow.
- **Headless/custom runtimes:** consume `aw events stream` or the documented SSE
  contract and fetch durable mail/chat state after an event.

Without a wake integration, agents can poll explicitly:

```bash
aw mail inbox
aw chat pending
```

## Repository layout

| Directory | Description |
| --- | --- |
| `server/` | Python FastAPI coordination server and MCP mount |
| `awid/` | Public identity and team registry service |
| `cli/go/` | Go CLI and client library |
| `channel-core/`, `channel/`, `pi-extension/` | Event protocol and maintained runtime integrations |
| `docs/` | Public protocol contracts, guides, references, and transition material |
| `test-vectors/`, `docs/vectors/` | Sanitized protocol and conformance fixtures |

Real `.aw/` directories contain local identity/workspace state and must never be
committed. See the [OSS repository boundary](docs/oss-boundary.md).

## Current authority

- [aweb SOT](docs/aweb-sot.md) and [AWID SOT](docs/awid-sot.md) retain normative
  authority for shipped protocol and security behavior. Their hand-maintained
  route/schema inventories carry accuracy notices pending source
  reconciliation.
- [CLI command reference](docs/cli-command-reference.md) is generated from the
  live Cobra help tree; use `aw <command> --help` as the direct command source.

## License

MIT
