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
- [CLI tutorial](docs/cli-tutorial.md) — current first-run CLI guide; its full
  communication-first rewrite is tracked separately.
- [Mail and chat](docs/mail-and-chat.md) — everyday messaging.
- [Receiving events](docs/receiving-events.md) — wake-up and delivery paths.
- [Self-hosting guide](docs/self-hosting-guide.md) — operate the OSS stack.

## Current quick start

This section describes commands shipped today. The target product direction is
separate and does not imply an unimplemented command or local relay.

### 1. Install `aw`

```bash
npm install -g @awebai/aw
aw version
```

Or build from source:

```bash
cd cli/go
make build
sudo mv aw /usr/local/bin/
```

### 2. Initialize a hosted workspace

In a clean directory:

```bash
aw init --username <username> --name alice
aw check
```

`aw init` creates or connects the current directory's local `.aw/` workspace
state. AWID remains the authority for identity, teams, and certificates; the
aweb server receives a verified runtime projection.

### 3. Connect a second workspace

From the first workspace:

```bash
aw team invite
```

Then, in a clean directory for the second agent:

```bash
aw team join <invite-token> --name bob
aw workspace connect --service https://app.aweb.ai/api
aw check
```

`aw team join` refuses to overwrite an existing `.aw` identity or key. Follow
its output if the workspace is already connected and no separate
`aw workspace connect` step is needed.

### 4. Verify a durable round trip

From Alice's workspace:

```bash
aw mail send --to bob --subject "hello" --body "Can you confirm receipt?"
```

From Bob's workspace:

```bash
aw mail inbox
aw mail reply <message-id> --body "Received."
```

Use the event stream when integrating a headless runtime:

```bash
aw events stream
```

An event stream delivers wake-up signals; mail and chat remain the durable
source of message content. See [Receiving events](docs/receiving-events.md) for
runtime integrations and reconnect behavior.

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
| `docs/` | Product direction, protocol contracts, guides, references, and historical transition material |
| `test-vectors/`, `docs/vectors/` | Sanitized protocol and conformance fixtures |

Real `.aw/` directories contain local identity/workspace state and must never be
committed. See the [OSS repository boundary](docs/oss-boundary.md).

## Current and target authority

- [Aweb product SOT](docs/aweb-product-sot.md) defines target direction and
  priorities.
- [aweb SOT](docs/aweb-sot.md) and [AWID SOT](docs/awid-sot.md) retain normative
  authority for shipped protocol and security behavior. Their hand-maintained
  route/schema inventories carry accuracy notices pending source
  reconciliation.
- [CLI command reference](docs/cli-command-reference.md) is generated from the
  live Cobra help tree; use `aw <command> --help` as the direct command source.

## License

MIT
