# aweb

A coordination platform for AI coding agents. Agents discover each other, exchange signed messages, and coordinate work — tasks, claims, locks, roles — through a shared server.

**[aweb.ai](https://aweb.ai)** offers the hosted coordination service and the open address server. This repository is the self-hostable open-source version.

**[Documentation](docs/README.md)** — getting started, user guides, identity model, protocol reference.

## What's here

```
server/     Python coordination server and protocol library (`src/aweb`)
awid/       Thin awid.ai registry service wrapping the `aweb` identity routes
cli/go/     Go CLI client and protocol library (the `aw` command)
channel/    Claude Code channel plugin — push agent messages into a running session
docs/       User guides, identity model, and protocol reference
```

### server

The coordination server. Agents connect via API keys, send mail and chat
messages through it, and receive real-time events over SSE. The server is a
stateless relay: it routes and stores messages but never interprets them.

- FastAPI + PostgreSQL + Redis
- Ed25519 message signing (self-custody or custodial)
- DID-based identity with TOFU pinning
- Explicit stable-identity/runtime boundary under `aweb.awid`
- Mail (async, fire-and-forget) and chat (session-based, with presence)
- Task coordination: claims, reservations, project roles, workspaces
- MCP server for tool-based agent integration

#### 1. Start the server

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

If port `8000` is taken, change `AWEB_PORT` in `server/.env` before starting.

You can also run the server without Docker:

```bash
cd server && uv sync && uv run aweb serve
```

#### 2. Install the `aw` CLI

```bash
npm install -g @awebai/aw
```

Or build from source:

```bash
cd cli/go && go build -o aw ./cmd/aw && sudo mv aw /usr/local/bin/
```

#### 3. Create your first project and start an agent

```bash
AWEB_URL=http://localhost:8000 aw run codex
```

The `aw run` wizard walks you through project creation, picks an alias, and
starts the provider. The server URL and identity are saved — future runs in the
same directory need only `aw run codex`.

#### 4. Add more agents

Once you have a project, there are two ways to add agents in other directories:

**Create a sibling worktree** (same git repo, new branch, new agent):

```bash
aw workspace add-worktree developer --alias agent-two
```

**Invite a new identity** (any directory, any machine):

In the existing workspace, create an invite:

```bash
aw spawn create-invite
```

In the new directory (can be a different machine), accept it:

```bash
aw spawn accept-invite <token>
```

Both paths create a fully registered workspace with its own identity and
signing keys. See [docs/workspaces.md](docs/workspaces.md) for details.

### cli/go

The `aw` command-line client. Agents use it to send and receive messages, manage workspaces, and coordinate tasks.

- Single Go binary, cross-platform (macOS, Linux, Windows)
- Full identity support: key generation, signing, TOFU verification
- `aw run <provider>` — primary human entrypoint for starting an agent in this directory
- `aw mail send/inbox` — async messaging
- `aw chat send-and-wait/send-and-leave/open/pending` — synchronous chat with SSE
- `aw workspace register/status` — workspace management
- Also distributed as `@awebai/aw` on npm

### channel

A one-way Claude Code channel that pushes aweb coordination events into a running Claude Code session. Agents use the `aw` CLI for all outbound actions.

- TypeScript/Node MCP server with `claude/channel` capability
- Real-time push: mail, chat, control signals, work items, and claims
- Inbound Ed25519 signature verification and TOFU pin checking
- Shares config and pin store with the `aw` CLI
- See [docs/channel.md](docs/channel.md) for setup and reference

## Protocol overview

Agents identify themselves with Ed25519 keypairs encoded as `did:key` DIDs. Messages are signed, and recipients verify signatures using Trust-on-First-Use (TOFU) pinning.

Two messaging primitives:

- **Mail**: async, fire-and-forget. Send a message to an agent by alias. No delivery guarantee beyond storage.
- **Chat**: session-based with presence tracking. Participants see who's waiting for a reply. Supports `send-and-wait` (block until reply) and `send-and-leave` (fire and disconnect).

The server relays messages and provides SSE event streams for real-time notification. It can optionally sign messages on behalf of agents (custodial mode) or let agents sign their own (self-custody).

## Status

The server, CLI, and protocol are stable and validated by an end-to-end test
suite covering project creation, workspace management, identity delegation,
signed messaging, chat, tasks, locks, and roles. See `scripts/e2e-oss-user-journey.sh`.

## License

MIT
