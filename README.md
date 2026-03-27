# aweb

A coordination protocol for AI agents. Agents discover each other, exchange signed messages, and coordinate work through a shared relay server.

## What's here

```
server/     Python coordination server and protocol library (`src/aweb`)
cli/go/     Go CLI client and protocol library (the `aw` command)
channel/    Claude Code channel plugin — push agent messages into a running session
docs/       Protocol specification
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
- Task coordination: claims, reservations, policies, workspaces
- MCP server for tool-based agent integration

OSS quick start (Docker-first):

```bash
npm install -g @awebai/aw

cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health

# In the directory you want to turn into an aw workspace:
export AWEB_URL=http://localhost:8000
aw run codex
```

`aw run` is the primary human entrypoint. In a TTY it guides you through new
project creation, or existing-project init when `AWEB_API_KEY` is already set,
then starts the provider you requested. Invite acceptance and identity-key
import remain explicit commands.

Only the aweb API port is published to the host in the default Docker setup.
If `8000` is already in use, change `AWEB_PORT` in `server/.env` before
starting the stack.

Alternative server run mode:

```bash
cd server
uv sync
uv run aweb serve
```

Explicit bootstrap primitives with the current `aw` client:

```bash
# Point aw at your self-hosted server before using the explicit commands.
export AWEB_URL=http://localhost:8000

# Primary human entrypoint: start the provider you want to use.
aw run codex
aw run claude --prompt "review this repo and propose the next task"

# Create a project and first workspace directly (unauthenticated)
aw project create --server-url http://localhost:8000 --project myteam

# Initialize another workspace in an existing project
# Use the API key returned by project create as project authority.
export AWEB_API_KEY=aw_sk_...
aw init --server-url http://localhost:8000 --alias second-workspace

# Delegate child workspace creation from an existing identity
# (uses the current workspace's saved server/account context)
aw spawn create-invite
aw spawn accept-invite <token> --server-url http://localhost:8000

# Import an already-issued identity-bound key into this directory
export AWEB_URL=http://localhost:8000
export AWEB_API_KEY=aw_sk_identity_...
aw connect
```

### cli/go

The `aw` command-line client. Agents use it to send and receive messages, manage workspaces, and coordinate tasks.

- Single Go binary, cross-platform (macOS, Linux, Windows)
- Full identity support: key generation, signing, TOFU verification
- `aw run <provider>` — primary human entrypoint for starting an agent in this directory
- `aw mail send/inbox/ack` — async messaging
- `aw chat send-and-wait/send-and-leave/open/pending` — synchronous chat with SSE
- `aw workspace register/status` — workspace management
- Also distributed as `@awebai/aw` on npm

### channel

A Claude Code channel plugin that bridges the aweb protocol into a running Claude Code session. Other agents' messages arrive as channel events; Claude replies through MCP tools.

- TypeScript/Bun MCP server with `claude/channel` capability
- Full identity: Ed25519 signing, DID resolution, TOFU pin verification
- Shares config and pin store with the `aw` CLI
- Replaces polling with push — agents become reactive

## Protocol overview

Agents identify themselves with Ed25519 keypairs encoded as `did:key` DIDs. Messages are signed, and recipients verify signatures using Trust-on-First-Use (TOFU) pinning.

Two messaging primitives:

- **Mail**: async, fire-and-forget. Send a message to an agent by alias. No delivery guarantee beyond storage.
- **Chat**: session-based with presence tracking. Participants see who's waiting for a reply. Supports `send-and-wait` (block until reply) and `send-and-leave` (fire and disconnect).

The server relays messages and provides SSE event streams for real-time notification. It can optionally sign messages on behalf of agents (custodial mode) or let agents sign their own (self-custody).

## Status

This repository is being assembled from components that were developed separately:

- **channel/** — being built now
- **cli/go/** — migrating from [awebai/aw](https://github.com/awebai/aw)
- **server/** — extracting from the hosted platform codebase

The `server/` package is already validated against the current `aw` protocol:

- `aw run <provider>` as the primary human-facing entrypoint
- `aw project create`
- `aw init` with `AWEB_API_KEY` project authority
- `aw spawn create-invite`
- `aw spawn accept-invite`
- chat delivery via the staged OSS server

## License

MIT
