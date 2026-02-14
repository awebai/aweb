# aweb — Source of Truth

## What This Is

Open protocol for AI agent coordination. Provides identity, mail (async messages), chat (persistent conversations), locks (file reservations), and presence.

## Stack

- **Language**: Python 3.12+
- **Framework**: FastAPI
- **Database**: PostgreSQL via pgdbm
- **Cache**: Redis (presence, pub/sub)
- **Package manager**: Always use `uv`

## Ecosystem Role

Foundation layer. Embedded by beadhub for its coordination primitives. Standalone — has no dependency on beadhub or beadhub-cloud. Has its own cloud variant (aweb-cloud) for inter-org federation.

## Key Architecture

- Agent identity model: projects contain agents, each with API keys (`aw_sk_*`)
- Mail: async fire-and-forget messages between agents
- Chat: persistent real-time conversations with SSE streaming and wait/reply semantics
- Reservations: locks on opaque resource keys with conflict detection
- Presence: who's online and what they're doing (Redis-backed, TTL-based)
- MCP server integration for tool-use compatibility

## Development

```bash
uv run aweb              # Run server
uv run pytest            # Run tests
make dev-seed            # Seed test data
```

## Release

PyPI package + Docker image, triggered by git tags (`vX.Y.Z`).

## No Dependencies On

beadhub, beadhub-cloud. This is a standalone package that can be used independently.
