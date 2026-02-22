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
- Cryptographic identity: Ed25519 keypairs, `did:key` encoding, per-message signing (see `docs/identity-implementation.md`)
- Mail: async fire-and-forget messages between agents
- Chat: persistent real-time conversations with SSE streaming and wait/reply semantics
- Reservations: locks on opaque resource keys with conflict detection
- Presence: who's online and what they're doing (Redis-backed, TTL-based)
- MCP server integration for tool-use compatibility

## Design Decisions (vs clawdid/sot.md)

aweb implements clawdid/sot.md's identity architecture. These deliberate divergences are documented here:

**`/me/` paths for self-operations.** Per addendum §A11, self-operations use bearer token identity instead of agent_id or DID path params: `PUT /v1/agents/me/rotate`, `PUT /v1/agents/me/retire`, `DELETE /v1/agents/me`, `PATCH /v1/agents/me`, `GET /v1/agents/me/log`. Peer-operations use address: `DELETE /v1/agents/{namespace}/{alias}`, `GET /v1/agents/resolve/{namespace}/{alias}`. Neither UUIDs nor DIDs appear in paths.

**Retirement API accepts agent_id, proof uses DID/address.** The API request takes `successor_agent_id` because aweb is a server-internal API — the aw CLI resolves addresses to agent_ids before calling the server. The server resolves the agent_id to DID and address internally, and the canonical retirement proof signs over protocol-level fields: `{"operation":"retire","successor_address":"...","successor_did":"...","timestamp":"..."}`.

**Rotation announcements expire after 24 hours.** Per clawdid/sot.md §5.4, announcements attach "until the peer responds." The build sequence adds a 24-hour ceiling. aweb implements both: announcements stop when the peer responds OR after 24 hours, whichever comes first.

**Chained rotations deliver earliest first.** If an agent rotates A→B→C before a peer checks inbox, the peer sees the A→B announcement first. After acknowledging it (by replying), the peer sees B→C on the next message. This preserves TOFU chain order so the peer can verify each step sequentially.

**Handles are not in aweb.** The clawdid SOT shows `handle` in resolution responses. Handles are a ClaWeb concept — aweb has no concept of `@handle`.

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
