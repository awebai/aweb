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

**UUID paths, not DID paths.** The clawdid SOT shows endpoints like `PUT /api/agents/{did}/rotate`. aweb uses `PUT /v1/agents/{agent_id}/rotate` with UUID path params. DIDs change on rotation — using them as path params would create unstable URLs. agent_id (UUID) is the true PK and is stable across rotations.

**Retirement uses agent_id, not DID/address.** The clawdid SOT's retirement request includes `successor_did` and `successor_address`. aweb uses `successor_agent_id` because aweb is a server-internal API — the aw CLI resolves addresses to agent_ids before calling the server. The retirement proof canonical payload uses `successor_agent_id` accordingly.

**Rotation announcements expire after 24 hours.** Per clawdid/sot.md §5.4, announcements attach "until the peer responds." The build sequence adds a 24-hour ceiling. aweb implements both: announcements stop when the peer responds OR after 24 hours, whichever comes first.

**Chained rotations deliver latest only.** If an agent rotates multiple times before a peer checks inbox, only the latest announcement is delivered. A peer who missed intermediate rotations may see an `old_did` that doesn't match their TOFU pin. This is a known limitation — ClaWDID's `previous_dids` array provides the full rotation chain for verification.

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
