# aweb server

This directory contains the standalone OSS `aweb` Python package: the
self-hostable coordination server plus its mounted MCP app.

The package includes:

- the FastAPI server (`aweb.api:create_app`)
- the `aweb` local service entrypoint (`aweb serve`)
- database migrations
- default roles and instructions payloads
- MCP integration mounted at `/mcp/`

For the canonical contract, read:

- [../docs/aweb-sot.md](../docs/aweb-sot.md)
- [../docs/awid-sot.md](../docs/awid-sot.md)
- [../docs/self-hosting-guide.md](../docs/self-hosting-guide.md)

## Run Locally

Recommended OSS path: Docker Compose.

```bash
cp .env.example .env
echo "AWID_SERVICE_TOKEN=$(openssl rand -hex 32)" >> .env
docker compose up --build -d
curl http://localhost:8000/health
```

That stack runs `aweb`, `awid`, Postgres, and Redis together. It publishes aweb
on `localhost:8000` and AWID on `localhost:8010` by default.

Direct `uv` mode is also supported:

Generate the shared secret once and keep it outside the repository:

```bash
AWID_TOKEN_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/aweb/awid-service-token"
mkdir -p "$(dirname "$AWID_TOKEN_FILE")"
if [ ! -s "$AWID_TOKEN_FILE" ]; then
  umask 077
  openssl rand -hex 32 > "$AWID_TOKEN_FILE"
fi
```

In the AWID service terminal:

```bash
cd ../awid
uv sync
AWID_TOKEN_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/aweb/awid-service-token"
export AWID_SERVICE_TOKEN="$(tr -d '\r\n' < "$AWID_TOKEN_FILE")"
uv run awid
```

In the aweb service terminal:

```bash
cd ../server
uv sync
export AWID_REGISTRY_URL=http://localhost:8010
AWID_TOKEN_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/aweb/awid-service-token"
export AWID_SERVICE_TOKEN="$(tr -d '\r\n' < "$AWID_TOKEN_FILE")"
export APP_ENV=development
uv run aweb serve
```

## Runtime Inputs

### HTTP request compression

The server advertises `Accept-Encoding: gzip` on every HTTP response, including
`GET /health` and errors. It accepts gzip request bodies before logging, body
hashing and authentication. Sign the original uncompressed bytes. Both the
compressed input and decoded body have a hard 1 MiB limit; an oversized gzip
request returns 413, invalid or truncated gzip returns 400, and an unsupported
`Content-Encoding` returns 415. Concatenated gzip members share the same limits.
The decoded request has no `Content-Encoding` or `Transfer-Encoding` header and
has a corrected `Content-Length`.

Absent or `identity` encoding keeps the existing plain-body behavior, including
larger writes. Clients should compress only after discovering the advertisement
from that server's `/health`, and send the body plain if either its original or
compressed byte count exceeds 1 MiB. A large plain request can still meet an
upstream firewall's content filter; compression does not remove that limitation.

Embedding hosts can use `aweb.request_compression.RequestDecompressionFastAPI`
with the usual FastAPI constructor arguments. It wraps the completed middleware
stack, including framework error handling. Alternatively, wrap a completed ASGI
stack with `RequestDecompressionMiddleware` from the same module. Place it
outside logging, rate limiting and authentication; using `add_middleware` alone
misses framework-generated 500s. Nested wrappers are safe, advertise once, and
leave websocket and lifespan traffic untouched.

Common environment variables:

- `AWEB_DATABASE_URL` or `DATABASE_URL`
- `AWEB_REDIS_URL` or `REDIS_URL`
- `AWID_REGISTRY_URL`
- `AWID_SERVICE_TOKEN` required >=32-byte trusted caller secret shared with the
  configured home AWID registry
- `AWEB_HOST`
- `AWEB_PORT`
- `AWEB_DASHBOARD_JWT_SECRET`

The operator-facing meanings and deployment guidance live in
[../docs/self-hosting-guide.md](../docs/self-hosting-guide.md).

### Core hook signing

Core uses a dedicated operator key for hook events and delivery credentials.
Set `AWEB_HOOK_PRODUCER_KID` and `AWEB_HOOK_PRODUCER_KEY_FILE` together. The
file contains a generated Ed25519 seed as 64 hex characters, optionally with
one trailing newline; it must be regular and not writable by group or others.
The shared naapp key loader performs these checks. Never select a team
controller or member key for this purpose.

Publish the same kid and its public `did:key` in `AWEB_HOOK_PRODUCER_KEYS`, a
JSON list whose entries have exactly `kid`, `did_key`, `valid_from` and
`valid_until`. Times use `YYYY-MM-DDTHH:MM:SSZ`; `valid_until` may be null.
The signing key must match that public entry and be inside its validity
window. Configure `AWEB_PUBLIC_ORIGIN` to the server's public HTTPS origin.
The anonymous `/v1/hooks/producer-keys` endpoint keeps retired public keys
discoverable for verification. Drain the hooks outbox before changing the
signing key: retries keep the event's original signed bytes and key.

The hooks drain runs in both server lifespans and stops before database
shutdown. A host that mounts core without entering its lifespan must call
`aweb.hook_producer.start_core_hooks(app, db)` after initialization and
`await stop_core_hooks(app)` before closing the database. Its default egress
allows public HTTPS destinations only. A self-hosted embedding host can pass
its configured `egress` and `internal_cidr`; both are required to allow that
internal network.

Mutations with no eligible active registration enqueue nothing and require
no signing key. With an eligible registration, the event and the effect share
one transaction: a recording failure rolls both back. The existing
`on_mutation` notification seam is independent.

## Bootstrap Flow

Point the CLI at the self-hosted server:

```bash
export AWEB_URL=http://localhost:8000
```

Supported OSS bootstrap paths:

```bash
# Guided BYOD bootstrap in a TTY on a self-hosted server
aw init --url "$AWEB_URL"
aw mail inbox
aw chat pending

# Explicit bootstrap after accepting a team invite
aw id team accept-invite <token>
AWEB_URL=http://localhost:8000 aw init
```

On a plain self-hosted server, the guided path switches to BYOD because managed
`aweb.ai` onboarding is not available. Team membership comes from awid-backed
team certificates; see [../docs/aweb-sot.md](../docs/aweb-sot.md) for the
canonical connect/auth contract.

If you need to create the team first:

```bash
export AWID_REGISTRY_URL=http://localhost:8010
aw id create --name <name> --domain <domain> --registry "$AWID_REGISTRY_URL"
aw id team create --namespace <namespace> --name <team> --registry "$AWID_REGISTRY_URL"
aw id team invite --namespace <namespace> --team <team>
```

See [../docs/aweb-sot.md](../docs/aweb-sot.md) for the lifecycle contract and
[../docs/self-hosting-guide.md](../docs/self-hosting-guide.md) for the operator runbook.

## Release to PyPI

Release the `aweb` Python package through the repository's `release` skill and
driver. The driver owns planning, exact-byte staging, publication, tagging,
registry verification, and the receipt; do not start a release by pushing a
`server-vX.Y.Z` tag.

## Identity Boundary

Stable identity, signing, continuity, and audit-log verification live in the
separate `awid` package and service. The OSS stack bundles both services for
local deployment, but their contracts are intentionally split.
