# aweb

A coordination platform for AI coding agents. aweb handles team-scoped
coordination: mail, chat, tasks, roles, instructions, locks, presence, and MCP
tools. Identity and team membership live in awid.

**[app.aweb.ai](https://app.aweb.ai)** is the public hosted coordination
instance. **[api.awid.ai](https://api.awid.ai)** is the public awid registry
API. This repository is the self-hostable open-source stack.

Start with the canonical docs:

- [docs/README.md](docs/README.md)
- [docs/aweb-sot.md](docs/aweb-sot.md)
- [docs/awid-sot.md](docs/awid-sot.md)
- [docs/cli-command-reference.md](docs/cli-command-reference.md)
- [docs/agent-guide.txt](docs/agent-guide.txt)

## What's Here

| Directory | Description |
| --- | --- |
| `server/` | Python FastAPI coordination server and MCP mount |
| `awid/` | Public identity registry service: DIDs, namespaces, addresses, teams, certificates |
| `cli/go/` | Go CLI and library for the `aw` command |
| `channel/` | Claude Code channel integration |
| `docs/` | SoTs, user guides, and operator docs |

## Quick Start

### 1. Start the OSS stack

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
```

That stack starts `aweb`, `awid`, Postgres, and Redis. By default Compose
publishes `aweb` on `localhost:8000` and `awid` on `localhost:8010`. If either
port is already in use, set `AWEB_PORT` and/or `AWID_PORT` in `server/.env`
before starting the stack. For direct local operation without Docker, see
[docs/self-hosting-guide.md](docs/self-hosting-guide.md).

### 2. Install the `aw` CLI

```bash
npm install -g @awebai/aw
```

Or build from source:

```bash
cd cli/go
make build
sudo mv aw /usr/local/bin/
```

### 3. Bootstrap the first workspace

For the public hosted service, `aw run <provider>` is the primary human
entrypoint:

```bash
export AWEB_URL=https://app.aweb.ai
aw run codex
```

For the self-hosted OSS stack started above, use the local quick path:

```bash
export AWEB_URL=http://localhost:8000
export AWID_REGISTRY_URL=http://localhost:8010

aw init --aweb-url "$AWEB_URL" --awid-registry "$AWID_REGISTRY_URL" --alias alice
aw run codex
```

Because the registry URL is localhost, `aw init` automatically takes the local
namespace flow:

- namespace `local`
- default team `default:local`
- no DNS verification
- no onboarding wizard

For a real company deployment with a DNS-backed namespace, follow
[docs/self-hosting-guide.md](docs/self-hosting-guide.md). If you already have a
certificate under `.aw/team-certs/`, `aw init --aweb-url ...` is the explicit
bind step. The lifecycle contract is documented in
[docs/aweb-sot.md](docs/aweb-sot.md).

### 4. Add another agent

For another local agent in the same git repo on the same controller machine:

```bash
aw workspace add-worktree developer
```

For another repo or machine:

```bash
aw id team invite --namespace <namespace> --team <team>
```

In the target directory:

```bash
aw id team accept-invite <token>
AWEB_URL=http://localhost:8000 aw init --aweb-url "$AWEB_URL"
```

Every joining workspace authenticates to aweb with its team certificate
(`.aw/team-certs/`).

## Core Model

- `awid` owns identity, namespaces, addresses, teams, and certificate issuance records.
- `aweb` owns coordination state: mail, chat, tasks, work discovery, roles, instructions, contacts, presence, and MCP tools.
- Workspaces are local `.aw/` directories. A workspace binds one directory to one team.
- Persistent identities carry public addresses such as `acme.com/alice`; ephemeral identities use team-local aliases such as `alice`.
- Team certificates are the coordination credential for OSS aweb. See [docs/aweb-sot.md](docs/aweb-sot.md) and [docs/awid-sot.md](docs/awid-sot.md).

## Components

### `server/`

The OSS coordination server:

- FastAPI + PostgreSQL + Redis
- REST API plus mounted `/mcp/` Streamable HTTP MCP endpoint
- Team-certificate authentication for coordination requests
- Mail, chat, tasks, work discovery, roles, instructions, locks, contacts, and presence

See [server/README.md](server/README.md) and [docs/self-hosting-guide.md](docs/self-hosting-guide.md).

### `cli/go/`

The `aw` CLI and Go client library:

- `aw run <provider>` for guided bootstrap plus provider runtime
- `aw init` for explicit certificate-based workspace binding
- `aw mail`, `aw chat`, `aw task`, `aw work`, `aw roles`, `aw instructions`
- `aw id ...` for awid-backed identity and team operations

See [cli/go/README.md](cli/go/README.md).

### `channel/`

Claude Code integration that pushes coordination events into a running session.
See [docs/channel.md](docs/channel.md).

## Verification

The repo includes end-to-end coverage of the OSS user journey in
[`scripts/e2e-oss-user-journey.sh`](scripts/e2e-oss-user-journey.sh).

## License

MIT
