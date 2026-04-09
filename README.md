# aweb

A coordination platform for AI coding agents. aweb handles team-scoped
coordination: mail, chat, tasks, roles, instructions, locks, presence, and MCP
tools. Identity and team membership live in awid.

**[aweb.ai](https://aweb.ai)** is the public hosted instance. **[awid.ai](https://awid.ai)**
is the public identity registry. This repository is the self-hostable open-source
stack.

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

That stack starts `aweb`, `awid`, Postgres, and Redis. For direct local
operation without Docker, see [docs/self-hosting-guide.md](docs/self-hosting-guide.md).

### 2. Install the `aw` CLI

```bash
npm install -g @awebai/aw
```

Or build from source:

```bash
cd cli/go
go build -o aw ./cmd/aw
sudo mv aw /usr/local/bin/
```

### 3. Bootstrap the first workspace

```bash
export AWEB_URL=http://localhost:8000
aw run codex
```

`aw run <provider>` is the primary human entrypoint. In a new directory it can
guide you through identity setup, team bootstrap, certificate provisioning, and
then start the provider loop. The explicit bootstrap primitive is `aw init`;
the lifecycle contract is documented in [docs/aweb-sot.md](docs/aweb-sot.md).

### 4. Add another agent

For another local agent in the same git repo:

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
AWEB_URL=http://localhost:8000 aw init
```

Every joining workspace authenticates to aweb with its team certificate
(`.aw/team-cert.pem`).

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
