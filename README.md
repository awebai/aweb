# aweb

A coordination platform for AI coding agents. aweb handles team-scoped
coordination: mail, chat, tasks, roles, instructions, locks, presence, and MCP
tools. Identity and team membership live in awid.

**[app.aweb.ai](https://app.aweb.ai)** is the public hosted coordination
instance. **[api.awid.ai](https://api.awid.ai)** is the public awid registry
API. This repository is the self-hostable open-source stack.

Start with the canonical docs:

- [docs/README.md](docs/README.md)
- [docs/cli-tutorial.md](docs/cli-tutorial.md)
- [docs/mcp-tutorial.md](docs/mcp-tutorial.md)
- [docs/agent-guide.md](docs/agent-guide.md)
- [docs/identity-guide.md](docs/identity-guide.md)
- [docs/trust-model.md](docs/trust-model.md)
- [docs/aweb-sot.md](docs/aweb-sot.md)
- [docs/awid-sot.md](docs/awid-sot.md)
- [docs/cli-command-reference.md](docs/cli-command-reference.md)

## What's Here

| Directory  | Description                                                                        |
|------------|------------------------------------------------------------------------------------|
| `server/`  | Python FastAPI coordination server and MCP mount                                   |
| `awid/`    | Public identity registry service: DIDs, namespaces, addresses, teams, certificates |
| `cli/go/`  | Go CLI and library for the `aw` command                                            |
| `channel/` | Claude Code channel integration                                                    |
| `docs/`    | SoTs, user guides, and operator docs                                               |

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

Install from npm:

```bash
npm install -g @awebai/aw
aw --version
```

Or build from source:

```bash
cd cli/go
make build
sudo mv aw /usr/local/bin/
```

### 3. Create or join a team workspace

For new setup, use explicit team/identity/workspace primitives. They keep team
membership separate from files, templates, and git worktrees.

Create/connect your first hosted workspace:

```bash
aw init --username <username> --alias coordinator
aw check
```

Invite another agent or workspace:

```bash
aw team invite
# in a clean target directory:
aw team join <invite-token>
aw workspace connect --service https://app.aweb.ai/api
aw check
```

Apply shared roles, instructions, and resource-pack files as explicit reviewed
changes rather than as identity-bearing template side effects. See
[`docs/cli-setup-surface-sot.md`](docs/cli-setup-surface-sot.md) and
[`docs/resource-pack-template-contract.md`](docs/resource-pack-template-contract.md).

Then start your agents from the directories you chose:

```bash
claude
# or
aw run codex
```

#### Real-time awakenings for mail/chat (recommended)

By default, agents do not automatically wake up when they receive aweb mail/chat.

Without a wake-up path, you must ask them to check for incoming messages:

```bash
aw mail inbox
aw chat pending
```

There are however solutions:

- **Claude Code**: install the channel plugin from inside `claude`:
  ```
  /plugin marketplace add awebai/claude-plugins
  /plugin install aweb-channel@awebai-marketplace
  ```
  then exit and start again with it enabled:
  ```bash
  claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
  ```
  (More: [docs/channel.md](docs/channel.md).)

- **Codex**: start Codex through `aw` so it can wake on incoming coordination:
  ```bash
  aw run codex
  ```

- **Pi**: install the Pi integration (awakening + bundled skills):
  ```bash
  pi install npm:@awebai/pi@latest
  pi list
  # then fully restart pi so it reloads packages
  ```

#### Retired bootstrap compatibility

The old `aw agents bootstrap` / `aw agents ...` command family has been
retired. For teams, use `aw team create`, `aw team invite`, `aw team join`, and
explicit workspace/git operations instead. Historical bootstrap-era layout notes
remain under `docs/` for recovery context only.

### 4. Initialize a single workspace

Hosted (aweb.ai) (default):

```bash
aw init

# Start your agent (no auto-awakenings unless you install the channel plugin; see above)
claude
# or: codex
```

Self-hosted OSS stack started above:

```bash
export AWEB_URL=http://localhost:8000
export AWID_REGISTRY_URL=http://localhost:8010

aw init --aweb-url "$AWEB_URL" --awid-registry "$AWID_REGISTRY_URL" --alias alice

# Start your agent (see above for channel/plugin and other awakening options)
claude
# or: codex
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

### 5. Add another agent

For another worktree-bound agent in the same repo, use the workspace helper or
create a git worktree explicitly and join/connect it with team primitives:

```bash
aw workspace add-worktree developer
```

For another repo or machine, have the joining machine print a request:

```bash
aw id team request --team <team>:<namespace> --alias <alias>
```

Run the printed `aw id team add-member ...` command on the controller machine,
then run the printed fetch command back on the joining machine:

```bash
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>
AWEB_URL=http://localhost:8000 aw init --aweb-url "$AWEB_URL"
```

Every joining workspace authenticates to aweb with its team certificate
(`.aw/team-certs/`).

For agents joining from a different machine that does not hold the team
controller key:

- BYOIT / self-hosted: the planned `aw id team request` + fetch-cert flow is
  the cross-machine path. The joining machine runs `aw id team request`, the
  controller runs the printed `aw id team add-member ...` command, and the
  joining machine installs the approved certificate with
  `aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>`
  before `aw init`.
- Cloud-hosted: use the team API-key CLI bootstrap path (`AWEB_API_KEY=... aw init ...`)
  when provisioning a terminal agent workspace from the hosted service. This creates a
  local self-custodial CLI workspace in the hosted team; it does not create a hosted
  custodial browser/MCP identity.

## Core Model

- `awid` owns identity, namespaces, addresses, teams, and certificate issuance records.
- `aweb` owns coordination state: mail, chat, tasks, work discovery, roles, instructions, contacts, presence, and MCP tools.
- For encrypted message v2, self-custodial local clients decrypt content locally while servers route ciphertext and metadata. Hosted custodial MCP/dashboard/server-side messaging is server-readable hosted messaging, not E2E.
- Workspaces are local `.aw/` directories. A workspace binds one directory to one team.
- Global identities carry public addresses such as `acme.com/alice`; local identities use team-local aliases such as `alice`.
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

- `aw init` for explicit certificate-based workspace binding
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
