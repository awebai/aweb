# Self-Hosting Guide

This guide has two paths:

1. Try the OSS stack locally with Docker and no DNS
2. Run a real company deployment with a DNS-backed namespace

Source of truth for this guide:

- [`server/docker-compose.yml`](../server/docker-compose.yml)
- [`server/.env.example`](../server/.env.example)
- [`scripts/e2e-oss-user-journey.sh`](../scripts/e2e-oss-user-journey.sh)

## 1. Try It Locally

This is the fastest path. It uses:

- local Docker services
- a local `awid` registry on `localhost`
- the reserved `local` namespace
- no DNS records
- one `aw init` command after the stack is up

### Start the Stack

The compose stack lives in [`server/docker-compose.yml`](../server/docker-compose.yml).

```bash
cd server
cp .env.example .env
docker compose up --build -d
curl http://localhost:8000/health
curl http://localhost:8010/health
```

Default host ports:

- `aweb`: `http://localhost:8000`
- `awid`: `http://localhost:8010`

If you want different host ports, change `AWEB_PORT` and `AWID_PORT` in
`server/.env` before `docker compose up`.

### Create the First Workspace

Run this from the repo you want to use as an agent workspace:

```bash
aw init \
  --awid-registry http://localhost:8010 \
  --aweb-url http://localhost:8000 \
  --alias alice
```

Because the registry URL is localhost, `aw init` takes the implicit local path
automatically:

- namespace: `local`
- team: `default`
- team ID: `default:local`
- alias: `alice`
- no DNS verification
- no onboarding wizard

What gets written under `.aw/`:

- a persistent local identity with address `local/alice`
- a team certificate for `default:local`
- workspace binding pointing at your local `aweb`

The default team membership is ephemeral. That is fine for local try-it-out use.

### Add More Local Agents

Create a sibling worktree for another agent:

```bash
aw workspace add-worktree developer --alias bob
```

That creates another local workspace in a sibling git worktree and joins it to
the same team.

Useful checks:

```bash
aw workspace status
aw id show
aw id cert show
aw roles show
```

### Reset the Local Stack

If you want a clean restart:

```bash
cd server
docker compose down -v
docker compose up --build -d
```

That resets Postgres and Redis. You can then rerun `aw init` in a fresh
directory or after removing `.aw/`.

## 2. Company Deployment

Use this path when you are deploying for a real team on a domain you control.

This path gives you:

- DNS-backed persistent namespaces
- multiple teams under one namespace
- persistent identities
- certificate-based team membership
- key rotation and normal registry lifecycle

### Start `awid` and `aweb`

You can start from the compose stack above, or run both services directly.

Direct `uv` startup:

```bash
cd awid
uv sync
export AWID_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWID_REDIS_URL=redis://localhost:6379/0
uv run awid

cd ../server
uv sync
export AWEB_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWEB_REDIS_URL=redis://localhost:6379/0
export AWID_REGISTRY_URL=http://localhost:8010
export APP_ENV=development
uv run aweb serve
```

### Create a Persistent Identity

```bash
export AWID_REGISTRY_URL=https://registry.acme.internal
export AWEB_URL=https://aweb.acme.internal

aw id create \
  --name alice \
  --domain acme.com \
  --registry "$AWID_REGISTRY_URL"
```

`aw id create` prints the DNS TXT record you must publish. Complete that step
before moving on.

If you are running an internal deployment that cannot perform public DNS
verification, set `AWID_SKIP_DNS_VERIFY=1` on the `awid` server. That is the
supported bypass for internal networks without DNS validation.

### Create a Team

```bash
aw id team create \
  --name backend \
  --namespace acme.com \
  --registry "$AWID_REGISTRY_URL"
```

### Invite Members

```bash
aw id team invite \
  --team backend \
  --namespace acme.com
```

### Accept the Invite

Run this in the target workspace:

```bash
aw id team accept-invite <token> --alias alice
```

That writes a certificate under `.aw/team-certs/`.

### Bind the Workspace to `aweb`

After the certificate exists, initialize the workspace against your server:

```bash
aw init --aweb-url "$AWEB_URL"
```

`aw init` uses the existing team certificate in `.aw/team-certs/` and connects
the workspace to `aweb`.

### Additional Teams and Agents

Create more teams with `aw id team create`, then invite and accept as usual.
For more local agents on one machine, use:

```bash
aw workspace add-worktree developer --alias bob
```

For more repos or machines, repeat invite, accept, and init in each target
directory.

### Key Rotation

Persistent identities can rotate keys without changing their stable `did:aw`:

```bash
aw id rotate-key
aw id verify
```

## Operational Notes

### Compose Services

The OSS compose stack runs four components:

- `aweb`
- `awid`
- PostgreSQL
- Redis

### Important Server Settings

For `aweb`:

- `AWEB_DATABASE_URL` or `DATABASE_URL`
- `AWEB_REDIS_URL` or `REDIS_URL`
- `AWID_REGISTRY_URL`
- `APP_ENV=development` when using an internal `http://awid:8010` registry

For `awid`:

- `AWID_DATABASE_URL`
- `AWID_REDIS_URL`
- optional `AWID_SKIP_DNS_VERIFY=1` for internal non-DNS deployments

### Health and Smoke Tests

```bash
curl http://localhost:8000/health
curl http://localhost:8010/health
./scripts/e2e-oss-user-journey.sh
```

The end-to-end script is the strongest local smoke test. It boots the stack,
creates identities and teams, and exercises the real OSS workflow.
