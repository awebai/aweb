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
  --name alice
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

- a local self-custodial identity for `default:local`, represented by its
  `did:key` and with no public address or `did:aw`;
- a team certificate for `default:local`; and
- a workspace binding pointing at your local `aweb`.

### Connect More Existing Agents

From Alice's directory, create an invite:

```bash
aw team invite
```

Run the join command from a second existing agent directory. Its equivalent
form is:

```bash
aw team join <invite-token> --name bob
```

Joining installs Bob's local identity and team membership; it does not create
the aweb workspace projection. Connect that existing membership explicitly,
then verify it:

```bash
aw workspace connect --service http://localhost:8000
aw check
```

This connects an agent directory you already operate. Aweb does not create its
definition, home, worktree, runtime, or process.

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

- DNS-backed global namespaces
- multiple teams under one namespace
- global identities
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
export AWEB_PUBLIC_ORIGIN=https://aweb.acme.internal
export APP_ENV=development
uv run aweb serve
```

`AWEB_PUBLIC_ORIGIN` is the public origin other aweb servers use for
federated mail and chat delivery. It must be an origin only, for example
`https://aweb.acme.internal`; do not include `/api` or another path.
Its scheme must match how remote servers reach this deployment. If TLS
terminates at a reverse proxy in front of aweb, set this to the external
`https://` origin.

### Create a Global Identity

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

### Publish the Address Route Delivery Origin

Federated first-contact mail and chat need a delivery origin on the namespace
address route. Run this from a workspace that holds the namespace controller key:

```bash
aw id namespace set-delivery-origin \
  --namespace acme.com \
  --origin "$AWEB_URL"
```

The origin must be the public server origin, not the coordination API path. For
example, use `https://aweb.acme.internal`, not
`https://aweb.acme.internal/api`. Namespace default delivery origin is inherited
by addresses in that namespace; it is not a canonical route for bare `did:aw`
first contact. Hosted aweb.ai namespaces are configured by the hosted service.

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
aw id team accept-invite <token> --name alice
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
For every additional agent, start with an existing target directory and repeat
the invite, accept, and service-connect steps there. The operator or
orchestrator remains responsible for creating and running that agent's home,
worktree, runtime, and process.

### Key Rotation

Global identities can rotate keys without changing their stable `did:aw`:

```bash
aw id rotate-key
aw id verify <did:aw>
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
- `AWEB_PUBLIC_ORIGIN` for federated mail/chat delivery
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
