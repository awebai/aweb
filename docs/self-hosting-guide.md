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
echo "AWID_SERVICE_TOKEN=$(openssl rand -hex 32)" >> .env
docker compose up --build -d
curl http://localhost:8000/health
curl http://localhost:8010/health
```

Default host ports:

- `aweb`: `http://localhost:8000`
- `awid`: `http://localhost:8010`

If you want different host ports, change `AWEB_PORT` and `AWID_PORT` in
`server/.env` before `docker compose up`.

Compose publishes both ports on `127.0.0.1` only, so they are reachable from
this machine and nowhere else. Docker's published ports bypass host firewalls
such as ufw: a port published on every interface is open to the network even
when the firewall says it is closed. To reach the services from other machines,
set `AWEB_BIND_ADDRESS` in `server/.env` to `0.0.0.0` or to the address of one
interface, and put a proxy in front of it or filter it with a rule in Docker's
`DOCKER-USER` chain; a plain ufw rule does not filter it.

Compose refuses to start any container when `AWID_SERVICE_TOKEN` is missing or
empty. Generate it once as shown above; Compose passes that exact value to both
aweb and AWID. Do not commit `server/.env`.

### Create the First Workspace

Run this from the repo you want to use as an agent workspace:

```bash
aw init \
  --new-team \
  --awid-registry http://localhost:8010 \
  --aweb-url http://localhost:8000 \
  --name alice
```

Because the registry URL is localhost and `--new-team` is explicit, `aw init`
takes the local-team path:

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

Joining installs Bob's local identity and team membership and connects the
workspace using the self-hosted URL carried by the invite. Verify it against
the server:

```bash
aw check --online
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

Do not remove `.aw/` to recover from an `aw init` that reached AWID but then
reported an `AWID_SERVICE_TOKEN` trusted-lane error. Correct the token so aweb
and AWID use the same value, restart aweb, and rerun the same `aw init` command
from the same directory with the same name. The retry reuses the signing key and
certificate already written locally and converges on one agent/workspace; no
database repair or alias cleanup is required.

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

For direct `uv` startup, generate the shared secret once and keep it outside
the repository:

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
cd awid
uv sync
AWID_TOKEN_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/aweb/awid-service-token"
export AWID_SERVICE_TOKEN="$(tr -d '\r\n' < "$AWID_TOKEN_FILE")"
export AWID_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWID_REDIS_URL=redis://localhost:6379/0
uv run awid
```

In the aweb service terminal:

```bash
cd server
uv sync
export AWEB_DATABASE_URL=postgresql://aweb:password@localhost:5432/aweb
export AWEB_REDIS_URL=redis://localhost:6379/0
export AWID_REGISTRY_URL=http://localhost:8010
AWID_TOKEN_FILE="${XDG_CONFIG_HOME:-$HOME/.config}/aweb/awid-service-token"
export AWID_SERVICE_TOKEN="$(tr -d '\r\n' < "$AWID_TOKEN_FILE")"
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
verification, set `AWID_SKIP_DNS_VERIFY=1` on the `awid` server to bootstrap
the first namespace registration. This bypass never authorizes replacement of
an existing namespace controller. `PUT /v1/namespaces/{domain}` still requires
DNS evidence proving the new key or valid parent-controller authorization,
even when this variable is set. The continuity-preserving rotation operation
retains its previous- and new-key proofs and DNS requirements.

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

Other servers deliver to this origin only when it is an `https` origin named by
host (not an address literal) and every address the host resolves to is public.
By default a sending aweb server refuses an origin that is `http`, reporting
`delivery_origin_refused` to the sender, and an origin that resolves to a
loopback, private, link-local, CGNAT or otherwise non-public address, reporting
`delivery_address_refused` and logging a warning that names the origin and the
setting below.

When the servers that federate are on one private network, as
`https://aweb.acme.internal` resolving to `10.0.0.5` is, list the private
delivery origins on each sending server:

```bash
AWEB_FEDERATION_PRIVATE_DELIVERY_ORIGINS=https://aweb.acme.internal,https://aweb.partner.internal:8443
```

Each entry is one exact origin, `https://host[:port]`, compared after the
canonicalisation every delivery origin gets (lowercase host, no trailing dot,
the default port dropped). It is not a pattern: a different port, a subdomain
or `http` is not covered, and address literals, CIDR ranges, wildcards, paths,
queries and user information are not accepted. The server refuses to start
when an entry is not such an origin, naming the entry. Besides public
addresses, a listed origin may resolve only to `10.0.0.0/8`, `172.16.0.0/12`,
`192.168.0.0/16`, `100.64.0.0/10` (CGNAT) and `fc00::/7` (an IPv4-mapped IPv6
answer is judged by its IPv4 address). Loopback, link-local (including
`169.254.169.254`), `0.0.0.0`, documentation, benchmarking, reserved and
multicast addresses stay refused, and one such answer refuses the origin; for
servers on one host, use the isolated development settings below. Delivery to
it is otherwise
unchanged: the host is resolved once, the connection goes to the checked
address, TLS is verified against the host name, and redirects are not
followed. The setting applies to federated mail and chat delivery only;
registry reads keep requiring public addresses. Unset or empty, no private
delivery origin is admitted.

For federation between servers on one development machine or compose network,
set `APP_ENV=development` and `AWEB_FEDERATION_TEST=1` on each aweb server. With
both set, a server whose own `AWEB_PUBLIC_ORIGIN` host is isolated (a
single-label name such as `aweb-a`, `localhost`, `*.localhost`, `*.test`,
`*.test.local`, or a loopback literal) delivers over `http` and to non-public
addresses when the destination host is isolated too. Do not set
`AWEB_FEDERATION_TEST` in production.

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

### Container Users

The `aweb`, `awid` and A2A gateway images run as the non-root user
`1001:1001`. Their `USER` is numeric, so a Kubernetes pod with
`securityContext.runAsNonRoot: true` admits them without setting `runAsUser`.
A file or volume mounted into any of them, such as the gateway's
configuration, workspace or audit directory, must be readable (and, for the
audit directory, writable) by uid `1001`.

### Important Server Settings

For `aweb`:

- `AWEB_DATABASE_URL` or `DATABASE_URL`, or `AWEB_DATABASE_URL_FILE`: a file
  that holds the URL, so the database password is in no environment
- `AWEB_REDIS_URL` or `REDIS_URL`, or `AWEB_REDIS_URL_FILE`: a file that
  holds the URL, so a Redis password is in no environment
- `AWID_REGISTRY_URL`
- `AWEB_PUBLIC_ORIGIN` for federated mail/chat delivery
- `APP_ENV=development` when using an internal `http://awid:8010` registry
- `AWEB_APP_INTERNAL_ORIGINS` and `AWEB_APP_INTERNAL_CIDR`, together, when the
  apps you install run on internal addresses beside the server (for example in
  the same cluster). `AWEB_APP_INTERNAL_ORIGINS` is a JSON list of exact HTTPS
  app origins, such as `["https://secrets.apps.internal"]`;
  `AWEB_APP_INTERNAL_CIDR` is the one network their addresses must lie in, such
  as the cluster's service CIDR. Only a listed origin is fetched on an internal
  address, and only inside that network; every other app origin stays public,
  so a manifest on a private address is refused. Unset, no origin is internal.
  The server refuses to start if either value is malformed or only one is set.

For `awid`:

- `AWID_DATABASE_URL`
- `AWID_REDIS_URL`
- optional `AWID_SKIP_DNS_VERIFY=1` for first-registration namespace bootstrap
  on internal networks; controller replacement still requires recovery proof

### App Task Request Authority Reads

Successful creation and replay checks on `POST /v1/tasks/app-requests` make
three uncached AWID reads: the team key, revocations, and current certificates.
The public member answer route repeats these fresh checks before its transaction.
Paginated lists can require additional HTTP calls. Account for this traffic
when sizing AWID's per-client rate limits. Registry failures return
`503 authority_unavailable`; these checks do not use stale authority.

If request volume warrants a future cache, it must have an explicit freshness
bound measured in seconds and fail closed at expiry, with no stale fallback.
The general registry outage-grace cache cannot serve this path. See the
[app task request contract](app-task-requests.md#verification-in-order).

### Cross-Registry Authority and Migration

`AWID_REGISTRY_URL` selects this aweb service's home registry. It does not route
or authorize a global sender whose client-signed address belongs to another
registry. Cross-registry ingress independently discovers `_awid.<sender-domain>`,
uses the DNS-selected HTTPS registry, and verifies the exact namespace
controller, address, stable DID, current key, identity log, and route origin.
Do not place a sender-supplied registry URL in a message or configure the home
client as a fallback for external addresses.

PostgreSQL is required security state for cross-registry checkpoints, complete
address-authority cohorts, fences, leases, limits, receiver-wide message
receipts, contact identity bindings, and atomic delivery effects. Redis remains
cache/wake infrastructure and cannot authorize during a PostgreSQL outage. A
coordination timeout or outage therefore returns a retryable closed failure and
stores no delivery effects.

A receiver may reuse one complete authority cohort for at most 60 seconds.
`AWEB_FEDERATION_AUTHORITY_REUSE_SECONDS` defaults to 60 and accepts only 1..60.
At expiry the receiver rereads DNS, namespace, address, key-or-log, and origin.
This does **not** promise revocation, rotation, registry migration, or
reassignment detection within 60 seconds: a DNS or registry source can suppress
an unseen transition indefinitely by continuing to serve old valid evidence. A
stronger detection guarantee requires a separate non-suppressible
witness/transparency mechanism.

Authority reads admit at most 32 globally, 2 per domain, and 4 per registry
origin. Source/domain/origin token buckets each burst to 5 and refill at 30 per
minute. PostgreSQL leases last 10 seconds, followers wait at most 5 seconds, and
a failed shared read publishes the same stable failure for 5 seconds.

The additive aweb migration is `015_federation_delivery_policy.sql`; do not edit
migration 014 or earlier. It adds the complete-or-null contact binding
columns/constraint/index, receiver-wide
`message_ingress_receipts` plus insertion triggers, historical unreplayable
backfill, and `federation_mutation_outbox`. Before enabling it on an existing
database:

- resolve any UUID that exists in both historical mail and chat stores; the
  migration fails rather than choosing one;
- expect local-path and historical receipts to be `legacy_unreplayable`: they
  cannot authorize federation replay and block UUID reuse after message deletion,
  while existing local pre-insert idempotency remains unchanged;
- explicitly bind address-only legacy contacts to a freshly resolved `did:aw`
  before relying on them for `team_and_contacts`; and
- treat address reassignment as a new trust decision. In-place replacement
  requires namespace-controller proof and explicit authenticated recipient
  acceptance; it never transfers automatically.

The mutation outbox uses `FOR UPDATE SKIP LOCKED` so concurrent workers do not
publish one committed row concurrently. Publication remains at-least-once if a
worker crashes after Redis accepts an event but before PostgreSQL records
`delivered_at`.

Same-registry global delivery and existing local `did:key` learned-route
continuation remain supported. Unknown local first contact and route injection
still fail closed. For incident triage, preserve `correlation_id` and use the
[generated federation error reference](federation-error-reference.md); only rate
limiting emits `Retry-After: 1`. Do not collect keys, DID logs, DNS answers, peer
bodies, or internal URLs from users.

### Health and Smoke Tests

```bash
curl http://localhost:8000/health
curl http://localhost:8010/health
./scripts/e2e-oss-user-journey.sh
```

Both services serve the same three unauthenticated probe routes:

| Route | Answers | Point at it |
|---|---|---|
| `/live` | 200 whenever the process serves requests; checks no dependency | Liveness probes and container healthchecks, which restart the process |
| `/ready` | 200 when Redis and the database answer, 503 when either check fails | Readiness probes, load-balancer routing, start-up ordering |
| `/health` | The same response as `/ready` | Monitoring and manual checks |

A probe that restarts the container must use `/live`: on `/ready` or `/health`
it restarts every replica during a Redis or database outage, into the same
outage. The shipped images' `HEALTHCHECK`s probe `/live`, and the compose
healthchecks, which only order start-up, probe `/ready`.

The end-to-end script is the strongest local smoke test. It boots the stack,
creates identities and teams, and exercises the real OSS workflow.


## Customer server using the public AWID registry

A standalone aweb server can verify a private team at the public registry
without an operator-wide `AWID_SERVICE_TOKEN`. Give it one **ordinary member
key per team**. The team owner keeps the team controller key; the server only
needs the member key. This member has ordinary membership authority, including
acting as that member on aweb. It is not a new server identity kind or a
read-only credential.

In a dedicated server identity directory, generate a local key and request
membership with the existing CLI:

```bash
aw id team request --create-local-key --team engineering:example.com --name server
```

The **team owner**, in the CLI home that holds the team controller key, runs
the command printed by that request:

```bash
aw id team add-member --namespace example.com --team engineering \
  --did <server-did-key> --name server --local
```

Back in the server identity directory, fetch the issued certificate:

```bash
aw id team fetch-cert --namespace example.com --team engineering --cert-id <certificate-id>
```

Create `/etc/aweb/member-keys.json` mapping each canonical `team:namespace`
to the existing Ed25519 seed PEM private key generated by `aw`
(`ED25519 PRIVATE KEY`, a 32-byte seed):

```json
{
  "engineering:example.com": "/var/lib/aweb/server-identity/.aw/signing.key"
}
```

Use the actual key path in your identity directory. Relative key paths resolve
relative to the JSON file. Keep the private files readable only by the server
operator and service account; mount them read-only into a container. Do not
put private keys into the JSON, environment variables or repository. Then run
aweb with:

```bash
export AWID_REGISTRY_URL=https://api.awid.ai
export AWID_MEMBER_KEYS_FILE=/etc/aweb/member-keys.json
unset AWID_SERVICE_TOKEN
aweb serve
```

To run the same thing under Docker Compose, use
[`server/docker-compose.customer.yml`](../server/docker-compose.customer.yml).
It runs aweb, PostgreSQL and Redis, no registry, and has no service token.
Every credential is a file under one directory, and none is in the
environment or in `.env`:

```text
/etc/aweb-secrets/
  aweb/member-keys.json    team id -> key file, relative paths
  aweb/<name>.key          the member key files it names
  aweb/database-url        postgresql://aweb:<password>@postgres:5432/aweb
  postgres/password        the same password, alone
```

The files under `aweb/` must be readable by uid `1001` and by no one else:
owner `1001` with mode `0400`, or `root:1001` with mode `0440`.
`postgres/password` is read by root in the database container.

```bash
cd server
cat > .env <<'ENV'
AWEB_PUBLIC_ORIGIN=https://aweb.example.com
SECRETS_DIR=/etc/aweb-secrets
ENV
docker compose -f docker-compose.customer.yml up --build -d
curl http://localhost:8000/ready
```

Each subdirectory is mounted read-only at `/run/secrets/<service>`. The default
`server/docker-compose.yml` is the other shape: it operates its own AWID
service and uses the shared token. Startup refuses missing credentials,
an empty key map, unreadable keys or non-Ed25519 PEM keys. Restart after changing
the key map. If a service token is also configured, it takes precedence.

The client signs GETs for team metadata, the certificate list, member lookup
and revocations with the configured team's key, using the existing DIDKey path
signature. That includes pagination and the fresh app-task and hook-binding
authority reads. No key is borrowed from another team, and neither this key nor
the service token authenticates reads routed to a different registry. Public
identity reads stay unchanged. Individual certificate-blob fetches remain
holder-only; a server member cannot fetch another member's blob.

To revoke the server's access, the owner runs the existing command:

```bash
aw id team remove-member --namespace example.com --team engineering --cert-id <server-certificate-id>
```

Fresh reads fail immediately after revocation. Normal member verification
refreshes its controller-key authority after 60 seconds; an AWID authentication
refusal is not an outage and cannot use the outage-grace cache. Previously
cached metadata and certificate lists use their existing TTLs, with a denied
refresh removing that entry. To recover, issue a replacement ordinary member
certificate (and configure its key if it changed), then restart the server.
The public registry's existing read rate limits still apply; member signing
does not grant the service-token rate-limit exemption.
