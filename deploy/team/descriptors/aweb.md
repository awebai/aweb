# aweb: the team's server

A customer-run aweb server. It is an ordinary member of each team it serves:
it holds that member's key, no registry-wide token, and runs no registry.

## Inputs

| Key | Becomes | Constraint | Default | Purpose |
| --- | --- | --- | --- | --- |
| `aweb.image` | the service's image | `repository@sha256:<64 hex>` | none | The server image. |
| `aweb.publicOrigin` | `AWEB_PUBLIC_ORIGIN` | https origin | none | The origin agents reach this server at. |
| `aweb.secrets` | mount at `/run/secrets/aweb` | reference | `aweb` | Where the secret files come from. |
| `team.registryUrl` | `AWID_REGISTRY_URL` | https origin | `https://api.awid.ai` | The AWID registry the team is in. |

Fixed: `AWEB_DATABASE_URL_FILE=/run/secrets/aweb/database-url`,
`AWID_MEMBER_KEYS_FILE=/run/secrets/aweb/member-keys.json`,
`AWEB_REDIS_URL=redis://redis:6379/0`, uid 1001.

## Secret files

| Name | Owner and mode | Provisioned by |
| --- | --- | --- |
| `database-url` | uid 1001, `0400` | The operator: the whole URL of the `aweb` database with the `aweb` role's password. |
| `member-keys.json` | uid 1001, `0400` | The operator: canonical team id to key file, relative paths. No key material. |
| `<name>.key` | uid 1001, `0400` | The operator, after the team owner admits the server as a member (`docs/self-hosting-guide.md`, "Customer server using the public AWID registry"). |

## Platform-only inputs

| Key | Platform | Why |
| --- | --- | --- |
| `aweb.compose.bindAddress`, `aweb.compose.port` | Compose | The host address and port the service is published on for the operator's reverse proxy. Kubernetes routes to the Service. |

Image: the aweb server image. Port: 8000. Health: `GET /ready`. Depends on:
`postgres`, `redis`, the registry at `team.registryUrl`.
