# One team's deployment

What a team runs in its own cluster or on its own machine: the aweb server,
the protected signer, the Secrets and Logs apps, and the OATS team container
behind an egress boundary. One set of images and one configuration file; a
Helm chart (Kubernetes) and a Compose file (one machine) are two thin layers
over them.

This directory holds what both layers share.

| File | What it is |
| --- | --- |
| `config.schema.json` | The schema of the operator's `deployment.yaml`. The Helm chart is to use it as its `values.schema.json`; no chart reads it yet. |
| `deployment.example.yaml` | An example that the schema accepts. |
| `render_env.py` | Checks a `deployment.yaml` against the schema and prints the env file the Compose layer reads: `python render_env.py deployment.yaml > .env`. It needs PyYAML and jsonschema, which the aweb server image has. |
| `compose.yaml` | The Compose layer: the two networks, Redis, the bundled PostgreSQL and aweb. From this directory: `docker compose --env-file .env up -d`. |
| `compose.secrets.yaml`, `compose.logs.yaml`, `compose.signer.yaml`, `compose.agents.yaml` | One optional component each; the agents' file holds the team container and its egress, extended from the pinned OATS source. The env file's `COMPOSE_FILE` names those `deployment.yaml` has; Compose never loads the others. |
| `teamctl` | The operator command on one machine: `teamctl start` renders `deployment.yaml`, starts the bundle and checks it is ready; with agents it derives egress's policy and holds the agent until the ingress and boundary probes pass. `teamctl connect` prints the origins and the deployment's `docker compose` command. It needs `uv` and this repository's checkout. |
| `egress_policy.py` | Derives the agents' egress policy from the deployment once its services are up. |
| `compose.test.yaml` | The journey's test world: its own registry, DNS, SMTP, TLS front and aw. Never in a production deployment. |
| `postgres-roles.sh` | Run by the bundled PostgreSQL at its first start: one role and one database per component. |
| `descriptors/<component>.md` | What one component needs from an operator, written by its owner. |

## The configuration file

`deployment.yaml` has one key per component, plus `team` and `postgres`. It
holds literals that are not secret and references to where secrets are. It
never holds a credential.

A key is the camelCase of the setting the service already reads, under its
component: `aweb.publicOrigin` is `AWEB_PUBLIC_ORIGIN`. No component has a
second set of names.

The Helm chart is to read the file as its values; that layer is not written
yet. Compose cannot read YAML, so its wrapper checks the file against the
schema and renders it to the env file Compose reads; that file holds no
credential either. The setting an input becomes
is the `x-env` of that input in the schema, so the mapping is written once.

## Rules every component follows

- **A credential is a file.** In the container it is at
  `/run/secrets/<component>/<name>`, read-only, and the service takes the
  path through a `*_FILE` setting. No credential is in an environment
  variable, an argument, `deployment.yaml` or the rendered env file.
  `<component>.secrets` says where the files come from: the name of an
  existing Secret in Kubernetes, a directory under `compose.secretsDir` on
  one machine.
  One exception, kept because operators' launch configurations name it: the
  agents' harness login is mounted at `/etc/agent-login/`.
- **A database URL is one file** that holds the whole URL, password included
  (`database-url`). So is aweb's Redis URL (`redis-url`).
- **Redis refuses a client without the password.** Its one secret file,
  `redis/users.acl` under `compose.secretsDir` (owned by the image's
  `redis` uid, `0400`), holds one line,
  `user default on #<SHA-256 of the password, hex> ~* &* +@all`: the hash,
  not the password, which only aweb's `redis-url` holds.
- **A service is reached by its component name:** `aweb:8000`,
  `signer:8080`, `secrets:8770`, `logs:8765`, `postgres:5432`, `redis:6379`,
  `egress`. Ports and service uids are fixed, not inputs.
- **Three networks.** `services` holds aweb, signer, secrets, logs and
  postgres. `backend` holds aweb and redis alone: nothing else reaches
  Redis. `agents` holds the team container and `egress`; it is internal,
  has IPv6 off and gives no route to the host's bridge gateway, so `egress`
  is the only way out. Egress reaches exactly five origins (aweb, Secrets,
  Logs, the signer's request origin for prepare and receipt, and the
  registry) at the addresses they resolve to when the deployment starts, and
  denies PostgreSQL. Agents are not admitted until the TLS ingress is shown
  to refuse the signer's request SNI carrying its human Host.
- **One PostgreSQL server, one database and one role per component.**
  `postgres.bundled: true` runs one and creates them at first start; with an
  operator's own server the operator creates them. The bundled server
  creates a role and a database named after each file in its
  `roles/` secrets directory (`postgres/roles/aweb`), which holds that
  role's password: the same password that is in the component's own
  `database-url`. A component added after the first start needs its role
  and database created by hand.
- **Public origins are inputs; TLS is the operator's.** A reverse proxy or
  an Ingress terminates TLS and routes by Host to the service.
- **An input that only one platform has** is under `<component>.kubernetes`
  or `<component>.compose`, and its descriptor says why it has no shared
  form.

## A descriptor

One file per component with three tables and four lines:

1. Inputs: schema key, the setting or mount it becomes, constraint, default,
   purpose.
2. Secret files: name under `/run/secrets/<component>/`, owner and mode, who
   provisions it.
3. Platform-only inputs: key, platform, why.

Then: image, port, health endpoint, depends on.
