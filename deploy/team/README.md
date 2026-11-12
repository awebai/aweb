# One team's deployment

What a team runs in its own cluster or on its own machine: the aweb server,
the protected signer, the Secrets and Logs apps, and the OATS team container
behind an egress boundary. One set of images and one configuration file; a
Helm chart (Kubernetes) and a Compose file (one machine) are two thin layers
over them.

This directory holds what both layers share.

| File | What it is |
| --- | --- |
| `config.schema.json` | The schema of the operator's `deployment.yaml`. The Helm chart uses it as its `values.schema.json`. |
| `deployment.example.yaml` | An example that the schema accepts. |
| `descriptors/<component>.md` | What one component needs from an operator, written by its owner. |

## The configuration file

`deployment.yaml` has one key per component, plus `team` and `postgres`. It
holds literals that are not secret and references to where secrets are. It
never holds a credential.

A key is the camelCase of the setting the service already reads, under its
component: `aweb.publicOrigin` is `AWEB_PUBLIC_ORIGIN`. No component has a
second set of names.

Helm reads the file as its values. Compose cannot read YAML, so its wrapper
checks the file against the schema and renders it to the env file Compose
reads; that file holds no credential either.

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
  (`database-url`).
- **A service is reached by its component name:** `aweb:8000`,
  `signer:8080`, `secrets:8770`, `logs:8765`, `postgres:5432`, `redis:6379`,
  `egress`. Ports and service uids are fixed, not inputs.
- **Two networks.** `services` holds aweb, signer, secrets, logs, postgres
  and redis. `agents` holds the team container and `egress`, and has no
  route out of its own: `egress` is the only way out, and its allowlist
  names the services agents use (aweb, Secrets, Logs) and denies PostgreSQL,
  Redis and every custody key.
- **One PostgreSQL server, one database and one role per component.**
  `postgres.bundled: true` runs one and creates them at first start; with an
  operator's own server the operator creates them.
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
