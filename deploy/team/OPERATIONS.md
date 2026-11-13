# Operating one team's deployment

What an operator runs on the machine that holds the bundle, what each command
keeps and deletes, what must be backed up and restored together, and what is
not yet supported. Every command is `deploy/team/teamctl`, run with
`TEAM_DEPLOYMENT_PROJECT` (the Compose project) and `TEAM_DEPLOYMENT_RUN_DIR`
(where the rendered env file, egress policy and probe evidence go) set:

```sh
export TEAM_DEPLOYMENT_PROJECT=team TEAM_DEPLOYMENT_RUN_DIR=/srv/team/run
deploy/team/teamctl start deployment.yaml
```

It needs `docker`, `uv` and this repository's checkout at the bundle's source
revision. No command reads, prints or passes a credential: every credential is a
file under `compose.secretsDir`, mounted by the one service that owns it.

## What each command keeps and deletes

| Command | Does | Keeps | Deletes |
| --- | --- | --- | --- |
| `start <deployment.yaml>` | Renders and checks the configuration, then starts the bundle and waits until every service is ready. A configuration the schema or the renderer refuses stops it before anything starts. With agents, egress starts with its derived policy, and the agent only after the ingress and boundary probes pass; it then exits 3, the agents held. | Everything | Nothing |
| `stop <deployment.yaml>` | Stops every service of the bundle. | Containers, networks, volumes, the secrets directory, the agents' state | Nothing |
| `destroy <deployment.yaml> --confirm <project>` | Removes the bundle's own containers and its named volumes. Refuses unless the project is named. | The secrets directory, the agents' state, networks, every other project and anything else the project runs beside the bundle | **Every database** (`postgres_data`) and Redis (`redis_data`) |
| `backup <deployment.yaml> <new dir>` | One consistent backup set; see below. | Everything | Nothing |
| `restore ...` | Refuses for a team's deployment; see below. | Everything | Nothing |

`scripts/e2e-team-deployment.sh compose down` is the test journey's cleanup,
not an operator command: it removes every container, network and volume of the
project, the test world's included, and the deployment's data with them.

## What the deployment's data is

| Artifact | Where | Holds | In `teamctl backup` |
| --- | --- | --- | --- |
| aweb's database | `postgres_data` volume, database `aweb` | Teams' messages, chats, tasks, workspaces, app installations | Yes, `pg_dump` |
| Secrets' database | `postgres_data`, database `secrets` | Every stored secret value, encrypted under the custody key; grants, receipts | Yes |
| Logs' database | `postgres_data`, database `logs` | Every retained event's content and its chain | Yes |
| The signer's database | `postgres_data`, database `signer` | Bootstrap consumption, credential and public-key records, bindings, receipts | Yes |
| Redis | `redis_data` volume | aweb's presence, wake and event fan-out and cached registry reads | **No.** Whether aweb keeps anything in Redis that it needs after a restore is not established; it is the aweb server owner's to confirm. |
| The secrets directory | `compose.secretsDir` | Each component's credentials: database URLs, aweb's Redis URL, member keys, Secrets' **custody key** and service keys, Logs' app keys, the signer's controller custody, SMTP passwords, Redis's ACL, the agents' harness login | Yes, as an archive with numeric owners and modes |
| The agents' state and work | `agents.compose.stateDir`, `agents.compose.workDir` | Each seat's `.aw` (its member key), the harness's sessions and transcripts, checkouts | Yes, as archives |
| Files `deployment.yaml` names | `signer.profileFile`, `signer.scopeFile`, the CA files | Public configuration and trust anchors | Yes, with their modes |
| The operator's Git mirrors and the OATS source | `agents.mirrorsDir`, `agents.compose.oatsSource` | Operator-provided inputs | No: recorded in the manifest only |

**Losing the custody key makes every stored secret unrecoverable.** Secrets
encrypts each value under the key in `secrets/custody-key` (or the KMS key
`secrets.kmsKeyId` names). A database backup without that key is ciphertext no
one can read. Keep the key's backup at least as protected as the live key
(`naapp/secrets/deploy/OPERATIONS.md`). Whoever holds both that key and the
database reads every stored value.

**The signer's controller key has its own backup: the team owner's offline
copy.** The live custody file is in the backup set because it is under the
secrets directory, but the owner's encrypted offline copy is the controller's
backup (`server/src/aweb/protected_signing/HOST.md`, "Controller key
installation, backup and cutover"). Never restore an older signer database
whose bootstrap is still pending over a completed enrollment.

## Backup

```sh
deploy/team/teamctl stop deployment.yaml
deploy/team/teamctl backup deployment.yaml /srv/team-backups/2026-11-13
```

`backup` refuses while any service other than the bundled PostgreSQL runs, so
no application or agent writes during it. It starts PostgreSQL alone if it is
stopped, and stops it again afterwards. The set holds:

- `databases/<name>.dump`: `pg_dump -Fc` of every database, and
  `databases/server-version`;
- `archives/<key>.tar`: the secrets directory and the agents' state and work,
  regular files and directories only, owners and modes kept;
- `files/<key>`: every file `deployment.yaml` names;
- `manifest.json`: the source revision, every image digest, the PostgreSQL
  version, and the SHA-256 and recorded path of every part. It holds no value.

The directory is created `0700` and must not exist before. **It holds every
credential of the deployment, the custody key included.** Keep it where only
the operator reaches it: never under a directory an agent mounts, never in a
repository or a published artifact. While it is present, the boundary probe
counts it as a protected source the agent must not reach.

With your own PostgreSQL server (`postgres.bundled: false`), `backup` refuses:
back up that server's databases with its own tools, at the same consistent
point (the bundle stopped), beside the files above.

## Restore: not supported for a team's deployment

`teamctl restore` refuses. A restored database must not serve a team until
each component can restore without bringing back what was destroyed:

| Component | What a restore needs | Owner and task | State |
| --- | --- | --- | --- |
| Secrets | Reapply the externally retained destroyed-version tombstones before serving; never resurrect a destroyed value. Custody-key rotation. | aweb-expert-secrets-root, `aweb-acyp` (after `aweb-acwd.24`) | OPEN |
| Logs | Reapply purge tombstones before serving, from a separate ledger database that is never restored from a content backup. | aweb-expert-logs, `aweb-acgh.16.23` (L5) | OPEN |
| Signer | An offline controller-key and database backup recipe; refuse a pending-bootstrap database restored over a completed enrollment. | aweb-protocol-expert-signer-embedding, `aweb-acyw` | OPEN |
| Signer | `team.controller.rotate` | `aweb-acxy.4` | OPEN |

Logs will need a second database for its tombstone ledger, with its own DSN
and its own backups; the bundle adds it when that ships.

`teamctl restore --lab-rehearsal <deployment.yaml> <backup>` restores a backup
of **disposable lab data** to rehearse the mechanics, never a team's. It checks
every part against the manifest's digests and takes every target path from the
`deployment.yaml` given, not from the backup. It refuses before writing
anything if a target exists, a parent is reached through a symbolic link, an
archive holds anything but regular files and directories, or any of the
bundle's containers or volumes exists. It restores the files and archives,
starts PostgreSQL alone (whose first start creates the roles and databases from
the restored secrets) and restores each dump, then leaves the bundle stopped.
Restored files keep their modes and belong to the operator.

## Upgrade

The images are pinned by digest in `deployment.yaml`. Each component runs its
database migrations when it starts; existing migrations are never edited.
Before changing a digest, `stop` and `backup`. There is no supported rollback:
starting an older image on a migrated database is not a migration rollback, and
restore is not supported. The Secrets procedure is pending
(`naapp/secrets/deploy/OPERATIONS.md`, "Upgrade and migration").

## Rotating a credential

| Credential | Supported path | What it ends | What stays |
| --- | --- | --- | --- |
| Secrets custody key | None. Replacing the key file is not a rotation: values under the old key become unreadable. | | `aweb-acyp`, OPEN |
| Team controller key (held by the signer) | None. `aw id team rotate-key` exists, but once the signer holds the team key, rotation is the protected `team.controller.rotate`; no raw-key command may bypass it (`HOST.md`). | | `aweb-acxy.4`, OPEN |
| A member's key (a service or a seat) | While the owner still holds the team key: remove the member (below), then admit it again with a new key (`aw id team add-member --local`). Once the signer holds the team key, none: see removal below. | The old certificate, once revoked | Anything the old key signed |
| Database passwords, Redis's password | Not exercised for this bundle: the role's password, the component's URL file and `postgres/roles/<name>` (or Redis's `users.acl` and aweb's `redis-url`) change together, then the services restart. | | Not qualified |
| The agents' harness login | The OATS container's; see its documentation. | | |

## Removing an agent, a service or an owner

A member is removed by revoking its certificate, which the team key signs.
While the team owner holds that key, `aw id team remove-member` does it. Once
the protected act has moved the key into the signer's custody, no one else
holds it, and the signer supports one operation, `human-role.revoke`
(`server/src/aweb/protected_signing/README.md`): **no member can then be
removed or added.** The journey admits its seats before that move for this
reason. Member revocation through the signer belongs to the catalog
implementation, `aweb-acxy.4`, OPEN.

| Remove | Supported path | Effective authority afterwards | Stored state that remains |
| --- | --- | --- | --- |
| An agent seat | Before the signer holds the team key: the owner's `aw id team remove-member`. After: none (`aweb-acxy.4`). | The certificate is revoked at the registry, and aweb refuses it (`AWEB_REQUIRE_REGISTERED_CERTIFICATES`). Every agent of the container could read the seat's key; revocation, not deleting the file, ends its use. | The seat's `.aw` and key in the agents' state, until the operator deletes them; its messages in aweb; its events in Logs; Secrets grants naming it, until an owner revokes them |
| A service member (aweb, Secrets, Logs) | As for a seat. The service then stops working for the team. | Revoked at the registry. | Its key and certificate files in the secrets directory; its database |
| An app role a human holds | `human-role.revoke`, the signer's protected act, approved in the browser. | The signer signs the owner act; delivering it to the app, which ends the designation, is not yet in this bundle. | The receipt in the signer's database |
| An owner | No supported recipe in this bundle. | | Open: to be named |

## Credentials an agent can read

The agents of one container share one operating-system user: every agent can
read every seat's key in the agents' state and the harness login. Who can read
what, for each party, is on its own page.
