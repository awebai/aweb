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

## The team's server record

Installed apps find the team's aweb through the team's server record at the
registry (`aweb.team-server/1`), signed by the team's key. Secrets refuses an
installation whose team has none (`team_server_unpublished`). The team owner
publishes it before installing the apps, while its machine still holds the
team's key, that is, before the signer takes custody:

```sh
aw id team set-server --team <team> --namespace <domain> --url <aweb.publicOrigin>
aw id team show-server --team <team> --namespace <domain>
```

A record signed by another key is refused, so a new controller key needs the
record published again. Once the signer holds the key, that has no supported
path (`aweb-acxy.4`, `team.controller.rotate`, OPEN).

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
| Secrets' database | `postgres_data`, database `secrets` | Every retained secret value, sealed under the custody key (references for values kept in 1Password); grants, receipts | Yes |
| Logs' database | `postgres_data`, database `logs` | Every retained event's content and its chain | Yes |
| The signer's database | `postgres_data`, database `signer` | Bootstrap consumption, credential and public-key records, bindings, receipts | Yes |
| Redis | `redis_data` volume | Rebuildable runtime state: presence and its indexes, active chat waits, current activity and listening hints, wake counters and pub/sub, registry-read caches, short-lived rate and cooldown state | **No.** Start with a fresh Redis and its restored credentials: clients reconnect and heartbeat, caches refill, and the previous transient hints and current rate and cooldown windows are lost. No durable aweb record needs this volume (federation state, work, leases and the lifecycle outbox are in PostgreSQL), and a cold registry cache reads fresh evidence upstream. aweb needs Redis reachable to start. This does not qualify the unsupported team restore. |
| The secrets directory | `compose.secretsDir` | Each component's credentials: database URLs, aweb's Redis URL, member keys, Secrets' **custody key** and service keys, Logs' app keys, the signer's controller custody, SMTP passwords, Redis's ACL, the agents' harness login | Yes, as an archive with numeric owners and modes, **without** the signer's live controller custody (`signer/private-controller`) or the agents' harness login (`agents/`), which is minted again rather than restored |
| The agents' state and work | `agents.compose.stateDir`, `agents.compose.workDir` | Each seat's `.aw` (its member key), the harness's sessions and transcripts, checkouts | Yes, as archives |
| Files `deployment.yaml` names | `signer.profileFile`, `signer.scopeFile`, the CA files | Public configuration and trust anchors | Yes, with their modes |
| The operator's Git mirrors and the OATS source | `agents.mirrorsDir`, `agents.compose.oatsSource` | Operator-provided inputs | No: recorded in the manifest only |

**Permanently losing every usable copy of the local custody key, or the ability
to decrypt with the KMS key, prevents recovering the values sealed under it.**
Secrets seals each retained value under the key in `secrets/custody-key` (or the
KMS key `secrets.kmsKeyId` names); a database backup without that key is
ciphertext no one can read. Keep compatible key backups, or the KMS access, at
least as protected as the live key (`naapp/secrets/deploy/OPERATIONS.md`). A
running Secrets reads its key once: a missing or replaced file takes effect when
it restarts. Whoever holds both the key and the database reads every value it
seals.

**The signer's controller key has its own backup: the team owner's separately
protected offline copy.** `teamctl backup` leaves the live custody volume
(`signer/private-controller`) out, as the signer's custody instructions require
(`server/src/aweb/protected_signing/HOST.md`, "Controller key installation,
backup and cutover"). The signer's database is in the backup set; never restore
an older one whose bootstrap is still pending over a completed enrollment. That
is a procedure, not an enforced fence (`aweb-acyw`).

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
- `archives/<key>.tar`: the secrets directory, without the signer's live
  controller custody or the agents' harness login, and the agents' state and work, regular files and
  directories only, owners and modes kept;
- `files/<key>`: every file `deployment.yaml` names;
- `manifest.json`: the source revision, every image digest, the PostgreSQL
  version, and the SHA-256 and recorded path of every part. It holds no value.

The directory is created `0700` and must not exist before. **It holds every
credential of the deployment but the signer's controller key, Secrets' custody
key included.** Keep it where only
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
and its own backups; the bundle adds it when that ships. Until Logs has
reapplied its tombstones after a restore, it answers ingest, reads and export
with `503 restore_not_ready`: a restore that still answers 503 is waiting on
that, not broken.

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

### Before upgrading Secrets to team-scoped installations (`aweb-acxc.45`)

That Secrets version gives every installation's policies, grant templates,
change-set settings and configuration revisions the team that owns them. Its
migrations keep a team only where the installation's retained rows (its
secrets, grants, intents, owner principals, role holdings and fences) name
exactly one. An installation with none, or with more than one, makes the
migration refuse, naming the table, and Secrets does not start. That is by
design: an installation id is not team authority.

Run the read-only count first, with every writer stopped and after `backup`:

```sh
<the deployment's docker compose command> exec -T postgres \
  psql -U postgres -X -d secrets -v secrets_schema=<secrets.dbSchema> -f - \
  < deploy/team/secrets-attribution-count.sql
```

`teamctl connect` prints the deployment's compose command, and
`secrets.dbSchema` defaults to `public`. The script opens a read-only
transaction and writes nothing. It refuses a schema that does not exist, rather
than answering zero. For each of the four tables it prints how many
installations have zero, several or one team. The counts are per table: an
installation can appear in more than one, so do not add them up. The script
was run on PostgreSQL against fixtures with one, several and no teams, a fresh
schema and a missing schema (source `1217f9b21`, SHA-256 `40f41cd3…`, gate
`a2930875`), apart from that gate's unrelated infrastructure status.

- **Only if the command finishes successfully, reports all four tables, and
  every `zero_teams` and `multiple_teams` is 0:** upgrade.
- **Any command error, timeout or missing table result, or any nonzero
  `zero_teams` or `multiple_teams`:** stop before migration. Keep the old
  image running, the backup and the output. Which team owns those installations needs an explicit,
  evidenced decision, and there is no supported repair statement. Do not
  update or delete rows, add rows to make the count zero, or give them the
  team that happens to be connected. A supported remedy would be a separately
  reviewed tool or migration; ask the Secrets owner.

**A refused upgrade is not undone by starting the old image.** Each migration
file commits on its own, and they do not run in the order above: the
configuration-revision migration can commit before the one that refuses.
After a refusal, read the migration ledger to see what was applied, and choose
the image from that, with the Secrets owner. Restore is not supported for a
team's deployment (above).

## Rotating a credential

| Credential | Supported path | What it ends | What stays |
| --- | --- | --- | --- |
| Secrets custody key | None. Replacing the key file is not a rotation: after a restart with the new key, values sealed under the old one cannot be read. | | `aweb-acyp`, OPEN |
| Team controller key (held by the signer) | None. `aw id team rotate-key` exists, but once the signer holds the team key, rotation is the protected `team.controller.rotate`; no raw-key command may bypass it (`HOST.md`). | | `aweb-acxy.4`, OPEN |
| A member's key (a service or a seat) | While the owner still holds the team key: remove the member (below), then admit it again with a new key (`aw id team add-member --local`). Once the signer holds the team key, none: see removal below. | The old certificate, once revoked | Anything the old key signed |
| Database passwords, Redis's password | Not exercised for this bundle: the role's password, the component's URL file and `postgres/roles/<name>` (or Redis's `users.acl` and aweb's `redis-url`) change together, then the services restart. | | Not qualified |
| The agents' harness login | The OATS container's; see its documentation. | | |

### The owner's log key for the agents' local logs (`aweb-acyh`, OPEN)

The agents' local logs are plaintext today
(`deploy/team/access/agents.md`). Sealing them under a key the team owner
holds is on `aw`'s main branch and not released: nothing here applies until the
pinned `aw` includes `aw team admin log-key`. Making the key needs no controller
key; the record that turns sealing on must be signed by the team controller
key, which the signer holds once a deployment is set up. The supported signing
route is a protected signer act (`team.log-key.sign`), which does not exist
yet. Until it does, the record is signed with the owner's offline controller
copy:

1. On the machine where the owner will read the logs, run
   `aw team admin log-key create --team <team_id> --out unsigned.json`. The log
   private key stays in that machine's keychain, under a passphrase, and never
   enters the container. The record is public.
2. Sign it where the controller key is present: at first setup, before the
   controller key is installed in the signer, on the owner's machine that
   still holds it in `~/.awid/team-keys/`; afterwards, wherever the owner
   restores the offline controller copy (the controller's backup, above),
   removing it again at once. Run
   `aw team admin log-key sign --record unsigned.json --offline-controller-key --out log-key.json`.
   `sign` with no route refuses; it never loads a controller key on its own.
   Restoring the copy exposes the controller key outside the signer by hand,
   and nothing enforces its removal: it is the reason the signer act is
   wanted. `aw team admin log-key signing-bytes --record unsigned.json --team-key-did <did>`
   prints the exact bytes signed, for a cross-check.
3. In the agent container, as the agents' user and from a directory bound to
   the team, run `aw team admin log-key install log-key.json`. One install
   covers every agent of the container, because they share `/state/home`.
   `aw doctor local` reports `local.log_key.owner_key_installed` as ok.
   Running agents follow it from their next write, without a restart. Lines
   written before the install stay plaintext: `aw doctor local`, run as each
   agent from that agent's directory, names each of that agent's logs still
   holding plaintext, with a count (`local.log_key.plaintext_lines`), and the
   owner decides whether to keep, move or delete those files.

After a controller replacement the agents' local logging **stops**, and does
not fall back to plaintext, until the record is signed again by the new
controller key (step 2, with the same `unsigned.json` or the previously
signed `log-key.json`) and installed again
(step 3). The log key itself does not change, so step 1 is not repeated. A new
log key is step 1 again, then steps 2 and 3. Lines already sealed stay readable
on the owner's machine with the keys in its keychain. While sealing is on, an
agent's own `aw log` refuses and `aw run --continue` shows no recap. The owner
reads the logs by copying the files out of the container and running
`aw log read <files>` on the reading machine.

## Removing an agent, a service or an owner

A member is removed by revoking its certificate, which the team key signs.
While the team owner holds that key, `aw id team remove-member` does it. After
the cutover, the supported online path for the owner and the agents has no
controller key file and goes through the protected signer, which exposes one
operation, `human-role.revoke` (`server/src/aweb/protected_signing/README.md`):
**member admission and removal through that protected path is not yet
implemented.** The journey admits its seats before the cutover for this reason.
The owner's separately protected offline backup and the host operator's ability
to read the custody file remain; whoever uses the raw key bypasses the signer's
browser approval, outside the supported workflow. Member revocation through the signer belongs to the catalog
implementation, `aweb-acxy.4`, OPEN.

| Remove | Supported path | Effective authority afterwards | Stored state that remains |
| --- | --- | --- | --- |
| An agent seat | Before the signer holds the team key: the owner's `aw id team remove-member`. After: none (`aweb-acxy.4`). | The certificate is revoked at the registry, and aweb refuses it (`AWEB_REQUIRE_REGISTERED_CERTIFICATES`). Every agent of the container could read the seat's key; revocation, not deleting the file, ends its use. | The seat's `.aw` and key in the agents' state, until the operator deletes them; its messages in aweb; its events in Logs; Secrets grants naming it, until an owner revokes them |
| A service member (aweb, Secrets, Logs) | As for a seat. The service then stops working for the team. | Revoked at the registry. | Its key and certificate files in the secrets directory; its database |
| An app role a human holds | `human-role.revoke`, the signer's protected act, approved in the browser. | The signer signs the owner act; delivering it to the app, which ends the designation, is not yet in this bundle. | The receipt in the signer's database |
| An owner | No supported recipe in this bundle. | | Open: to be named |

## Mail and chat with other servers

A team deployment delivers its agents' mail and chat to no other aweb server:
the renderer sets `AWEB_FEDERATION_OUTBOUND=off`. To allow some, list their
exact origins in `deployment.yaml` and `start` again:

```yaml
aweb:
  federationOutbound: ["https://aweb.partner.example"]
```

The server then delivers only to those origins. It refuses any other with 403,
before looking the destination up or connecting to it, and refuses to start
on an entry that is not an exact https origin (`docs/self-hosting-guide.md`).
This bounds where the server sends messages; it does not bound what the
Secrets broker sends under an agent's grant (`deploy/team/access/agents.md`).

## Credentials an agent can read

The agents of one container share one operating-system user: every agent can
read every seat's key in the agents' state and the harness login. Who can read
what, for each party, is on its own page.
