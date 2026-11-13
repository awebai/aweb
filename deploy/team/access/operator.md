# What the operator can read and do

The operator runs the machine that holds the deployment: Docker, the volumes,
`compose.secretsDir` and the backups. When one organization operates a
deployment for another team, the operating organization is this operator, and
the team's own page tells the team so.

Root on the host, or membership of the `docker` group (root-equivalent), reaches
everything below. Each row is what one artifact gives on its own.

| Holding | Reads | Can do | Source |
| --- | --- | --- | --- |
| aweb's database (`postgres_data`, database `aweb`, or a backup) | Every mail and chat body in plaintext, unless its sender used `--e2ee` between self-custodial identities; subjects of those too. Tasks, workspaces, instructions, roles, the audit log. | Change or delete any of it. | `docs/e2e-messaging-contract.md` ("Current `aw` sends server-readable plaintext by default") |
| Secrets' database | Sealed values only: ciphertext, metadata, grants and receipts. | | `naapp/secrets/deploy/OPERATIONS.md` |
| Secrets' database **and** the custody key (`secrets/custody-key`, or the KMS key `secrets.kmsKeyId` names) | **Every stored secret value, in plaintext.** | Decrypt outside every application policy. | `naapp/secrets/deploy/OPERATIONS.md`, "Secrets local-key-file custody" |
| Logs' database | Every retained event's content. | Purge or alter rows outside owner acts. | `naapp/logs/deploy/README.md`; `naapp/secrets/deploy/OPERATIONS.md`, Logs row |
| Logs' database **and** its `logs-chain` key | | Rewrite a team's history so that it verifies. Only receipts and checkpoints held outside the deployment can show it. | `naapp/secrets/deploy/OPERATIONS.md`, Logs row |
| The signer's database | Bindings, approvals, receipts, its local audit. No key. | | `server/src/aweb/protected_signing/HOST.md` |
| The signer's controller custody file (`signer/private-controller/controller.key`) | | Everything the team's controller key signs: admit and remove members, sign team records, outside the signer's one supported operation. | `HOST.md`, "Controller key installation, backup and cutover" |
| A service's member key (`aweb/<team>.key`, `secrets/awid-member-key`, `logs/awid-member-key`) | What that member reads in the team. | Act as that member. | |
| The front's key (`front/key.pem`) | | Serve the deployment's origins as the deployment. | `descriptors/front.md` |
| The agents' state (`agents.compose.stateDir`) and login | Every seat's key; every harness session transcript under `/state/home/.claude`; each `aw` interaction log; the harness login token. | Act as every seat, and as the harness account. | `deploy/team/access/agents.md` |
| The services network | Plaintext HTTP between the services and plaintext PostgreSQL. Redis needs its password, held in `aweb/redis-url`. | | `deploy/team/compose.yaml` |

A backup made with `teamctl backup` holds all of the files above and every
database: whoever holds the backup holds all of it (`OPERATIONS.md`).

Stating what the operator can do does not authorize it. Access to a team's data
follows the team's own authorization; the operator's runbook
(`OPERATIONS.md`) covers operating, not reading.
