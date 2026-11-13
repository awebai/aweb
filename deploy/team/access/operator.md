# What the operator can read and do

The operator runs the machine that holds the deployment: Docker, the volumes,
`compose.secretsDir` and the backups. When one organization operates a
deployment for another team, the operating organization is this operator, and
the team's own page tells the team so.

Root on the host, or membership of the `docker` group (root-equivalent), reaches
everything below. Each row is what one artifact gives on its own.

| Holding | Reads | Can do | Source |
| --- | --- | --- | --- |
| aweb's database (`postgres_data`, database `aweb`, or a backup) | Mail and chat bodies and mail subjects sent the default way, in plaintext. For self-custodial `--e2ee` messages, ciphertext and routing and read metadata only: neither subject nor body is readable from the database alone. Tasks, workspaces, instructions, roles and audit records. | Change or delete any of it. | `docs/e2e-messaging-contract.md`; `server/src/aweb/messaging/messages.py`; `migrations/aweb/005_messages_encrypted_v2_shape_legacy_fields.sql` |
| Secrets' database | Metadata, grants and receipts, readable; every stored credential value as ciphertext only. A value kept in 1Password is in the database as a reference, its token sealed. | | `naapp/secrets/src/aweb_secrets/custody/store.py` |
| Secrets' database **and** the matching local custody key (`secrets/custody-key`), or authorized KMS Decrypt on the key `secrets.kmsKeyId` names | **Every value it retains sealed under that key, in plaintext**, the 1Password backend's token included; with that token, the vault's items. | Decrypt outside every application policy. | `naapp/secrets/src/aweb_secrets/custody/sealing.py`, `providers.py`, `opening.py`; `naapp/secrets/deploy/OPERATIONS.md` |
| Logs' database | Every retained event's content. | Purge any event's content, naming any act. Alter or drop rows, which verify reports. | `naapp/logs/deploy/README.md`; `naapp/secrets/deploy/OPERATIONS.md`, Logs row |
| Logs' database **and** its `logs-chain` key | | Drop, reorder or purge events and re-sign receipts and checkpoints so that the chain verifies. Changing an event's content also needs its producer's key, which the secrets directory holds. Only receipts and checkpoints held outside the deployment show it. | `naapp/secrets/deploy/OPERATIONS.md`, Logs row |
| The signer's database | Bindings, approvals, receipts, its local audit, the bootstrap and enrollment records, and the people's WebAuthn public credentials. No controller private key. | Alter those authority and credential records, the receipts and the audit. | `server/src/aweb/protected_signing/migrations/002_operator_bootstrap.sql`; `naapp-lib` passkey migrations |
| The signer's controller custody file (`signer/private-controller/controller.key`) | | Everything the team's controller key signs: admit and remove members, sign team records, outside the signer's one supported operation. | `HOST.md`, "Controller key installation, backup and cutover" |
| A service's member key (`aweb/<team>.key`, `secrets/awid-member-key`, `logs/awid-member-key`) | What that member reads in the team. | Act as that member. | |
| The front's key (`front/key.pem`) | | Serve the deployment's origins as the deployment. | `descriptors/front.md` |
| The agents' state (`agents.compose.stateDir`) and login | Every seat's key; the harness's locally retained session transcripts (under `/state/home/.claude` when that launch configuration is selected); each `aw` interaction log; the harness login token. | Act as every seat, and as the harness account. | `deploy/team/access/agents.md` |
| The services network | Plaintext HTTP between the services and plaintext PostgreSQL. Redis needs its password, held in `aweb/redis-url`. | | `deploy/team/compose.yaml` |

A backup made with `teamctl backup` holds every database and all of the files
above but the signer's controller custody, which it leaves out: whoever holds
the backup holds all the rest (`OPERATIONS.md`).

Stating what the operator can do does not authorize it. Access to a team's data
follows the team's own authorization; the operator's runbook
(`OPERATIONS.md`) covers operating, not reading.
