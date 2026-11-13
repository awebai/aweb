# What an agent in the team container can read and reach

All the agents of one container run as one operating-system user. Whatever one
agent can read, every agent there can read. A prompt-injected agent has all of
the access in the first table.

## Readable by every agent of the container

| What | Where | Source |
| --- | --- | --- |
| Every seat's identity: its signing key, encryption keys and certificate | `/state/seats/<alias>/.aw` | OATS `docs/container.md`, seat provisioning |
| The harness login token | `/etc/agent-login/claude-token`, mounted read-only, group-readable by the agents' group | OATS `docs/container.md`: "readable by every agent in the same trust group; read-only mounting does not hide it or narrow its authority" |
| Claude Code's locally retained session transcripts, including prompts and tool output | The shared `/state/home/.claude` when the operator selects that launch configuration (`CLAUDE_CONFIG_DIR`), on the bind-mounted state that survives the container's recreation. OATS and `teamctl` do not prune that directory; the harness's own cleanup, and the operator or an agent deleting files, can remove its contents. It is persistent shared storage, not a complete or immutable archive. | OATS `docs/container.md`, launch configuration and shared storage |
| Every mail and chat an agent's `aw` sent or received (`aw mail`, `aw chat`, `aw run`): decrypted body, subject, sender and recipient | `.aw/interaction-log.jsonl` in the nearest directory above where `aw` runs that holds `.aw/context`, `.aw/workspace.yaml` or `.git`; file `0600`, directory `0700`, appended, never rotated. Readable by any process of the same user, so by every agent of the container, and by whoever holds the volume or its backups: end-to-end encryption protects messages in transit, not this file. Inside a repository it is in the working tree; `aw` adds `.aw/` to the repository's local exclude, but `git add -f`, or a repository without that exclude, can still commit it. Encrypting it under an owner-managed key is wanted and not built: `aweb-acyh`, OPEN. | `cli/go/cmd/aw/interaction_log.go`, `git_runtime_state.go` |
| The public CA and the operator's Git mirrors | `/etc/agent-trust/ca.pem`, `/mirrors` | `descriptors/agents.md` |

The knowledge-store publication credential is not provisioned: whether agents
get one, and with what scope, is a separate decision. Once provisioned, it is
readable by every agent like the login above.

## Not reachable from the container

| What | How it is kept out | Evidence |
| --- | --- | --- |
| Any service's credential | No secrets directory is mounted in the agent; the boundary probe checks that the service-private sources, the database and Redis volumes, the Docker socket, and the backup paths declared in its plan (the backups `teamctl` recorded in this run directory, and `TEAM_DEPLOYMENT_PROTECTED_SOURCES`) are out of reach. It cannot find a backup made or copied elsewhere. | `teamctl` boundary probe |
| PostgreSQL and Redis | The agent is on the agents network alone; egress denies both backends; Redis is on a network aweb alone shares, and needs its password. | Boundary probe; the journey's Redis isolation check |
| The internet | Egress forwards to five origins only: aweb, Secrets, Logs, the signer's request origin and the registry. | `descriptors/egress.md`; the ingress probe |
| A direct export of a stored value | No agent-facing route exports a stored value; Secrets' errors are fixed codes and its receipts have no body. Broker results are filtered and redacted, but an arbitrary transformation by the upstream is covered by no confidentiality guarantee: a credential an upstream returns is withheld only when redaction recognises it. | `naapp/secrets/values/src/aweb_secrets_values/redaction.py`; `naapp/secrets/src/aweb_secrets/member_types.py` |
| A signature from the signer | The signer signs only after a person approves in the browser. | `server/src/aweb/protected_signing/README.md` |

Egress bounds where packets go, not where data goes. aweb delivers mail to other
servers, and the Secrets broker sends requests the agent chooses under an
`open_request` grant, where both the grant and Secrets' policy allow it: both
carry data out through allowed origins.
