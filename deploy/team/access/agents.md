# What an agent in the team container can read and reach

All the agents of one container run as one operating-system user. Whatever one
agent can read, every agent there can read. A prompt-injected agent has all of
the access in the first table.

## Readable by every agent of the container

| What | Where | Source |
| --- | --- | --- |
| Every seat's identity: its signing key, encryption keys and certificate | `/state/seats/<alias>/.aw` | OATS `docs/container.md`, seat provisioning |
| The harness login token | `/etc/agent-login/claude-token`, mounted read-only, group-readable by the agents' group | OATS `docs/container.md`: "readable by every agent in the same trust group; read-only mounting does not hide it or narrow its authority" |
| Every harness session, verbatim | `/state/home/.claude` (`CLAUDE_CONFIG_DIR`), one directory for all agents, on the state volume that outlives the container. Nothing in the bundle removes old sessions. | OATS `docs/container.md`, launch configuration |
| Every mail and chat an agent's `aw` sent or received, decrypted | `.aw/interaction-log.jsonl` at the nearest directory, from where `aw` runs, that holds `.aw/context`, `.aw/workspace.yaml` or `.git`: inside a repository, that is the repository's root, untracked. Mode `0600`, appended, never rotated. | `cli/go/cmd/aw/interaction_log.go` |
| The public CA and the operator's Git mirrors | `/etc/agent-trust/ca.pem`, `/mirrors` | `descriptors/agents.md` |

The knowledge-store publication credential is not provisioned: whether agents
get one, and with what scope, is a separate decision. Once provisioned, it is
readable by every agent like the login above.

## Not reachable from the container

| What | How it is kept out | Evidence |
| --- | --- | --- |
| Any service's credential | No secrets directory is mounted in the agent; the boundary probe checks every secrets directory, the database and Redis volumes, the Docker socket and every backup is out of reach. | `teamctl` boundary probe |
| PostgreSQL and Redis | The agent is on the agents network alone; egress denies both backends; Redis is on a network aweb alone shares, and needs its password. | Boundary probe; the journey's Redis isolation check |
| The internet | Egress forwards to five origins only: aweb, Secrets, Logs, the signer's request origin and the registry. | `descriptors/egress.md`; the ingress probe |
| A stored secret's value | No route of Secrets returns one; its errors are fixed codes and its receipts have no body. A credential an upstream returns is withheld only when its redaction recognises it. | `naapp/secrets/deploy/OPERATIONS.md` |
| A signature from the signer | The signer signs only after a person approves in the browser. | `server/src/aweb/protected_signing/README.md` |

Egress bounds where packets go, not where data goes. aweb delivers mail to other
servers, and the Secrets broker sends requests the agent chooses under an
`open_request` grant: both carry data out through allowed origins.
