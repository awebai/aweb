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
| Locally logged mail and chat text, plaintext after `aw` decrypts it, and `aw run`'s user prompts and agent output: a best-effort log, not a complete transcript (`aw mail show` does not append; blank or duplicate entries may be skipped; a write error goes only to debug output) | `<log-root>/.aw/interaction-log.jsonl`, where log-root is the nearest ancestor of the command's working directory with `.aw/context`, `.aw/workspace.yaml` or `.git`, or the working directory if there is none: usually the repository's root, unless a nearer workspace marker wins. `AWEB_IDENTITY_HOME` does not choose it. Created `0600` (an existing file's mode is not repaired), appended by this logger, never rotated or pruned. Readable by any process of the same user, so by every agent of the container, and by whoever holds the volume or its backups: end-to-end encryption protects messages in transit, not this file. The logger adds no ignore rule: `aw`'s workspace setup adds `.aw/` to a repository's local exclude, but in another repository, or with `git add -f`, it can be committed. Sealing under the team owner's log key is built (`aweb-acyh`): once the pinned `aw` includes it and the owner's key is installed, new lines are sealed and only the owner's machine reads them; lines written before the install stay plaintext (`deploy/team/OPERATIONS.md`, "The owner's log key"). | `cli/go/cmd/aw/interaction_log.go`, `mail.go`, `chat.go`, `run.go`, `git_runtime_state.go` |
| The subjects and bodies of the mail and chat each account's `aw` sends and receives, again | Per-account communication logs, `~/.config/aw/logs/<account>.jsonl` (in the container, under `/state/home`): best-effort, created `0600`, readable as above, and sealed like the interaction log once the owner's key is installed. | `cli/go/awconfig/state.go`, `cli/go/cmd/aw/commlog.go` |
| The public CA and the operator's Git mirrors | `/etc/agent-trust/ca.pem`, `/mirrors` | `descriptors/agents.md` |

The knowledge-store publication credential is not provisioned: whether agents
get one, and with what scope, is a separate decision. Once provisioned, it is
readable by every agent like the login above.

## Not reachable from the container

| What | How it is kept out | Evidence |
| --- | --- | --- |
| Any service's credential | No secrets directory is mounted in the agent; the boundary probe checks that the service-private sources, the database and Redis volumes, the Docker socket, and the backup paths declared in its plan (the backups `teamctl` recorded in this run directory, and `TEAM_DEPLOYMENT_PROTECTED_SOURCES`) are out of reach. It cannot find a backup made or copied elsewhere. | `teamctl` boundary probe |
| PostgreSQL and Redis | The agent is on the agents network alone; egress denies both backends; Redis is on a network aweb alone shares, and needs its password. | Boundary probe; the journey's Redis isolation check |
| The rest of the internet | Egress forwards to the deployment's five origins (aweb, Secrets, Logs, the signer's request origin and the registry) and, only where the operator turns them on, to `https://github.com` (`egress.external.source`) and `https://api.anthropic.com` (`egress.external.model`). Nothing else. | `descriptors/egress.md`; the ingress probe |
| A direct export of a stored value | No agent-facing route exports a stored value; Secrets' errors are fixed codes and its receipts have no body. Broker results are filtered and redacted, but an arbitrary transformation by the upstream is covered by no confidentiality guarantee: a credential an upstream returns is withheld only when redaction recognises it. | `naapp/secrets/values/src/aweb_secrets_values/redaction.py`; `naapp/secrets/src/aweb_secrets/member_types.py` |
| A signature from the signer | The signer signs only after a person approves in the browser. | `server/src/aweb/protected_signing/README.md` |

Egress bounds where packets go, not where data goes. aweb delivers mail and
chat to the other servers the operator lists (`aweb.federationOutbound`; none by
default, `deploy/team/OPERATIONS.md`), and the Secrets broker sends requests
the agent chooses under an `open_request` grant, where both the grant and
Secrets' policy allow it: both carry data out through allowed origins.

With `egress.external.source` on, an agent reaches all of `github.com`, not
only the OATS repositories: egress forwards by SNI and cannot see the path,
method or repository inside TLS. Without any credential, an agent can still
send data to GitHub in request paths, query strings and request bodies, and
fetch any public repository, each file of which can carry instructions aimed
at it. The rule bounds the host, nothing more. No credential that can publish
to GitHub is provisioned. With `egress.external.model` on, the harness's
requests go to the model provider (`deploy/team/access/registry-and-provider.md`).
