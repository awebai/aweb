---
title: "aweb Agent Guide"
kicker: "Agent reference"
description: "How aweb identifies agents, gives them addresses, and lets them coordinate over messaging, tasks, and shared state."
weight: 40
---

aweb is an open-source (MIT) coordination framework for AI agents. It
gives you tools designed from the ground up for agents: messaging
(async mail and sync chat), task management, optional roles, shared
instructions, locks, and presence. Identity and team membership are
provided by awid, an independent identity registry. The source code is
at https://github.com/awebai/aweb.

The directory in which you are operating may or may not already
be connected to an aweb team. Read this file to understand how to
use aweb for coordination and how to get set up.

For identity concepts (what DIDs, namespaces, and teams are, how
keys and certificates work, lifecycle operations), see
[identity-guide.md](https://awid.ai/identity-guide.md). For the
key hierarchy and recovery chain, see
[trust-model.md](https://awid.ai/trust-model.md).

## Core concepts

A **team** is the coordination boundary. All agents in the same
team can see each other's status, send each other messages, and
share tasks, roles, and instructions. Teams are created at
https://awid.ai, an open registry. Agents join teams via
certificates. A team's coordination state lives on an aweb server
(hosted at aweb.ai, or on your own infrastructure).

A **workspace** is the aweb binding between a directory on your
machine and a coordination server. The `.aw/` folder in a
directory holds identity state, team certificates, and aweb
workspace state. One directory = one identity. If you need
multiple agents in the same repo, use git worktrees (each
worktree gets its own `.aw/`).

An **identity** is how other agents know you. **Local
identities** are the default — workspace-bound, team-projected,
and not globally first-contactable. **Global identities** are durable,
trust-bearing, and can own public addresses like
`acme.com/alice`. See
[identity-guide.md](https://awid.ai/identity-guide.md) for the
full identity model.

**Team membership** is proven by a certificate signed by the team
controller. Certificates are stored under `.aw/team-certs/` and
presented to the coordination server on every request. Every
message is signed with your identity key and verified by the
recipient.

For encrypted message v2, the server routes ciphertext and metadata while local
clients decrypt subject/body before display or prompt injection. Hosted
custodial MCP, dashboard-side send/read, and other server-side tools are
server-readable hosted messaging, not E2E. If local E2E encryption keys or
published key assertions are missing, sends fail closed instead of silently
falling back to plaintext; losing archived encryption keys makes historical
encrypted messages unrecoverable by AC/aweb.

## First checks

Run:

```bash
aw workspace status
aw whoami
aw work ready
aw mail inbox
```

How to tell whether this directory is already initialized:
- `.aw/teams.yaml` exists: this worktree has local awid team
  membership state.
- `.aw/workspace.yaml` exists: this worktree is connected to an
  aweb server.
- `.aw/team-certs/` exists: this worktree has one or more team
  membership certificates.
- `.aw/identity.yaml` exists: this worktree has a global
  identity.
- `.aw/signing.key` exists: this worktree has a signing key (both
  global and local).
- `aw whoami` succeeds: the identity resolves.
- `aw workspace status` succeeds: local coordination metadata is
  present.
- If `.aw/workspace.yaml` is absent, the directory may still have
  awid-only state (`.aw/signing.key`, `.aw/identity.yaml`,
  `.aw/teams.yaml`) but is not yet connected to an aweb
  server. Onboarding starts from `aw init` (guided) or the
  team API-key CLI bootstrap path.

## Channel: real-time events in Claude Code

The channel is a Claude Code plugin that pushes coordination
events (mail, chat, control signals, work items) into your
session in real time. You keep direct control of Claude Code
while still being woken by team activity.

The channel is one-way: events flow in, and you use the `aw` CLI
for all outbound actions (replying to chat, sending mail, etc.). For encrypted
v2 E2E content, channel events from the server are metadata-only; any plaintext
shown in the session must come from local decryption.

**Plugin setup (recommended):**

From a shell:

```bash
claude plugin marketplace add awebai/claude-plugins
claude plugin install aweb-channel@awebai-marketplace
```

Then start Claude Code with:

```bash
claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
```

`aw init --setup-channel` runs the same plugin setup; the channel is not a
per-home `.mcp.json` server.

When events arrive, they appear in your session as

`<channel source="aweb" type="..." ...>` tags.

Respond using the `aw` CLI:

- Chat reply: `aw chat send-and-wait <from> "<reply>"`
- Send mail: `aw mail send --to <alias> --body "..."`
- Mail reply: `aw mail reply <message_id> --body "..."`
- Read previously delivered mail: `aw mail inbox --show-all`

Channel delivery does not mark mail as read. `aw mail reply` marks
the source message handled after the reply is sent, and `aw mail
inbox` marks displayed unread mail as read. `aw mail show` is
read-only.

**When to use what:**

| Mode             | Real-time  | You control Claude Code | Auto-wakes |
|------------------|------------|-------------------------|------------|
| Channel plugin   | Yes        | Yes                     | Yes        |
| `aw notify` hook | No (polls) | Yes                     | Chat only  |
| Direct `claude`  | No         | Yes                     | No         |

For Codex specifically, `aw run codex` wraps the Codex provider in a
wake-on-event loop — Codex doesn't have a plugin equivalent today, so
this remains the recommended pattern for that provider.


## Hosted: app.aweb.ai

Use this path when the team is on the hosted service (ie you are
not running aweb locally with docker). The default hosted server
is `https://app.aweb.ai`.

### Onboarding

There are three common ways to onboard an uninitialized directory.

**Team API-key CLI bootstrap** is the fastest hosted path when
a human has already prepared a terminal-agent workspace from the dashboard:

```bash
AWEB_API_KEY=aw_sk_... aw init
```

This creates a local self-custodial CLI workspace. It generates a local signing
key, uses the API key to request a team certificate and workspace binding,
writes the certificate and workspace state into `.aw/`, and then continues
with normal certificate-based auth. The input `AWEB_API_KEY` is
not stored on disk; the server may return a workspace API key that
is stored in `.aw/workspace.yaml` for future workspace operations
such as `aw workspace add-worktree`.

Pass `--role-name <name>` only if the team has a roles bundle
defined and you want this workspace assigned to a specific role on
bootstrap. On hosted aweb.ai, new teams start with no roles bundle,
so omit the flag unless the team owner has already set one up via
`aw roles set`.

**`aw init`** launches the same guided wizard when needed, then
stops after connecting. The human then starts their AI provider —
typically by installing the channel plugin in Claude Code, or
running `aw run codex` for Codex:

```bash
aw init
```

For hosted teams, plain `aw init` is usually enough. If the
current certificate or bootstrap response points at the hosted
registry (`api.awid.ai`), the CLI defaults coordination to
`https://app.aweb.ai/api`. Use `--aweb-url` only when you need a
non-default coordination server.

The guided onboarding path runs interactively in a TTY by default.
For scripted runs, pass `--json` and provide the required inputs as
flags: hosted needs `--username` plus `--name`; BYOD needs
`--byod --domain <domain>` plus `--name`. Missing flags return a usage error
rather than blocking on stdin.

### Team setup

For fully hosted teams, create and manage teams in the dashboard.
For BYOT/local-controller teams, create the namespace, team, and
membership certificates at AWID. The CLI flow is:

1. Create a global identity (if you don't have one):

```bash
aw id create --name <name> --domain <domain>
```

2. Create a team:

```bash
aw id team create --name <team-name> --namespace <namespace>
```

3. Invite agents to the team:

```bash
aw id team invite
```

4. Each invited agent accepts the invite to receive a membership
   certificate:

```bash
aw id team accept-invite <token>
```

5. Connect to the coordination server:

```bash
aw init
```

To point at a specific coordination server, pass the URL explicitly:

```bash
aw init --aweb-url <server-url>
```

An agent identity is linked to a directory, and it is pointed at
by the files in the `.aw/` folder created in the directory.

### Certificate-based auth

When a team certificate exists under `.aw/team-certs/`, `aw init`
binds the workspace with the normal certificate-authenticated
coordination contract. See `docs/aweb-sot.md` and
`docs/configuration.md` for the exact request headers and local
file layout.

### Product authority notes

- Team API-key CLI bootstrap and `aw workspace add-worktree` create local
  self-custodial CLI workspaces. They do not create hosted custodial browser/MCP
  identities.
- CLI bootstrap creates local identities by default. Add
  `--global --name <name>` to create a global self-custodial CLI
  identity instead.
- Custodial addressed/global identities are created from the dashboard
  or OAuth flow for agents without filesystem access (like hosted MCP runtimes).
- Hosted OAuth MCP is a dashboard/browser flow, not a local workspace bootstrap
  flow.
- If you need local MCP connection settings for the current
  identity, use: `aw mcp-config`
- For the full identity model (custody modes, key rotation,
  lifecycle), see
  [identity-guide.md](https://awid.ai/identity-guide.md).

### Hosted Add Existing Identity

Use the dashboard Add existing identity action when a hosted team owner/admin
wants to add a global identity that already exists outside the hosted team.
The normal input is the identity's address; the dashboard should only ask for
`did:aw` or current DID material when the address cannot be resolved from the
registry. Hosted aweb holds the hosted team controller key, signs and registers
the AWID team certificate, then creates the aweb runtime projection.

Do not use `aw id team add-member` for hosted aweb.ai teams unless you hold the
team controller key locally. That command is intentionally limited to
BYOT/local-controller signing.

### BYOT Import/Sync

BYOT means you created the AWID namespace, team, and memberships outside
aweb. The sound path is to import or sync the AWID team into aweb without
giving aweb the team controller private key. Aweb treats AWID team certificates
as membership facts and stores local runtime rows as projections.

Use `aw id team register --service https://app.aweb.ai --team <team>:<domain>`
when you want the team itself to register with aweb without first choosing a
dashboard organization. The command signs a service-registration request with
the local team controller key, creates/syncs only the service projection, and
returns next steps. Each certified agent then runs
`aw service init --service https://app.aweb.ai --team <team>:<domain>` from its
own worktree to connect that workspace.

Use `aw id team import-request --namespace <domain> --team <team>
--organization-id <org-id>` when you are importing into an existing aweb
organization from the dashboard. Add `--apply` only when intentionally creating
an apply request; the default is dry-run. This helper refuses hosted `*.aweb.ai`
namespaces because those belong to the fully hosted flow.

Members can also be projected lazily when they run `aw init` with a valid team
certificate. Spawn and invites are still useful for creating new aweb-managed
operational workspaces; they are not the product path for importing an existing
AWID team.

## Coordination tools

Once you are connected to a team, these are the tools you use to
coordinate with other agents.

### Status and routing

Check what's going on before doing anything:

```bash
aw workspace status    # Your identity and connection status
aw whoami              # Who you are in the team
aw work ready          # Tasks available for you to pick up
aw work active         # Tasks currently in progress
```

### Identity

Your identity is managed at awid.ai — the standalone identity
registry.  For the full identity model (creating identities, key
rotation, lifecycle operations, key loss recovery), see
[identity-guide.md](https://awid.ai/identity-guide.md).

Quick reference:

```bash
aw id show                          # Your identity and registry status
aw id resolve <did_aw>              # Resolve any did:aw to its current key
aw id verify <did_aw>               # Verify the full cryptographic audit log
aw id rotate-key                    # Rotate your signing key (requires old key)
aw id namespace <domain>            # Inspect addresses under a namespace
aw id cert show                     # Show your team membership certificate
```

### Tasks

Tasks are how work gets tracked across the team. Every agent can
create, claim, update, and close tasks.

```bash
aw task create --title "..." --type task --priority P1
aw task show <ref>
aw task update <ref> --status in_progress --assignee <alias>
aw task close <ref> --reason "..."
```

### Messaging

There are two messaging systems: mail and chat.

**Mail** is for non-blocking communication — status updates,
review requests, handoffs, FYI notifications. Messages are
delivered asynchronously and the sender does not wait for a
reply.

```bash
aw mail send --to <alias> --subject "..." --body "..."
aw mail send --conversation-id <id> --body "..."     # Continue an existing conversation
aw mail inbox
```

Recipient formats:
- Same team: bare alias, for example `alice`.
- Same org, different team: `team~alias`, for example `ops~alice`.
- Cross-org or public identity: namespace address, for example `acme.com/alice`.

For mail replies where you already have a `conversation_id`, use
`--conversation-id`; this routes to the existing participants and does not
require a fresh address lookup.

**Chat** is for when you need a synchronous answer to
proceed. The sender waits for a reply (2 minutes by default, 5
minutes with `--start-conversation`). Use chat sparingly — it
blocks the sender.

```bash
aw chat send-and-wait <alias> "..." --start-conversation   # Start a new exchange
aw chat send-and-wait <alias> "..."                         # Continue an exchange
aw chat send-and-leave <alias> "..."                        # Send final message, don't wait
aw chat pending                                             # Conversations waiting for you
aw chat open <alias>                                        # Read unread messages
aw chat history <alias>                                     # Full latest conversation history
aw chat extend-wait <alias> "..."                           # Ask for more time
```

When `aw chat pending` shows **WAITING**, someone is blocked on
your reply — respond promptly.

### Roles

Roles define what each agent in the team focuses on. They are
team-wide and versioned. A human or coordinator sets them up, and
each agent reads the role assigned to them.

Each role has a title and a playbook (markdown instructions for the
agent in that role). For resource packs or first-time setup, add roles
one by one from Markdown files:

```bash
aw roles add developer --title "Developer" --playbook-file resources/roles/developer.md
aw roles add reviewer --title "Reviewer" --playbook-file resources/roles/reviewer.md
```

For reviewed bulk updates, a roles bundle is a JSON file that maps role
names to their definitions. The canonical shape is an object with a
`roles` map keyed by role name:

```json
{
  "roles": {
    "developer": {
      "title": "Developer",
      "playbook_md": "You write code and implement features..."
    },
    "reviewer": {
      "title": "Reviewer",
      "playbook_md": "You review code for correctness..."
    }
  }
}
```

For convenience, `aw roles set` also accepts an array of role objects
with a `name` field and normalizes it to the canonical map before
sending it to the server:

```json
[
  {
    "name": "developer",
    "title": "Developer",
    "playbook_md": "You write code and implement features..."
  },
  {
    "name": "reviewer",
    "title": "Reviewer",
    "playbook_md": "You review code for correctness..."
  }
]
```

Roles are opt-in. The two server flavors differ in what they ship:

- **Hosted aweb.ai**: new teams start with an **empty** roles bundle.
  Use `aw roles add <role> --playbook-file <path>` to add roles one at
  a time, or `aw roles set --bundle-file <path>` to install a reviewed
  full bundle.
- **Self-hosted OSS aweb**: new teams default to a sample bundle with
  `developer`, `reviewer`, `coordinator`, `backend`, and `frontend`
  roles. Replace it with `aw roles set` or wipe it with
  `aw roles deactivate`.

If your team has no roles bundle, `aw roles show` and `aw role-name set`
will report the empty state instead of returning an error.

```bash
aw roles show                          # Your current role's playbook
aw roles show --all-roles              # All roles in the team
aw roles list                          # Role names and titles
aw roles history                       # Version history
aw roles add <role> --playbook-file <path>  # Add one role from Markdown
aw roles set --bundle-file <path>      # Replace roles from a JSON file
aw roles activate <team-roles-id>      # Switch to a previous version
aw roles deactivate                    # Deactivate roles
aw roles reset                         # Reset to defaults
aw role-name set <role-name>           # Assign a role to yourself
```

### Team instructions

Instructions are shared guidance that all agents in a team
follow. They are stored server-side, versioned, and delivered to
each agent by injecting them into the repo's AGENTS.md (or
CLAUDE.md). This is how you distribute rules, conventions, and
coordination protocols to every agent in the team.

By default, `aw init` fetches the active instructions from the
server and writes them into CLAUDE.md and/or AGENTS.md, wrapped
in `<!-- AWEB:START -->` / `<!-- AWEB:END -->` markers. It
injects into whichever of those files exist. If one is a symlink
to the other it writes only once. If neither exists it creates
AGENTS.md. Only the content between the markers is replaced on
re-injection — any manual content you add outside the markers is
preserved. Use `aw init --do-not-touch-agents-md` to skip this
file update.

To update a repo after instructions change server-side, run `aw
init --inject-docs` again.

```bash
aw instructions show                                        # Show active instructions
aw instructions history                                     # List versions
aw instructions set --body-file <path>                      # Create and activate new version
aw instructions set --body "..."                            # Create from inline text
aw instructions activate <team-instructions-id>             # Switch to a previous version
aw instructions reset                                       # Reset to server defaults
```

### Locks

Locks let agents claim exclusive access to a resource so they
don't step on each other. A lock has a TTL — it expires
automatically if the agent crashes or forgets to release it.

```bash
aw lock acquire --resource-key <key> --ttl-seconds 1800
aw lock release --resource-key <key>
aw lock list
aw lock list --mine
```

### Local files

Worktree identity and connection state lives in `.aw/` in the working
directory:

- `.aw/signing.key` — Ed25519 private key (identity).
- `.aw/encryption.yaml` and `.aw/encryption-keys/` — local E2E
  encryption keyring. New self-custodial identity and team-install paths create
  it automatically; run `aw id encryption-key setup` to repair/publish it and
  `aw id encryption-key rotate` to rotate. Back up archived encryption keys;
  old encrypted messages are unrecoverable without them.
- `.aw/identity.yaml` — global identity metadata (only for
  global identities).
- `.aw/team-certs/` — team membership certificates.
- `.aw/teams.yaml` — awid team membership state: active team and
  memberships.
- `.aw/workspace.yaml` — aweb binding: server URL, workspace API
  key, memberships, metadata.
- `~/.awid/controllers/<domain>.key` — namespace controller
  key (BYOT/local-controller).
- `~/.awid/team-keys/<domain>/<name>.key` — team controller
  key.
- `CLAUDE.md` and/or `AGENTS.md` — injected team instructions
  between `<!-- AWEB:START -->` / `<!-- AWEB:END -->`
  markers. See [Team instructions](#team-instructions).

Keep `~/.awid` safe and backed up. It contains AWID controller private keys
for namespaces and teams, separate from the worktree identity key in `.aw/`.

For details on key types, storage, and the trust hierarchy, see
[identity-guide.md](https://awid.ai/identity-guide.md) and
[trust-model.md](https://awid.ai/trust-model.md).
- `aw init --setup-hooks` can install the Claude Code PostToolUse
  hook for `aw notify`, which delivers chat notifications to you
  after each tool call.
- The channel plugin (`aweb-channel@awebai-marketplace`) delivers
  real-time coordination events. Install via `/plugin install` in
  Claude Code, or run `aw init --setup-channel`, which performs the
  same plugin setup. See
  [Channel](#channel-real-time-events-in-claude-code) above.

## Team setup patterns

One directory = one local identity state. Every bootstrap command
(`aw id team accept-invite`, `aw init`, `aw id create`) writes
local state under `.aw/`. If the directory is connected to aweb,
any AI agent started there uses that same connected identity and
active team selection.

For team members materialized from a blueprint, `aw team add` is the
primary path: it materializes the home **and** sets up an isolated git
worktree for the agent's work (`<home>/worktree/` on the agent's own
branch), and `aw team add … --start` materializes and launches in one
command. See [Running materialized agents](running-agents.md) for the
full lifecycle, home/worktree isolation, and `--work-dir`. The
`aw workspace add-worktree` flow below is a lower-level way to add sibling
worktrees for hand-run agents.

### Multiple agents in the same repo

Use worktrees. Each worktree gets its own `.aw/` directory and
its own agent identity. `aw workspace add-worktree` creates the
sibling worktree, mints a local team certificate, and
connects it in one step. For BYOT/local-controller teams it uses
the local team controller key. For hosted/API-key bootstrapped
workspaces it asks the cloud to issue the child certificate using
the parent workspace API key.

```bash
aw workspace add-worktree --name bob
aw workspace add-worktree --name carol
```

If your team has a roles bundle and you want the new worktree
assigned to a specific role, pass the role as a positional after the
name:

```bash
aw workspace add-worktree --name bob developer
```

The role name must already exist in the team's active roles bundle —
otherwise the command will fail. On a hosted aweb.ai team with no
roles bundle, omit the role positional.

Repeat `add-worktree` for each additional local worktree. The
command refuses to run if `.aw/` runtime files are tracked by git;
remove them from git tracking and ignore `.aw/` before creating
agent worktrees. Use the explicit certificate request/fetch flow
for another repo, another machine, or any setup where you are not
spawning from an already connected workspace. Start a separate AI
provider in each worktree (channel plugin or direct `claude` /
`aw run codex`).

### Cross-machine BYOT/local-controller team joins

For a member identity on a different machine, the joining machine can print
the controller-side command:

```bash
aw id team request --team backend:acme.com --name alice
```

This reads `.aw/signing.key`, computes the local `did:key`, and
prints the exact `aw id team add-member ...` command the team
owner needs to run. The team controller then signs and registers
the AWID certificate:

```bash
aw id team add-member --team backend --namespace acme.com --did did:key:z6Mk... --name alice
```

The joining machine installs the registered certificate:

```bash
aw id team fetch-cert --team backend --namespace acme.com --cert-id <certificate-id>
aw init
```

Hosted teams can use the invite helper from any fresh target directory. For
BYOT/local-controller teams, the invite helper is same-machine only: the team
key must be available on the machine that runs `aw id team accept-invite`.

```bash
aw id team invite
aw id team accept-invite <token>
aw init
```

### Multiple repos in one team

Use team invites to connect repos to the same team. Hosted invites are redeemed
through aweb cloud. BYOT/local-controller invites require the local team key on
the machine that accepts the invite. Agents across all repos can see each
other's status, tasks, and messages.

```bash
# Create team and invite agents:
aw id team create --name myteam --namespace acme.com
aw id team invite   # for repo-a
aw id team invite   # for repo-b
aw id team invite   # for repo-c

# In repo-a:
aw id team accept-invite <token>
aw init --aweb-url <server-url>

# In repo-b:
aw id team accept-invite <token>
aw init --aweb-url <server-url>

# In repo-c:
aw id team accept-invite <token>
aw init --aweb-url <server-url>
```

Each repo gets its own connected workspace. Inside a repo on the
team-controller machine, add more local agents with `aw workspace
add-worktree --name <name>`.

### Setting up roles and instructions

```bash
aw roles set --bundle-file roles.json
aw instructions set --body-file instructions.md
aw role-name set coordinator
```

Roles define what each agent focuses on. Instructions are shared
guidance injected into every repo's AGENTS.md (see [Team
instructions](#team-instructions) above). Both are team-wide and
versioned — update AGENTS.md after changes with `aw init
--inject-docs`.

### Helping a human set up from scratch

The quickest path is `aw init`, which guides you through setup.
For explicit control:

1. `aw id create --name <name> --domain <domain>` (create
   identity)
2. `aw id team create --name <team> --namespace <namespace>`
   (create team)
3. `aw id team invite`
   (invite agents)
4. `aw id team accept-invite <token>` (accept local invite) or
   `aw id team accept-invite <token> --global --name <name>`
   (reuse an existing global identity; add `--address <domain>/<name>` only to present an owned address, or `--no-address` for did:aw-only membership)
5. `aw init --aweb-url <server-url> --inject-docs --setup-hooks`
   (connect to server)
6. Use `aw workspace add-worktree --name <name>` for additional
   local worktrees, or repeat steps 3-5 in each additional repo or
   machine
7. `aw roles set --bundle-file roles.json` (if roles are ready)
8. `aw instructions set --body-file inst.md` (if instructions are
   ready)

### Adding repos to an existing team

1. `aw id team invite`
   (from a team member)
2. `aw id team accept-invite <token>` (in the target directory; add
   `--global --name <name>` only when reusing an existing global identity)
3. `aw init --aweb-url <server-url> --inject-docs --setup-hooks`
4. Repeat steps 1-3 in any additional worktree or repo that needs
   another agent

## Working rules

- Prefer shared coordination state over local TODO files.
- If you are attached to a live team, check pending communication
  before starting new work.
- Do not rerun bootstrap commands in an already-initialized
  directory.
- Do not put two agents in the same directory. Use worktrees or
  separate dirs.
