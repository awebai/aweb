# CLI Command Reference

This reference is generated from the live Cobra help tree emitted by the
`aw` binary built from [`cli/go/cmd/aw/`](../cli/go/cmd/aw). Run
[`scripts/regenerate-cli-reference.sh`](../scripts/regenerate-cli-reference.sh)
to refresh it.

## Command Families

| Family | Commands |
| --- | --- |
| Workspace Setup | `connect`, `init`, `reset`, `workspace` |
| Identity | `claim-human`, `id`, `mcp-config`, `whoami` |
| Messaging & Network | `chat`, `contacts`, `control`, `directory`, `events`, `heartbeat`, `log`, `mail` |
| Coordination & Runtime | `instructions`, `lock`, `notify`, `role-name`, `roles`, `run`, `task`, `work` |
| Utility | `completion`, `help`, `upgrade`, `version` |

## Global Flags

- `--debug Log background errors to stderr`
- `-h, --help help for aw`
- `--json Output as JSON`
- `--server-name string Override the server host or name for this command`

## `connect`

### `connect`

Connect this directory to a team using a bootstrap token

Flags:
- `--address string Persistent public address from the dashboard copy command`
- `--bootstrap-token string One-time bootstrap token from the dashboard`
- `-h, --help help for connect`
- `--mock-url string Override the bootstrap/aweb base URL for local development`

## `init`

### `init`

Initialize the current directory using one of the supported
team-architecture flows:

- connect with an existing team certificate already present in .aw/
- create a hosted aweb.ai account with --hosted
- launch guided onboarding in a TTY when this directory is still clean

Flags:
- `--agent-type string Runtime type (default: AWEB_AGENT_TYPE or agent)`
- `--alias string Ephemeral identity routing alias (optional; default: server-suggested)`
- `-h, --help help for init`
- `--hosted Create a hosted aweb.ai identity in this directory`
- `--human-name string Human name (default: AWEB_HUMAN or $USER)`
- `--inject-docs Inject aw coordination instructions into CLAUDE.md and AGENTS.md`
- `--name string Persistent identity name (required with --persistent unless .aw/identity.yaml already exists)`
- `--persistent Create a durable self-custodial identity instead of the default ephemeral identity`
- `--print-exports Print shell export lines after JSON output`
- `--reachability string Persistent address reachability (private|org-visible|contacts-only|public)`
- `--role string Compatibility alias for --role-name`
- `--role-name string Workspace role name (must match a role in the active team roles bundle)`
- `--setup-channel Set up Claude Code channel MCP server for real-time coordination`
- `--setup-hooks Set up Claude Code PostToolUse hook for aw notify`
- `--url string Base URL for the aweb server used for init, bootstrap, and hosted onboarding flows`
- `--username string Hosted username to create with --hosted`
- `--write-context Ensure .aw/context exists in the current directory (default true)`

## `reset`

### `reset`

Removes the local .aw/context and .aw/workspace.yaml files in the current directory without mutating any server-side identity state.

Flags:
- `-h, --help help for reset`

## `workspace`

### `workspace`

Manage repo-local coordination workspaces

Subcommands:
- `add-worktree` Create a sibling git worktree and initialize a new coordination workspace in it
- `status` Show coordination status for the current workspace/identity and team

Flags:
- `-h, --help help for workspace`

## `workspace add-worktree`

### `workspace add-worktree`

Create a sibling git worktree and initialize a new coordination workspace in it

Flags:
- `--alias string Override the default alias`
- `-h, --help help for add-worktree`

## `workspace status`

### `workspace status`

Show coordination status for the current workspace/identity and team

Flags:
- `--all Show all local team memberships in addition to the selected team status`
- `-h, --help help for status`
- `--limit int Maximum team workspaces to show (default 15)`

## `claim-human`

### `claim-human`

Attach an email address to your CLI-created account

Flags:
- `--email string Email address to attach to the current CLI-created account`
- `-h, --help help for claim-human`
- `--mock-url string Override the bootstrap base URL for local development`

## `id`

### `id`

Identity lifecycle, registry, settings, and key management

Subcommands:
- `cert` Team certificate operations
- `create` Create a standalone persistent identity with a DNS-backed address in .aw/
- `log` Show an identity log
- `namespace` Inspect a namespace and its registered addresses
- `register` Register the current persistent identity at awid.ai
- `rotate-key` Rotate the current persistent identity signing key at the registry
- `request` Make a DIDKey-signed HTTP request with the local identity key
- `resolve` Resolve a did:aw to its current did:key
- `show` Show the current identity and registry status
- `sign` Sign a canonical JSON payload with the local identity key
- `team` Team management (create, invite, membership)
- `verify` Verify the full audit log for a did:aw

Flags:
- `-h, --help help for id`

## `id cert`

### `id cert`

Team certificate operations

Subcommands:
- `show` Show the current team certificate

Flags:
- `-h, --help help for cert`

## `id cert show`

### `id cert show`

Show the current team certificate

Flags:
- `-h, --help help for show`

## `id create`

### `id create`

Create a standalone persistent identity with a DNS-backed address in .aw/

Flags:
- `--domain string Persistent identity domain`
- `-h, --help help for create`
- `--name string Persistent identity name`
- `--registry string Registry origin override (default: api.awid.ai)`
- `--skip-dns-verify Skip the DNS TXT verification prompt and lookup`

## `id log`

### `id log`

Display rotation and status history. Without arguments, shows your own log.

Flags:
- `-h, --help help for log`

## `id namespace`

### `id namespace`

Inspect a namespace and its registered addresses

Flags:
- `-h, --help help for namespace`

## `id register`

### `id register`

Register the current persistent identity at awid.ai

Flags:
- `-h, --help help for register`

## `id rotate-key`

### `id rotate-key`

Rotate the current persistent identity signing key at the registry

Flags:
- `-h, --help help for rotate-key`

## `id request`

### `id request`

Make a DIDKey-signed HTTP request with the local identity key

Flags:
- `--body string Request body to send`
- `--body-file string Read the request body from a file`
- `--header stringArray Additional header in 'Name: Value' form`
- `-h, --help help for request`
- `--raw Print only the upstream response body`
- `--sign string JSON object describing the signed payload fields`
- `--sign-file string Read the JSON sign payload from a file`

## `id resolve`

### `id resolve`

Resolve a did:aw to its current did:key

Flags:
- `-h, --help help for resolve`

## `id show`

### `id show`

Show the current identity and registry status

Flags:
- `-h, --help help for show`

## `id sign`

### `id sign`

Sign a canonical JSON payload with the local identity key

Flags:
- `-h, --help help for sign`
- `--payload string JSON object to sign`
- `--payload-file string Read the JSON payload to sign from a file`

## `id team`

### `id team`

Team management (create, invite, membership)

Subcommands:
- `add` Join another team in this workspace with the current identity
- `accept-invite` Accept a team invite and receive a membership certificate
- `add-member` Add a member directly to a team (controller signs certificate)
- `create` Create a team at awid
- `invite` Generate an invite token for a team
- `leave` Remove a team membership from this workspace
- `list` List team memberships for this workspace
- `remove-member` Remove a member from a team (revoke certificate)
- `switch` Switch the active team for this workspace

Flags:
- `-h, --help help for team`

## `id team add`

### `id team add`

Join another team in this workspace with the current identity

Flags:
- `--alias string Alias for the added team membership (defaults to the current identity name)`
- `-h, --help help for add`

## `id team accept-invite`

### `id team accept-invite`

Accept a team invite and receive a membership certificate

Flags:
- `--alias string Alias for the accepting agent (defaults to identity name)`
- `-h, --help help for accept-invite`

## `id team add-member`

### `id team add-member`

Add a member directly to a team (controller signs certificate)

Flags:
- `-h, --help help for add-member`
- `--member string Member address (e.g. acme.com/alice)`
- `--namespace string Namespace domain`
- `--team string Team name`

## `id team create`

### `id team create`

Create a team at awid

Flags:
- `--display-name string Team display name`
- `-h, --help help for create`
- `--name string Team name`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`

## `id team invite`

### `id team invite`

Generate an invite token for a team

Flags:
- `--ephemeral Create ephemeral member invite`
- `-h, --help help for invite`
- `--namespace string Namespace domain`
- `--team string Team name`

## `id team leave`

### `id team leave`

Remove a team membership from this workspace

Flags:
- `-h, --help help for leave`

## `id team list`

### `id team list`

List team memberships for this workspace

Flags:
- `-h, --help help for list`

## `id team remove-member`

### `id team remove-member`

Remove a member from a team (revoke certificate)

Flags:
- `-h, --help help for remove-member`
- `--member string Member address (e.g. acme.com/alice)`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

## `id team switch`

### `id team switch`

Switch the active team for this workspace

Flags:
- `-h, --help help for switch`

## `id verify`

### `id verify`

Verify the full audit log for a did:aw

Flags:
- `-h, --help help for verify`

## `mcp-config`

### `mcp-config`

Output MCP server configuration for the current identity

Flags:
- `--channel Output stdio channel config instead of HTTP MCP config`
- `-h, --help help for mcp-config`

## `whoami`

### `whoami`

Show the current identity

Flags:
- `-h, --help help for whoami`

## `chat`

### `chat`

Real-time chat

Subcommands:
- `extend-wait` Ask the other party to wait longer
- `history` Show chat history with alias
- `listen` Wait for a message without sending
- `open` Open a chat session
- `pending` List pending chat sessions
- `send-and-leave` Send a message and leave the conversation
- `send-and-wait` Send a message and wait for a reply
- `show-pending` Show pending messages for alias

Flags:
- `-h, --help help for chat`

## `chat extend-wait`

### `chat extend-wait`

Ask the other party to wait longer

Flags:
- `-h, --help help for extend-wait`

## `chat history`

### `chat history`

Show chat history with alias

Flags:
- `-h, --help help for history`

## `chat listen`

### `chat listen`

Wait for a message without sending

Flags:
- `-h, --help help for listen`
- `--wait int Seconds to wait for a message (0 = no wait) (default 120)`

## `chat open`

### `chat open`

Open a chat session

Flags:
- `-h, --help help for open`

## `chat pending`

### `chat pending`

List pending chat sessions

Flags:
- `-h, --help help for pending`

## `chat send-and-leave`

### `chat send-and-leave`

Send a message and leave the conversation

Flags:
- `-h, --help help for send-and-leave`

## `chat send-and-wait`

### `chat send-and-wait`

Send a message and wait for a reply

Flags:
- `-h, --help help for send-and-wait`
- `--start-conversation Start conversation (5min default wait)`
- `--wait int Seconds to wait for reply (default 120)`

## `chat show-pending`

### `chat show-pending`

Show pending messages for alias

Flags:
- `-h, --help help for show-pending`

## `contacts`

### `contacts`

Manage contacts

Subcommands:
- `add` Add a contact
- `list` List contacts
- `remove` Remove a contact by address

Flags:
- `-h, --help help for contacts`

## `contacts add`

### `contacts add`

Add a contact

Flags:
- `-h, --help help for add`
- `--label string Label for the contact`

## `contacts list`

### `contacts list`

List contacts

Flags:
- `-h, --help help for list`

## `contacts remove`

### `contacts remove`

Remove a contact by address

Flags:
- `-h, --help help for remove`

## `control`

### `control`

Send control signals to agents

Subcommands:
- `interrupt` Send interrupt signal to an agent
- `pause` Send pause signal to an agent
- `resume` Send resume signal to an agent

Flags:
- `-h, --help help for control`

## `control interrupt`

### `control interrupt`

Send interrupt signal to an agent

Flags:
- `--agent string Agent alias to send signal to`
- `-h, --help help for interrupt`

## `control pause`

### `control pause`

Send pause signal to an agent

Flags:
- `--agent string Agent alias to send signal to`
- `-h, --help help for pause`

## `control resume`

### `control resume`

Send resume signal to an agent

Flags:
- `--agent string Agent alias to send signal to`
- `-h, --help help for resume`

## `directory`

### `directory`

Search or look up persistent identities in the network directory

Flags:
- `--capability string Filter by capability`
- `--domain string Filter by domain`
- `-h, --help help for directory`
- `--limit int Max results (default 100)`
- `--query string Search handle/description`

## `events`

### `events`

Event stream operations

Subcommands:
- `stream` Listen to real-time agent events via SSE

Flags:
- `-h, --help help for events`

## `events stream`

### `events stream`

Listen to real-time agent events via SSE

Flags:
- `-h, --help help for stream`
- `--timeout int Stop after N seconds (0 = indefinite)`

## `heartbeat`

### `heartbeat`

Send an explicit presence heartbeat

Flags:
- `-h, --help help for heartbeat`

## `log`

### `log`

Show local communication log

Flags:
- `--channel string Filter by channel (mail, chat, dm)`
- `--from string Filter by sender (substring match)`
- `-h, --help help for log`
- `--limit int Max entries to show (default 20)`

## `mail`

### `mail`

Agent messaging

Subcommands:
- `inbox` List inbox messages (unread only by default)
- `send` Send a message to another agent

Flags:
- `-h, --help help for mail`

## `mail inbox`

### `mail inbox`

List inbox messages (unread only by default)

Flags:
- `-h, --help help for inbox`
- `--limit int Max messages (default 50)`
- `--show-all Show all messages including already-read`

## `mail send`

### `mail send`

Send a message to another agent

Flags:
- `--body string Body`
- `-h, --help help for send`
- `--priority string Priority: low|normal|high|urgent (default "normal")`
- `--subject string Subject`
- `--to string Recipient address`

## `instructions`

### `instructions`

Read and manage shared team instructions

Subcommands:
- `activate` Activate an existing shared team instructions version
- `history` List shared team instructions history
- `reset` Reset shared team instructions to the server default
- `set` Create and activate a new shared team instructions version
- `show` Show shared team instructions

Flags:
- `-h, --help help for instructions`

## `instructions activate`

### `instructions activate`

Activate an existing shared team instructions version

Flags:
- `-h, --help help for activate`

## `instructions history`

### `instructions history`

List shared team instructions history

Flags:
- `-h, --help help for history`
- `--limit int Max instruction versions (default 20)`

## `instructions reset`

### `instructions reset`

Reset shared team instructions to the server default

Flags:
- `-h, --help help for reset`

## `instructions set`

### `instructions set`

Create and activate a new shared team instructions version

Flags:
- `--body string Instructions markdown body`
- `--body-file string Read instructions markdown from file ('-' for stdin)`
- `-h, --help help for set`

## `instructions show`

### `instructions show`

Show shared team instructions

Flags:
- `-h, --help help for show`

## `lock`

### `lock`

Distributed locks

Subcommands:
- `acquire` Acquire a lock
- `list` List active locks
- `release` Release a lock
- `renew` Renew a lock
- `revoke` Revoke locks

Flags:
- `-h, --help help for lock`

## `lock acquire`

### `lock acquire`

Acquire a lock

Flags:
- `-h, --help help for acquire`
- `--resource-key string Opaque resource key`
- `--ttl-seconds int TTL seconds (default 3600)`

## `lock list`

### `lock list`

List active locks

Flags:
- `-h, --help help for list`
- `--mine Show only locks held by the current workspace alias`
- `--prefix string Prefix filter`

## `lock release`

### `lock release`

Release a lock

Flags:
- `-h, --help help for release`
- `--resource-key string Opaque resource key`

## `lock renew`

### `lock renew`

Renew a lock

Flags:
- `-h, --help help for renew`
- `--resource-key string Opaque resource key`
- `--ttl-seconds int TTL seconds (default 3600)`

## `lock revoke`

### `lock revoke`

Revoke locks

Flags:
- `-h, --help help for revoke`
- `--prefix string Optional prefix filter`

## `notify`

### `notify`

Check for pending chat notifications.

Silent if no pending chats; outputs JSON with additionalContext if there are
messages waiting. Designed for Claude Code PostToolUse hooks so notifications
are surfaced to the agent automatically.

Hook configuration in .claude/settings.json (set up via aw init --setup-hooks):
  "hooks": {
    "PostToolUse": [{
      "matcher": ".*",
      "hooks": [{"type": "command", "command": "aw notify"}]
    }]
  }

Flags:
- `-h, --help help for notify`

## `role-name`

### `role-name`

Manage the current workspace role name

Subcommands:
- `set` Set the current workspace role name

Flags:
- `-h, --help help for role-name`

## `role-name set`

### `role-name set`

Set the current workspace role name

Flags:
- `-h, --help help for set`

## `roles`

### `roles`

Read and manage team roles bundles and role definitions

Subcommands:
- `activate` Activate an existing team roles bundle version
- `deactivate` Deactivate team roles by replacing the active bundle with an empty bundle
- `history` List team roles history
- `list` List roles defined in the active team roles bundle
- `reset` Reset team roles to the server default bundle
- `set` Create and activate a new team roles bundle version
- `show` Show role guidance from the active team roles bundle

Flags:
- `-h, --help help for roles`

## `roles activate`

### `roles activate`

Activate an existing team roles bundle version

Flags:
- `-h, --help help for activate`

## `roles deactivate`

### `roles deactivate`

Deactivate team roles by replacing the active bundle with an empty bundle

Flags:
- `-h, --help help for deactivate`

## `roles history`

### `roles history`

List team roles history

Flags:
- `-h, --help help for history`
- `--limit int Max role bundle versions (default 20)`

## `roles list`

### `roles list`

List roles defined in the active team roles bundle

Flags:
- `-h, --help help for list`

## `roles reset`

### `roles reset`

Reset team roles to the server default bundle

Flags:
- `-h, --help help for reset`

## `roles set`

### `roles set`

Create and activate a new team roles bundle version

Flags:
- `--bundle-file string Read team roles bundle JSON from file ('-' for stdin)`
- `--bundle-json string Team roles bundle JSON`
- `-h, --help help for set`

## `roles show`

### `roles show`

Show role guidance from the active team roles bundle

Flags:
- `--all-roles Include all role playbooks instead of only the selected role`
- `-h, --help help for show`
- `--role string Compatibility alias for --role-name`
- `--role-name string Preview a specific role name`

## `run`

### `run`

Start the requested AI coding agent in this directory.

In a TTY, if this directory is not initialized yet, aw run can guide you
through supported onboarding before starting the provider. The explicit
bootstrap path is aw init, backed by guided onboarding, hosted signup,
or a team certificate already present in .aw/.

Current implementation includes:
  - repeated provider invocations (currently Claude and Codex)
  - provider session continuity when --continue is requested
  - /stop, /wait, /autofeed on|off, /quit, and prompt override controls
  - aw event-stream wakeups for mail, chat, and optional work events
  - optional background services declared in aw run config

This aw-first command intentionally excludes bead-specific dispatch.

Flags:
- `--allowed-tools string Provider-specific allowed tools string`
- `--autofeed-work Wake for work-related events in addition to incoming mail/chat`
- `--base-prompt string Override the configured base mission prompt for this run`
- `--comms-prompt-suffix string Override the configured comms cycle prompt suffix for this run`
- `--continue Continue the most recent provider session across runs`
- `--dir string Working directory for the agent process`
- `-h, --help help for run`
- `--idle-wait int Reserved idle-wait setting for future dispatch modes (default 30)`
- `--init Prompt for ~/.config/aw/run.json values and write them`
- `--max-runs int Stop after N runs (0 means infinite)`
- `--model string Provider-specific model override`
- `--prompt string Initial prompt for the first provider run`
- `--provider-pty Run the provider subprocess inside a pseudo-terminal instead of plain pipes when interactive controls are available`
- `--trip-on-danger Remove provider bypass flags and use native provider safety checks`
- `--wait int Idle seconds per wake-stream wait cycle (default 20)`
- `--work-prompt-suffix string Override the configured work cycle prompt suffix for this run`

## `task`

### `task`

Manage tasks

Subcommands:
- `close` Close one or more tasks
- `comment` Manage task comments
- `create` Create a new task
- `delete` Delete a task
- `dep` Manage task dependencies
- `list` List tasks
- `reopen` Reopen a closed task
- `show` Show task details
- `stats` Show task statistics
- `update` Update a task

Flags:
- `-h, --help help for task`

## `task close`

### `task close`

Close one or more tasks

Flags:
- `-h, --help help for close`
- `--reason string Reason for closing (replaces notes)`

## `task comment`

### `task comment`

Manage task comments

Subcommands:
- `add` Add a comment to a task
- `list` List comments on a task

Flags:
- `-h, --help help for comment`

## `task comment add`

### `task comment add`

Add a comment to a task

Flags:
- `-h, --help help for add`

## `task comment list`

### `task comment list`

List comments on a task

Flags:
- `-h, --help help for list`

## `task create`

### `task create`

Create a new task

Flags:
- `--assignee string Assignee agent alias`
- `--description string Task description`
- `-h, --help help for create`
- `--labels string Comma-separated labels`
- `--notes string Task notes`
- `--parent string Parent task ref`
- `--priority string Priority 0-4 (accepts P0-P4)`
- `--title string Task title (required)`
- `--type string Task type (task, bug, feature, epic)`

## `task delete`

### `task delete`

Delete a task

Flags:
- `-h, --help help for delete`

## `task dep`

### `task dep`

Manage task dependencies

Subcommands:
- `add` Add a dependency
- `list` List dependencies for a task
- `remove` Remove a dependency

Flags:
- `-h, --help help for dep`

## `task dep add`

### `task dep add`

Add a dependency

Flags:
- `-h, --help help for add`

## `task dep list`

### `task dep list`

List dependencies for a task

Flags:
- `-h, --help help for list`

## `task dep remove`

### `task dep remove`

Remove a dependency

Flags:
- `-h, --help help for remove`

## `task list`

### `task list`

List tasks

Flags:
- `--assignee string Filter by assignee agent alias`
- `-h, --help help for list`
- `--labels string Filter by labels (comma-separated)`
- `--priority string Filter by priority 0-4 (accepts P0-P4)`
- `--status string Filter by status (open, in_progress, closed, blocked)`
- `--type string Filter by type (task, bug, feature, epic)`

## `task reopen`

### `task reopen`

Reopen a closed task

Flags:
- `-h, --help help for reopen`

## `task show`

### `task show`

Show task details

Flags:
- `-h, --help help for show`

## `task stats`

### `task stats`

Show task statistics

Flags:
- `-h, --help help for stats`

## `task update`

### `task update`

Update a task

Flags:
- `--assignee string Assignee agent alias`
- `--description string Description`
- `-h, --help help for update`
- `--labels string Comma-separated labels`
- `--notes string Notes`
- `--priority string Priority 0-4 (accepts P0-P4)`
- `--status string Status (open, in_progress, closed)`
- `--title string Title`
- `--type string Type (task, bug, feature, epic)`

## `work`

### `work`

Discover coordination-aware work

Subcommands:
- `active` List active in-progress work across the team
- `blocked` List blocked tasks
- `ready` List ready tasks that are not already claimed by other workspaces

Flags:
- `-h, --help help for work`

## `work active`

### `work active`

List active in-progress work across the team

Flags:
- `-h, --help help for active`

## `work blocked`

### `work blocked`

List blocked tasks

Flags:
- `-h, --help help for blocked`

## `work ready`

### `work ready`

List ready tasks that are not already claimed by other workspaces

Flags:
- `-h, --help help for ready`

## `completion`

### `completion`

Generate the autocompletion script for aw for the specified shell.
See each sub-command's help for details on how to use the generated script.

Subcommands:
- `bash` Generate the autocompletion script for bash
- `fish` Generate the autocompletion script for fish
- `powershell` Generate the autocompletion script for powershell
- `zsh` Generate the autocompletion script for zsh

Flags:
- `-h, --help help for completion`

## `completion bash`

### `completion bash`

Generate the autocompletion script for the bash shell.

This script depends on the 'bash-completion' package.
If it is not installed already, you can install it via your OS's package manager.

To load completions in your current shell session:

	source <(aw completion bash)

To load completions for every new session, execute once:

#### Linux:

	aw completion bash > /etc/bash_completion.d/aw

#### macOS:

	aw completion bash > $(brew --prefix)/etc/bash_completion.d/aw

You will need to start a new shell for this setup to take effect.

Flags:
- `-h, --help help for bash`
- `--no-descriptions disable completion descriptions`

## `completion fish`

### `completion fish`

Generate the autocompletion script for the fish shell.

To load completions in your current shell session:

	aw completion fish | source

To load completions for every new session, execute once:

	aw completion fish > ~/.config/fish/completions/aw.fish

You will need to start a new shell for this setup to take effect.

Flags:
- `-h, --help help for fish`
- `--no-descriptions disable completion descriptions`

## `completion powershell`

### `completion powershell`

Generate the autocompletion script for powershell.

To load completions in your current shell session:

	aw completion powershell | Out-String | Invoke-Expression

To load completions for every new session, add the output of the above command
to your powershell profile.

Flags:
- `-h, --help help for powershell`
- `--no-descriptions disable completion descriptions`

## `completion zsh`

### `completion zsh`

Generate the autocompletion script for the zsh shell.

If shell completion is not already enabled in your environment you will need
to enable it.  You can execute the following once:

	echo "autoload -U compinit; compinit" >> ~/.zshrc

To load completions in your current shell session:

	source <(aw completion zsh)

To load completions for every new session, execute once:

#### Linux:

	aw completion zsh > "${fpath[1]}/_aw"

#### macOS:

	aw completion zsh > $(brew --prefix)/share/zsh/site-functions/_aw

You will need to start a new shell for this setup to take effect.

Flags:
- `-h, --help help for zsh`
- `--no-descriptions disable completion descriptions`

## `help`

### `help`

Help provides help for any command in the application.
Simply type aw help [path to command] for full details.

Flags:
- `-h, --help help for help`

## `upgrade`

### `upgrade`

Upgrade aw to the latest version

Flags:
- `-h, --help help for upgrade`

## `version`

### `version`

Print version information

Flags:
- `-h, --help help for version`
