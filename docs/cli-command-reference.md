# CLI Command Reference

This reference is derived from the live Cobra help tree generated from the
`aw` binary under [`cli/go/cmd/aw/`](../cli/go/cmd/aw).

## Command Families

| Family | Commands |
| --- | --- |
| Workspace setup | `init`, `project`, `reset`, `spawn`, `workspace` |
| Identity | `claim-human`, `identities`, `identity`, `mcp-config`, `whoami` |
| Messaging and network | `chat`, `contacts`, `control`, `directory`, `events`, `heartbeat`, `log`, `mail` |
| Coordination and runtime | `instructions`, `lock`, `notify`, `role-name`, `roles`, `run`, `task`, `work` |
| Utility | `completion`, `help`, `upgrade`, `version` |

## Global flags

- `--debug`: Log background errors to stderr.
- `--json`: Output as JSON when the command supports it.
- `--server-name string`: Override the server host or name for this command.

## Notes

- Many commands also read saved config, `.aw/context`, `AWEB_URL`, and
  `AWEB_API_KEY`.
- `aw run <provider>` is the primary human entrypoint.
- `aw project create`, `aw init`, and `aw spawn accept-invite` are the
  explicit bootstrap primitives.
- The sections below are exhaustive for the current command tree. Flags are
  copied from the live help output rather than maintained by hand.

## Common Environment Variables

| Variable | Purpose |
| --- | --- |
| `AWEB_URL` | Override the base server URL |
| `AWEB_API_KEY` | Override the API key |
| `AW_DEBUG` | Enable debug logging |

## Resolution Order

The CLI resolves context in this order:

1. explicit flags such as `--server-name`
2. environment variables
3. local `.aw/workspace.yaml`
4. local `.aw/identity.yaml` for permanent identity fields
5. local `.aw/context`

## `init`

### `init`

Use this when you already have a project-scoped API key. Human users normally start with aw run <provider>; aw init is the explicit existing-project bootstrap primitive.

Flags:
- `--agent-type string     Runtime type (default: AWEB_AGENT_TYPE or agent)`
- `--alias string          Ephemeral identity routing alias (optional; default: server-suggested)`
- `-h, --help                  help for init`
- `--human-name string     Human name (default: AWEB_HUMAN or $USER)`
- `--inject-docs           Inject aw coordination instructions into CLAUDE.md and AGENTS.md`
- `--name string           Permanent identity name (required with --permanent unless .aw/identity.yaml already exists)`
- `--permanent             Create a durable self-custodial identity instead of the default ephemeral identity`
- `--print-exports         Print shell export lines after JSON output`
- `--reachability string   Permanent address reachability (private|org-visible|contacts-only|public)`
- `--role string           Compatibility alias for --role-name`
- `--role-name string      Workspace role name (must match a role in the active project roles bundle)`
- `--server string         Base URL for the aweb server (alias for --server-url)`
- `--server-url string     Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).`
- `--setup-hooks           Set up Claude Code PostToolUse hook for aw notify`
- `--write-context         Write/update .aw/context in the current directory (non-secret pointer) (default true)`

## `project`

### `project`

Subcommands:
- `create      Create a project and initialize this directory as its first agent`
- `namespace   Manage project namespaces`

Flags:
- `-h, --help   help for project`

### `project create`

Human users normally start with aw run <provider>; aw project create is the explicit create-project bootstrap primitive.

Flags:
- `--agent-type string       Runtime type (default: AWEB_AGENT_TYPE or agent)`
- `--alias string            Ephemeral identity routing alias (optional; default: server-suggested)`
- `-h, --help                    help for create`
- `--human-name string       Human name (default: AWEB_HUMAN or $USER)`
- `--inject-docs             Inject aw coordination instructions into CLAUDE.md and AGENTS.md`
- `--name string             Permanent identity name (required with --permanent unless .aw/identity.yaml already exists)`
- `--namespace string        Authoritative namespace slug when it differs from the project slug (default: project slug)`
- `--namespace-slug string   Authoritative namespace slug (alias for --namespace)`
- `--permanent               Create a durable self-custodial identity instead of the default ephemeral identity`
- `--print-exports           Print shell export lines after JSON output`
- `--project string          Project slug (default: AWEB_PROJECT_SLUG, AWEB_PROJECT, or prompt in TTY)`
- `--reachability string     Permanent address reachability (private|org-visible|contacts-only|public)`
- `--role string             Compatibility alias for --role-name`
- `--role-name string        Workspace role name (must match a role in the active project roles bundle)`
- `--server string           Base URL for the aweb server (alias for --server-url)`
- `--server-url string       Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).`
- `--setup-hooks             Set up Claude Code PostToolUse hook for aw notify`
- `--write-context           Write/update .aw/context in the current directory (non-secret pointer) (default true)`

### `project namespace`

Subcommands:
- `add         Add a BYOD namespace to the current project`
- `delete      Delete a namespace from the current project`
- `list        List namespaces attached to the current project`
- `verify      Verify DNS and register a BYOD namespace for the current project`

Flags:
- `-h, --help   help for namespace`

### `project namespace add`

Flags:
- `-h, --help   help for add`

### `project namespace delete`

Flags:
- `--force   Skip confirmation prompt`
- `-h, --help    help for delete`

### `project namespace list`

Flags:
- `-h, --help   help for list`

### `project namespace verify`

Flags:
- `-h, --help   help for verify`

## `reset`

### `reset`

Flags:
- `-h, --help   help for reset`

## `spawn`

### `spawn`

Subcommands:
- `accept-invite Join an existing project in this directory from a spawn invite`
- `create-invite Create a spawn invite for another workspace`
- `list-invites  List active spawn invites`
- `revoke-invite Revoke a spawn invite by token prefix`

Flags:
- `-h, --help   help for spawn`

### `spawn accept-invite`

In a TTY, aw will prompt for any missing alias, name, or role information before initializing the workspace. Identities are ephemeral by default; pass --permanent to create a durable self-custodial identity instead.

Flags:
- `--agent-type string     Runtime type (default: AWEB_AGENT_TYPE or agent)`
- `--alias string          Ephemeral identity routing alias (optional; default: invite or server-suggested)`
- `-h, --help                  help for accept-invite`
- `--human-name string     Human name (default: AWEB_HUMAN or $USER)`
- `--inject-docs           Inject aw coordination instructions into CLAUDE.md and AGENTS.md`
- `--name string           Permanent identity name (required with --permanent unless .aw/identity.yaml already exists)`
- `--permanent             Create a durable self-custodial identity instead of the default ephemeral identity`
- `--print-exports         Print shell export lines after JSON output`
- `--reachability string   Permanent address reachability (private|org-visible|contacts-only|public)`
- `--role string           Compatibility alias for --role-name`
- `--role-name string      Workspace role name (must match a role in the active project roles bundle)`
- `--server string         Base URL for the aweb server (alias for --server-url)`
- `--server-url string     Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).`
- `--setup-hooks           Set up Claude Code PostToolUse hook for aw notify`
- `--write-context         Write/update .aw/context in the current directory (non-secret pointer) (default true)`

### `spawn create-invite`

Flags:
- `--access string    Access mode: project|owner|contacts|open (default "open")`
- `--alias string     Pre-assign a routing alias hint for the child workspace`
- `--expires string   Invite lifetime (examples: 24h, 7d) (default "24h")`
- `-h, --help             help for create-invite`
- `--uses int         Maximum number of invite uses (default 1)`

### `spawn list-invites`

Flags:
- `-h, --help   help for list-invites`

### `spawn revoke-invite`

Flags:
- `-h, --help   help for revoke-invite`

## `use`

### `use`

Flags:
- `-h, --help   help for use`

## `workspace`

### `workspace`

Subcommands:
- `add-worktree Create a sibling git worktree and initialize a new coordination workspace in it`
- `status       Show coordination status for the current workspace/identity and team`

Flags:
- `-h, --help   help for workspace`

### `workspace add-worktree`

Flags:
- `--alias string   Override the default alias`
- `-h, --help           help for add-worktree`

### `workspace status`

Flags:
- `-h, --help        help for status`
- `--limit int   Maximum team workspaces to show (default 15)`

## `claim-human`

### `claim-human`

Flags:
- `--email string   Email address for human account claim`
- `-h, --help           help for claim-human`

## `identities`

### `identities`

Flags:
- `-h, --help   help for identities`

## `identity`

### `identity`

Subcommands:
- `create       Create a standalone permanent identity with a DNS-backed address in .aw/`
- `access-mode  Get or set identity access mode`
- `delete       Delete the current ephemeral identity`
- `log          Show an identity log`
- `reachability Get or set permanent address reachability`
- `register     Register the current permanent identity at awid.ai`
- `resolve      Resolve a did:aw to its current did:key`
- `show         Show the current identity and registry status`
- `namespace    Inspect a namespace and its registered addresses`
- `rotate-key   Rotate the identity signing key`
- `verify       Verify the full audit log for a did:aw`

Flags:
- `-h, --help   help for identity`

### `identity create`

Flags:
- `-h, --help      help for create`
- `--name string   Permanent identity name`

### `identity access-mode`

Flags:
- `-h, --help   help for access-mode`

### `identity delete`

Flags:
- `--confirm   Required to delete the current ephemeral identity`
- `-h, --help      help for delete`

### `identity log`

Flags:
- `-h, --help   help for log`

### `identity namespace`

Flags:
- `-h, --help   help for namespace`

### `identity register`

Flags:
- `-h, --help   help for register`

### `identity resolve`

Flags:
- `-h, --help   help for resolve`

### `identity show`

Flags:
- `-h, --help   help for show`

### `identity reachability`

Flags:
- `-h, --help   help for reachability`

### `identity rotate-key`

Flags:
- `-h, --help           help for rotate-key`
- `--self-custody   Graduate from custodial to self-custody`

### `identity verify`

Flags:
- `-h, --help   help for verify`

## `mcp-config`

### `mcp-config`

Flags:
- `--all    Output config for all accounts`
- `-h, --help   help for mcp-config`

## `whoami`

### `whoami`

Flags:
- `-h, --help   help for whoami`

## `chat`

### `chat`

Subcommands:
- `extend-wait    Ask the other party to wait longer`
- `history        Show chat history with alias`
- `listen         Wait for a message without sending`
- `open           Open a chat session`
- `pending        List pending chat sessions`
- `send-and-leave Send a message and leave the conversation`
- `send-and-wait  Send a message and wait for a reply`
- `show-pending   Show pending messages for alias`

Flags:
- `-h, --help   help for chat`

### `chat extend-wait`

Flags:
- `-h, --help   help for extend-wait`

### `chat history`

Flags:
- `-h, --help   help for history`

### `chat listen`

Flags:
- `-h, --help       help for listen`
- `--wait int   Seconds to wait for a message (0 = no wait) (default 120)`

### `chat open`

Flags:
- `-h, --help   help for open`

### `chat pending`

Flags:
- `-h, --help   help for pending`

### `chat send-and-leave`

Flags:
- `-h, --help   help for send-and-leave`

### `chat send-and-wait`

Flags:
- `-h, --help                 help for send-and-wait`
- `--start-conversation   Start conversation (5min default wait)`
- `--wait int             Seconds to wait for reply (default 120)`

### `chat show-pending`

Flags:
- `-h, --help   help for show-pending`

## `contacts`

### `contacts`

Subcommands:
- `add         Add a contact`
- `list        List contacts`
- `remove      Remove a contact by address`

Flags:
- `-h, --help   help for contacts`

### `contacts add`

Flags:
- `-h, --help           help for add`
- `--label string   Label for the contact`

### `contacts list`

Flags:
- `-h, --help   help for list`

### `contacts remove`

Flags:
- `-h, --help   help for remove`

## `control`

### `control`

Subcommands:
- `interrupt   Send interrupt signal to an agent`
- `pause       Send pause signal to an agent`
- `resume      Send resume signal to an agent`

Flags:
- `-h, --help   help for control`

### `control interrupt`

Flags:
- `--agent string   Agent alias to send signal to`
- `-h, --help           help for interrupt`

### `control pause`

Flags:
- `--agent string   Agent alias to send signal to`
- `-h, --help           help for pause`

### `control resume`

Flags:
- `--agent string   Agent alias to send signal to`
- `-h, --help           help for resume`

## `directory`

### `directory`

Flags:
- `--capability string   Filter by capability`
- `-h, --help                help for directory`
- `--limit int           Max results (default 100)`
- `--namespace string    Filter by namespace slug`
- `--query string        Search handle/description`

## `events`

### `events`

Subcommands:
- `stream      Listen to real-time agent events via SSE`

Flags:
- `-h, --help   help for events`

### `events stream`

Flags:
- `-h, --help          help for stream`
- `--timeout int   Stop after N seconds (0 = indefinite)`

## `heartbeat`

### `heartbeat`

Flags:
- `-h, --help   help for heartbeat`

## `log`

### `log`

Flags:
- `--channel string   Filter by channel (mail, chat, dm)`
- `--from string      Filter by sender (substring match)`
- `-h, --help             help for log`
- `--limit int        Max entries to show (default 20)`

## `mail`

### `mail`

Subcommands:
- `inbox       List inbox messages (unread only by default)`
- `send        Send a message to another agent`

Flags:
- `-h, --help   help for mail`

### `mail inbox`

Flags:
- `-h, --help        help for inbox`
- `--limit int   Max messages (default 50)`
- `--show-all    Show all messages including already-read`

### `mail send`

Flags:
- `--body string       Body`
- `-h, --help              help for send`
- `--priority string   Priority: low|normal|high|urgent (default "normal")`
- `--subject string    Subject`
- `--to string         Recipient address`

## `lock`

### `lock`

Subcommands:
- `acquire     Acquire a lock`
- `list        List active locks`
- `release     Release a lock`
- `renew       Renew a lock`
- `revoke      Revoke locks`

Flags:
- `-h, --help   help for lock`

### `lock acquire`

Flags:
- `-h, --help                  help for acquire`
- `--resource-key string   Opaque resource key`
- `--ttl-seconds int       TTL seconds (default 3600)`

### `lock list`

Flags:
- `-h, --help            help for list`
- `--mine            Show only locks held by the current workspace alias`
- `--prefix string   Prefix filter`

### `lock release`

Flags:
- `-h, --help                  help for release`
- `--resource-key string   Opaque resource key`

### `lock renew`

Flags:
- `-h, --help                  help for renew`
- `--resource-key string   Opaque resource key`
- `--ttl-seconds int       TTL seconds (default 3600)`

### `lock revoke`

Flags:
- `-h, --help            help for revoke`
- `--prefix string   Optional prefix filter`

## `notify`

### `notify`

Silent if no pending chats; outputs JSON with additionalContext if there are messages waiting. Designed for Claude Code PostToolUse hooks so notifications are surfaced to the agent automatically.  Hook configuration in .claude/settings.json (set up via aw init --setup-hooks): "hooks": { "PostToolUse": [{ "matcher": ".*", "hooks": [{"type": "command", "command": "aw notify"}] }] }

Flags:
- `-h, --help   help for notify`

## `instructions`

### `instructions`

Subcommands:
- `activate    Activate an existing shared project instructions version`
- `history     List shared project instructions history`
- `reset       Reset shared project instructions to the server default`
- `set         Create and activate a new shared project instructions version`
- `show        Show shared project instructions`

Flags:
- `-h, --help   help for instructions`

### `instructions activate`

Flags:
- `-h, --help   help for activate`

### `instructions history`

Flags:
- `-h, --help        help for history`
- `--limit int   Max instruction versions (default 20)`

### `instructions reset`

Flags:
- `-h, --help   help for reset`

### `instructions set`

Flags:
- `--body string        Instructions markdown body`
- `--body-file string   Read instructions markdown from file ('-' for stdin)`
- `-h, --help               help for set`

### `instructions show`

Flags:
- `-h, --help   help for show`

## `role-name`

### `role-name`

Subcommands:
- `set         Set the current workspace role name`

Flags:
- `-h, --help   help for role-name`

### `role-name set`

Flags:
- `-h, --help   help for set`

## `roles`

### `roles`

Subcommands:
- `activate    Activate an existing project roles bundle version`
- `deactivate  Deactivate project roles by replacing the active bundle with an empty bundle`
- `history     List project roles history`
- `list        List roles defined in the active project roles bundle`
- `reset       Reset project roles to the server default bundle`
- `set         Create and activate a new project roles bundle version`
- `show        Show role guidance from the active project roles bundle`

Flags:
- `-h, --help   help for roles`

### `roles activate`

Flags:
- `-h, --help   help for activate`

### `roles deactivate`

Flags:
- `-h, --help   help for deactivate`

### `roles history`

Flags:
- `-h, --help        help for history`
- `--limit int   Max role bundle versions (default 20)`

### `roles list`

Flags:
- `-h, --help   help for list`

### `roles reset`

Flags:
- `-h, --help   help for reset`

### `roles set`

Flags:
- `--bundle-file string   Read project roles bundle JSON from file ('-' for stdin)`
- `--bundle-json string   Project roles bundle JSON`
- `-h, --help                 help for set`

### `roles show`

Flags:
- `--all-roles          Include all role playbooks instead of only the selected role`
- `-h, --help               help for show`
- `--role string        Compatibility alias for --role-name`
- `--role-name string   Preview a specific role name`

## `run`

### `run`

In a TTY, if this directory is not initialized yet, aw run can guide you through new-project creation or existing-project init before starting the provider. The explicit bootstrap commands remain available for scripts and expert use: aw project create, aw init, and aw spawn accept-invite. Current implementation includes repeated provider invocations (currently Claude and Codex), provider session continuity when --continue is requested, `/stop`, `/wait`, `/resume`, `/autofeed on|off`, `/quit`, and prompt override controls, aw event-stream wakeups for mail, chat, and optional work events, and optional background services declared in aw run config. This aw-first command intentionally excludes bead-specific dispatch.

Flags:
- `--allowed-tools string         Provider-specific allowed tools string`
- `--autofeed-work                Wake for work-related events in addition to incoming mail/chat`
- `--base-prompt string           Override the configured base mission prompt for this run`
- `--comms-prompt-suffix string   Override the configured comms cycle prompt suffix for this run`
- `--continue                     Continue the most recent provider session across runs`
- `--dir string                   Working directory for the agent process`
- `-h, --help                         help for run`
- `--idle-wait int                Reserved idle-wait setting for future dispatch modes (default 30)`
- `--init                         Prompt for ~/.config/aw/run.json values and write them`
- `--max-runs int                 Stop after N runs (0 means infinite)`
- `--model string                 Provider-specific model override`
- `--prompt string                Initial prompt for the first provider run`
- `--provider-pty                 Run the provider subprocess inside a pseudo-terminal instead of plain pipes when interactive controls are available`
- `--trip-on-danger               Remove provider bypass flags and use native provider safety checks`
- `--wait int                     Idle seconds per wake-stream wait cycle (default 20)`
- `--work-prompt-suffix string    Override the configured work cycle prompt suffix for this run`

## `task`

### `task`

Subcommands:
- `close       Close one or more tasks`
- `comment     Manage task comments`
- `create      Create a new task`
- `delete      Delete a task`
- `dep         Manage task dependencies`
- `list        List tasks`
- `reopen      Reopen a closed task`
- `show        Show task details`
- `stats       Show task statistics`
- `update      Update a task`

Flags:
- `-h, --help   help for task`

### `task close`

Flags:
- `-h, --help            help for close`
- `--reason string   Reason for closing (replaces notes)`

### `task comment`

Subcommands:
- `add         Add a comment to a task`
- `list        List comments on a task`

Flags:
- `-h, --help   help for comment`

### `task create`

Flags:
- `--assignee string      Assignee agent alias`
- `--description string   Task description`
- `-h, --help                 help for create`
- `--labels string        Comma-separated labels`
- `--notes string         Task notes`
- `--parent string        Parent task ref`
- `--priority string      Priority 0-4 (accepts P0-P4)`
- `--title string         Task title (required)`
- `--type string          Task type (task, bug, feature, epic)`

### `task delete`

Flags:
- `-h, --help   help for delete`

### `task dep`

Subcommands:
- `add         Add a dependency`
- `list        List dependencies for a task`
- `remove      Remove a dependency`

Flags:
- `-h, --help   help for dep`

### `task list`

Flags:
- `--assignee string   Filter by assignee agent alias`
- `-h, --help              help for list`
- `--labels string     Filter by labels (comma-separated)`
- `--priority string   Filter by priority 0-4 (accepts P0-P4)`
- `--status string     Filter by status (open, in_progress, closed, blocked)`
- `--type string       Filter by type (task, bug, feature, epic)`

### `task reopen`

Flags:
- `-h, --help   help for reopen`

### `task show`

Flags:
- `-h, --help   help for show`

### `task stats`

Flags:
- `-h, --help   help for stats`

### `task update`

Flags:
- `--assignee string      Assignee agent alias`
- `--description string   Description`
- `-h, --help                 help for update`
- `--labels string        Comma-separated labels`
- `--notes string         Notes`
- `--priority string      Priority 0-4 (accepts P0-P4)`
- `--status string        Status (open, in_progress, closed)`
- `--title string         Title`
- `--type string          Type (task, bug, feature, epic)`

### `task comment add`

Flags:
- `-h, --help   help for add`

### `task comment list`

Flags:
- `-h, --help   help for list`

### `task dep add`

Flags:
- `-h, --help   help for add`

### `task dep list`

Flags:
- `-h, --help   help for list`

### `task dep remove`

Flags:
- `-h, --help   help for remove`

## `work`

### `work`

Subcommands:
- `active      List active in-progress work across the project`
- `blocked     List blocked tasks`
- `ready       List ready tasks that are not already claimed by other workspaces`

Flags:
- `-h, --help   help for work`

### `work active`

Flags:
- `-h, --help   help for active`

### `work blocked`

Flags:
- `-h, --help   help for blocked`

### `work ready`

Flags:
- `-h, --help   help for ready`

## `completion`

### `completion`

Subcommands:
- `bash        Generate the autocompletion script for bash`
- `fish        Generate the autocompletion script for fish`
- `powershell  Generate the autocompletion script for powershell`
- `zsh         Generate the autocompletion script for zsh`

Flags:
- `-h, --help   help for completion`

### `completion bash`

This script depends on the 'bash-completion' package. If it is not installed already, you can install it via your OS's package manager.  To load completions in your current shell session:  source <(aw completion bash)  To load completions for every new session, execute once:  #### Linux:  aw completion bash > /etc/bash_completion.d/aw  #### macOS:  aw completion bash > $(brew --prefix)/etc/bash_completion.d/aw  You will need to start a new shell for this setup to take effect.

Flags:
- `-h, --help              help for bash`
- `--no-descriptions   disable completion descriptions`

### `completion fish`

To load completions in your current shell session:  aw completion fish | source  To load completions for every new session, execute once:  aw completion fish > ~/.config/fish/completions/aw.fish  You will need to start a new shell for this setup to take effect.

Flags:
- `-h, --help              help for fish`
- `--no-descriptions   disable completion descriptions`

### `completion powershell`

To load completions in your current shell session:  aw completion powershell | Out-String | Invoke-Expression  To load completions for every new session, add the output of the above command to your powershell profile.

Flags:
- `-h, --help              help for powershell`
- `--no-descriptions   disable completion descriptions`

### `completion zsh`

If shell completion is not already enabled in your environment you will need to enable it.  You can execute the following once:  echo "autoload -U compinit; compinit" >> ~/.zshrc  To load completions in your current shell session:  source <(aw completion zsh)  To load completions for every new session, execute once:  #### Linux:  aw completion zsh > "${fpath[1]}/_aw"  #### macOS:  aw completion zsh > $(brew --prefix)/share/zsh/site-functions/_aw  You will need to start a new shell for this setup to take effect.

Flags:
- `-h, --help              help for zsh`
- `--no-descriptions   disable completion descriptions`

## `help`

### `help`

Help provides help for any command in the application. Simply type aw help [path to command] for full details.

Flags:
- `-h, --help   help for help`

## `upgrade`

### `upgrade`

Flags:
- `-h, --help   help for upgrade`

## `version`

### `version`

Flags:
- `-h, --help   help for version`
