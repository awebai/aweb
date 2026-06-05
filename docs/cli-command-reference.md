# CLI Command Reference

This reference is generated from the live Cobra help tree emitted by the
`aw` binary built from [`cli/go/cmd/aw/`](../cli/go/cmd/aw). Run
[`scripts/regenerate-cli-reference.sh`](../scripts/regenerate-cli-reference.sh)
to refresh it.

## Command Families

| Family | Commands |
| --- | --- |
| Workspace Setup | `claim-human`, `init`, `reset`, `service`, `team`, `workspace` |
| Identity | `id`, `mcp-config`, `whoami` |
| Messaging & Network | `chat`, `contacts`, `control`, `directory`, `events`, `heartbeat`, `inbound-mode`, `log`, `mail` |
| Coordination & Runtime | `instructions`, `lock`, `notify`, `role-name`, `roles`, `run`, `task`, `work` |
| Utility | `completion`, `doctor`, `help`, `upgrade`, `version` |

## Global Flags

- `--debug Log background errors to stderr`
- `-h, --help help for aw`
- `--json Output as JSON`
- `--server-name string Override the server host or name for this command`

## `claim-human`

### `claim-human`

Attach an email address to your CLI-created account

Flags:
- `--email string Email address to attach to the current CLI-created account`
- `-h, --help help for claim-human`
- `--mock-url string Override the bootstrap base URL for local development`
- `--username string Override the default dashboard username derived from the registered domain`

## `init`

### `init`

Initialize the current directory using one of the supported
team-architecture flows:

- connect with an existing team certificate already present in .aw/
- create a hosted aweb.ai account when this directory is still clean
- use --byod to create an identity under a domain you control

By default, init creates or updates the clearly marked aweb section in
AGENTS.md or CLAUDE.md. Use --do-not-touch-agents-md to skip that file update.

Flags:
- `--agent-type string Runtime type (default: AWEB_AGENT_TYPE or agent)`
- `--alias string Local workspace routing alias (optional; default: server-suggested)`
- `--aweb-url string Base URL for the aweb server used by aw init (overrides AWEB_URL)`
- `--awid-registry string Base URL for the awid registry used by aw init (overrides AWID_REGISTRY_URL)`
- `--byod Use a domain you control instead of hosted aweb.ai onboarding`
- `--do-not-touch-agents-md Do not create or update AGENTS.md or CLAUDE.md during init`
- `--domain string BYOD domain to use with --byod`
- `--global Create an addressed self-custodial global identity instead of the default local workspace`
- `-h, --help help for init`
- `--human-name string Human name (default: AWEB_HUMAN or $USER)`
- `--inbound-mode string Inbound delivery mode for a global identity (open|team-and-contacts). Only valid with --global.`
- `--inject-docs Inject aw coordination instructions into CLAUDE.md and AGENTS.md`
- `--name string Global identity name (required with --global unless .aw/identity.yaml already exists)`
- `--print-exports Print shell export lines after JSON output`
- `--role string Compatibility alias for --role-name`
- `--role-name string Workspace role name (must match a role in the active team roles bundle)`
- `--setup-channel Set up Claude Code channel MCP server for real-time coordination`
- `--setup-hooks Set up Claude Code PostToolUse hook for aw notify`
- `--url string Base URL for the aweb server used for init, bootstrap, and hosted onboarding flows`
- `--username string Hosted username to create`
- `--write-context Ensure .aw/context exists in the current directory (default true)`

## `reset`

### `reset`

Removes the local .aw/context and .aw/workspace.yaml files in the current directory without mutating any server-side identity state.

Flags:
- `-h, --help help for reset`

## `service`

### `service`

Connect an existing AWID identity and team certificate to an aw-compatible service.

Service commands do not create identities, register AWID teams, mutate team
membership, or call BYOD onboarding flows. Use `aw id team register` to add a
team projection to a service first, then run `aw service init` from each
certified agent workspace.

Subcommands:
- `init` Initialize this workspace against a service using an existing team certificate

Flags:
- `-h, --help help for service`

## `service init`

### `service init`

Initialize this workspace against a service using the existing .aw signing key
and team certificate in this directory. This command only connects this
workspace to the service; it does not create identities, create teams, or
change AWID team membership.

Flags:
- `-h, --help help for init`
- `--role string Optional role name for this workspace`
- `--service string Service URL to connect to`
- `--team string Canonical AWID team id to activate before connecting`

## `team`

### `team`

Bootstrap agent teams from templates

Subcommands:
- `bootstrap` Bootstrap an agent team from a template repository

Flags:
- `-h, --help help for team`
- `--team string Override the selected team_id for this command`

## `team bootstrap`

### `team bootstrap`

Bootstrap an agent team from a template repository.

The template repository is convention-first:

  docs/                  shared team/project instructions
  roles/                 role playbooks installed with aw roles set
  home/<responsibility>/AGENTS.md
  team.yaml              maps agent responsibility dirs to aw role names

team.yaml supplies the parts that cannot be inferred safely: role bundle
metadata, each agent responsibility's role_name, and default identity names.
Agent directory names are responsibilities (for example coordinator,
implementation, or review), not fixed human/agent names.

By default bootstrap runs in the current project git repo and creates an
agents/ convention directory:

  agents/home/<responsibility>/      agent homes; run Codex/Claude from here
  agents/worktrees/<alias>/          generated git worktrees for worktree agents

Use --agents-dir to choose a different project-local convention directory.
Passing --work-directory or --work-repo-url selects the legacy out-of-repo mode.

By default bootstrap uses the template's default identity names; pass
--ask-for-agent-names when you want an interactive prompt to rename generated
agents before provisioning.

Flags:
- `--agents-dir string Project-local directory to create for in-repo bootstrap output (default "agents")`
- `--ask-for-agent-names Prompt for generated agent names instead of using template defaults`
- `--aweb-url string Aweb server base URL to connect each generated agent workspace`
- `--dry-run Validate and print the bootstrap plan without changing files or team roles`
- `--fork Fork the template repository with gh and clone the fork into the destination directory`
- `-h, --help help for bootstrap`
- `--home-root string Legacy mode: directory where agent workspaces are created (default: <template-dir>/agents)`
- `--invite-token string Team invite token to accept into the first generated agent workspace`
- `--namespace string BYOT team namespace domain to create/use (required for one-step BYOT team bootstrap)`
- `--refresh-template Re-clone the template into the destination directory before using it`
- `--registry string AWID registry URL override`
- `--skip-instructions Do not install shared team instructions`
- `--skip-roles Do not install the roles bundle`
- `--team string BYOT team name/slug to create/use (required for one-step BYOT team bootstrap)`
- `--team-display-name string Optional team display name when creating a new BYOT team`
- `--template-cache-dir string Directory where remote templates are cloned (advanced; defaults to cloning into the current directory)`
- `--username string Hosted onboarding username to create/use (prompts when omitted and onboarding is used)`
- `--work-directory string Legacy mode: directory symlinked into each agent workspace as ./work (mutually exclusive with --work-repo-url)`
- `--work-repo-url string Legacy mode: git URL or local repo path to clone into <template-dir>/worktrees/<derived-name> (mutually exclusive with --work-directory)`

## `workspace`

### `workspace`

Manage repo-local coordination workspaces

Subcommands:
- `add-worktree` Create a sibling git worktree and initialize a new coordination workspace in it
- `delete` Delete a local workspace and its local identity
- `migrate-multi-team` Rewrite a legacy single-team workspace into the canonical multi-team shape
- `status` Show coordination status for the current workspace/identity and team

Flags:
- `-h, --help help for workspace`
- `--team string Override the selected team_id for this command`

## `workspace add-worktree`

### `workspace add-worktree`

Create a sibling git worktree and initialize a new coordination workspace in it

Flags:
- `--alias string Override the default alias`
- `-h, --help help for add-worktree`

## `workspace delete`

### `workspace delete`

Delete a local workspace and its local identity

Flags:
- `-h, --help help for delete`

## `workspace migrate-multi-team`

### `workspace migrate-multi-team`

Rewrite a legacy single-team workspace into the canonical multi-team shape

Flags:
- `-h, --help help for migrate-multi-team`

## `workspace status`

### `workspace status`

Show coordination status for the current workspace/identity and team

Flags:
- `--all Show all local team memberships in addition to the selected team status`
- `-h, --help help for status`
- `--limit int Maximum team workspaces to show (default 15)`

## `id`

### `id`

Identity lifecycle, registry, settings, and key management

Subcommands:
- `addresses` List registry addresses for a did:aw
- `cert` Team certificate operations
- `create` Create a standalone global identity with a DNS-backed address in .aw/
- `encryption-key` Manage local E2E encryption keys for this self-custodial identity
- `log` Show an identity log
- `namespace` Inspect or recover namespace controller state
- `register` Register the current global identity at the configured registry
- `request` Make a DIDKey-signed HTTP request with the local identity key
- `resolve` Resolve a did:aw to its current did:key
- `rotate-key` Rotate the current global identity signing key at the registry
- `show` Show the current identity and registry status
- `sign` Sign a canonical JSON payload with the local identity key
- `team` Team management (create, invite, membership)
- `verify` Verify the full audit log for a did:aw

Flags:
- `-h, --help help for id`

## `id addresses`

### `id addresses`

List registry addresses for a did:aw

Flags:
- `-h, --help help for addresses`

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

Create a standalone global identity with a DNS-backed address in .aw/

Flags:
- `--domain string Global identity domain`
- `-h, --help help for create`
- `--name string Global identity name`
- `--registry string Registry origin override (default: api.awid.ai)`
- `--skip-dns-verify Skip the DNS TXT verification prompt and lookup`

## `id encryption-key`

### `id encryption-key`

Manage local E2E encryption keys for this self-custodial identity

Subcommands:
- `rotate` Rotate the local E2E encryption key while keeping archived keys
- `setup` Create or publish the local E2E encryption key for this identity
- `show` Show local E2E encryption key state

Flags:
- `-h, --help help for encryption-key`

## `id encryption-key rotate`

### `id encryption-key rotate`

Rotate the local E2E encryption key while keeping archived keys

Flags:
- `-h, --help help for rotate`

## `id encryption-key setup`

### `id encryption-key setup`

Create or publish the local E2E encryption key for this identity

Flags:
- `-h, --help help for setup`

## `id encryption-key show`

### `id encryption-key show`

Show local E2E encryption key state

Flags:
- `-h, --help help for show`

## `id log`

### `id log`

Display rotation and status history. Without arguments, shows your own log.

Flags:
- `-h, --help help for log`

## `id namespace`

### `id namespace`

Inspect or recover namespace controller state

Subcommands:
- `addresses` List registry namespace addresses
- `assign-address` Assign a namespace address to an existing did:aw using the local controller key
- `check-txt` Verify the _awid DNS TXT record matches the local namespace controller key
- `delete` Delete an AWID namespace using the local controller key
- `delete-address` Delete a namespace address claim using the local controller key
- `prepare-controller` Create or show a local namespace controller key and DNS TXT value
- `resolve` Resolve a registry namespace address
- `rotate-controller` Recover namespace control by rotating to a new controller key
- `set-delivery-origin` Set namespace address-route default delivery origin using the local controller key

Flags:
- `-h, --help help for namespace`

## `id namespace addresses`

### `id namespace addresses`

List registry namespace addresses

Flags:
- `--authority string Authority mode: anonymous, did, or namespace-controller (default "anonymous")`
- `-h, --help help for addresses`

## `id namespace assign-address`

### `id namespace assign-address`

Assign a namespace address to an existing did:aw using the local controller key

Flags:
- `--did-aw string Existing did:aw to bind the address to`
- `--domain string Namespace domain (e.g. aweb.ai)`
- `-h, --help help for assign-address`
- `--name string Address name (e.g. alice)`

## `id namespace check-txt`

### `id namespace check-txt`

Verify the _awid DNS TXT record matches the local namespace controller key.

This is read-only. It looks up _awid.<domain>, loads the local namespace
controller key from ~/.awid/controllers/<domain>.key (or --controller-key),
and fails if DNS has not propagated or points at a different controller DID.

Flags:
- `--controller-key string Namespace controller key path override`
- `--domain string Namespace domain`
- `-h, --help help for check-txt`

## `id namespace delete`

### `id namespace delete`

Delete an AWID namespace using the local namespace controller key.

Namespace deletion requires all active certificates in the namespace to be
revoked first. It does not update DNS; remove any _awid TXT record at your
DNS provider after the registry delete succeeds. Local controller/team key
files are preserved unless --purge-local is set, in which case they are moved
to ~/.awid/deregister-backups/ instead of being unlinked.

Flags:
- `--domain string Namespace domain (e.g. aweb.ai)`
- `-h, --help help for delete`
- `--purge-local Move local controller and team keys for the namespace to ~/.awid/deregister-backups after successful registry delete`
- `--reason string Optional deletion reason recorded by the registry`
- `--registry string Registry origin override`

## `id namespace delete-address`

### `id namespace delete-address`

Delete a namespace address claim using the local namespace controller key.

This removes the address route/claim, not the append-only did:aw audit log. If the
address has active team certificates, revoke those certificates first.

Flags:
- `--domain string Namespace domain (e.g. aweb.ai)`
- `-h, --help help for delete-address`
- `--name string Address name (e.g. alice)`
- `--reason string Optional deletion reason recorded by the registry`
- `--registry string Registry origin override`

## `id namespace prepare-controller`

### `id namespace prepare-controller`

Create or show a local namespace controller key and DNS TXT value.

This command is deliberately local-only: it writes the namespace controller
key under ~/.awid/controllers and prints the _awid TXT record to publish.
Keep ~/.awid safe and backed up; losing this key means losing direct namespace
controller authority unless you recover via DNS. It does not call AWID, create
a did:aw identity, claim an address, create a team, or modify aweb Cloud state.

Flags:
- `--domain string Namespace domain`
- `-h, --help help for prepare-controller`
- `--registry string Registry origin to place in the DNS TXT record (default: api.awid.ai or AWID_REGISTRY_URL)`

## `id namespace resolve`

### `id namespace resolve`

Resolve a registry namespace address

Flags:
- `--authority string Authority mode: anonymous, did, or namespace-controller (default "anonymous")`
- `-h, --help help for resolve`

## `id namespace rotate-controller`

### `id namespace rotate-controller`

Recover namespace control by rotating to a new controller key

Flags:
- `--domain string Namespace domain to rotate`
- `-h, --help help for rotate-controller`

## `id namespace set-delivery-origin`

### `id namespace set-delivery-origin`

Set namespace address-route default delivery origin using the local controller key

Flags:
- `--domain string Namespace domain (alias for --namespace)`
- `-h, --help help for set-delivery-origin`
- `--namespace string Namespace domain (e.g. acme.com)`
- `--origin string Canonical aweb server origin (e.g. https://aweb.acme.com)`

## `id register`

### `id register`

Register the current global identity at the configured registry

Flags:
- `-h, --help help for register`

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
- `--team-auth Attach the active team certificate and sign a team-bound request payload`

## `id resolve`

### `id resolve`

Resolve a did:aw to its current did:key

Flags:
- `-h, --help help for resolve`

## `id rotate-key`

### `id rotate-key`

Rotate the current global identity signing key at the registry

Flags:
- `-h, --help help for rotate-key`

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
- `accept-invite` Accept a team invite and receive a membership certificate
- `add` Join another team with the current identity
- `add-member` Add a member directly to a team (controller signs certificate)
- `cleanup-cloud` Delete aweb Cloud's BYOT projection after registry team deletion
- `create` Create a team at awid
- `delete` Delete an AWID team using the namespace controller key
- `fetch-cert` Fetch and install an approved team certificate
- `import-request` Create a signed BYOT import request for aweb cloud
- `invite` Generate an invite token for a team
- `leave` Remove a team membership from this identity
- `list` List team memberships for this identity
- `register` Register or sync a customer-controlled team with a service
- `remove-member` Remove a member from a team (revoke certificate)
- `request` Print the add-member command the team owner should run
- `switch` Switch the active team for this identity

Flags:
- `-h, --help help for team`

## `id team accept-invite`

### `id team accept-invite`

Accept a team invite and receive a membership certificate.

Hosted aw_inv_ tokens are redeemed through the cloud, generate a fresh local
identity, and refuse to overwrite an existing .aw identity in the target
directory. After accepting, run `aw init` in that directory to connect the
workspace.

Local-controller invite tokens are same-machine helpers: they require the
local invite record and local team controller key. For cross-machine BYOT
joins, use `aw id team request`, have the controller run
`aw id team add-member`, then install with `aw id team fetch-cert` on the
joining machine.

Flags:
- `--address string Registered address to place in the global member certificate`
- `--alias string Alias for the accepting agent (defaults to identity name)`
- `-h, --help help for accept-invite`

## `id team add`

### `id team add`

Join another team with the current identity

Flags:
- `--address string Registered address to place in the global member certificate`
- `--alias string Alias for the added team membership (defaults to the current identity name)`
- `-h, --help help for add`

## `id team add-member`

### `id team add-member`

Add a member directly to a team (controller signs certificate)

Flags:
- `--address string Global member address when using --did; must resolve to --did-aw`
- `--alias string Alias to use with --did`
- `--did string Member did:key for direct certificate issuance`
- `--did-aw string Optional stable did:aw when using --did`
- `--global Issue a global member certificate for --did`
- `-h, --help help for add-member`
- `--local Issue a local workspace member certificate for --did (default)`
- `--member string Member address (e.g. acme.com/alice)`
- `--namespace string Namespace domain`
- `--team string Team name`

## `id team cleanup-cloud`

### `id team cleanup-cloud`

Delete aweb Cloud's imported BYOT team projection using customer-held controller authority.

This command does not mutate AWID. In the normal path it signs the cleanup
request with ~/.awid/team-keys/<namespace>/<team>.key so aweb Cloud can
verify that the customer-controlled team controller authorized the projection
delete. If the team controller key has already been retired, use
--namespace-controller to sign with the namespace controller key; aweb Cloud
will verify that key against the _awid.<domain> DNS TXT controller for the
team's domain, with AWID registry lookup as a fallback when DNS is absent.

Flags:
- `--apply Apply the cleanup instead of dry-run`
- `--aweb-url string aweb Cloud URL (default "https://app.aweb.ai")`
- `-h, --help help for cleanup-cloud`
- `--namespace string Namespace domain`
- `--namespace-controller Authorize cleanup with the namespace controller key instead of the team controller key`
- `--namespace-key string Namespace controller key path override for --namespace-controller`
- `--team string Team name`
- `--team-key string Team controller key path override`
- `--timestamp string RFC3339 timestamp to sign (defaults to now; accepted for five minutes by cloud)`

## `id team create`

### `id team create`

Create a team at awid

Flags:
- `--display-name string Team display name`
- `-h, --help help for create`
- `--name string Team name`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`

## `id team delete`

### `id team delete`

Delete an AWID team using the local namespace controller key.

Delete-team requires the team's active certificates to be revoked first. It
does not delete the namespace or any unrelated address claims.

Flags:
- `-h, --help help for delete`
- `--namespace string Namespace domain`
- `--reason string Optional deletion reason recorded by the registry`
- `--registry string Registry origin override`
- `--team string Team name`

## `id team fetch-cert`

### `id team fetch-cert`

Fetch and install an approved team certificate

Flags:
- `--cert-id string Certificate id`
- `--force Overwrite an existing local certificate for the team`
- `-h, --help help for fetch-cert`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

## `id team import-request`

### `id team import-request`

Create a signed BYOT import request for aweb cloud.

This command signs the canonical import payload with your local BYOT team
controller key. It prints the request body expected by
POST /api/v1/teams/byoidt/import. It never uploads or prints namespace or
team controller private keys. The cloud import endpoint accepts the signed
timestamp for five minutes; regenerate the request body after it expires.

Flags:
- `--apply Create an apply request instead of the default dry-run request`
- `--cloud-team-id string Existing AC team id to sync`
- `-h, --help help for import-request`
- `--namespace string Namespace domain`
- `--organization-id string AC organization id for a new imported team`
- `--team string Team name`
- `--timestamp string RFC3339 timestamp to sign (defaults to now; accepted for five minutes by cloud)`

## `id team invite`

### `id team invite`

Generate an invite token for a team.

Defaults to the active local team when --team and --namespace are omitted.
Invites create local workspace members unless --global is set. Hosted teams use cloud
invite authority; local-controller teams use the local team controller key.

Flags:
- `--global Create global member invite`
- `-h, --help help for invite`
- `--local Create local workspace member invite (default)`
- `--namespace string Namespace domain`
- `--team string Team name`

## `id team leave`

### `id team leave`

Remove a team membership from this identity

Flags:
- `-h, --help help for leave`

## `id team list`

### `id team list`

List team memberships for this identity

Flags:
- `-h, --help help for list`

## `id team register`

### `id team register`

Register or sync a customer-controlled AWID team with an aw-compatible service.

This command is service-generic: it signs a registration request with the
local team controller key and sends only public/signed team facts to the
service. It never uploads namespace or team controller private keys and does
not initialize any agent workspace. Services may return their own next steps,
such as `aw service init` or `aw claim-human`.

Flags:
- `--dry-run Preview registration without mutating the service projection`
- `-h, --help help for register`
- `--registry string Registry origin override`
- `--service string Service URL to register with`
- `--team string Canonical AWID team id (<team>:<namespace>)`
- `--timestamp string RFC3339 timestamp to sign (defaults to now; accepted for five minutes by service)`

## `id team remove-member`

### `id team remove-member`

Remove a member from a team (revoke certificate)

Flags:
- `-h, --help help for remove-member`
- `--member string Member address (e.g. acme.com/alice)`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

## `id team request`

### `id team request`

Print the add-member command the team owner should run

Flags:
- `--alias string Suggested alias for the new team membership`
- `-h, --help help for request`
- `--team string Canonical team ID (<name>:<domain>)`

## `id team switch`

### `id team switch`

Switch the active team for this identity

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
- `--team string Override the selected team_id for this command`

## `chat`

### `chat`

Real-time chat

Subcommands:
- `extend-wait` Ask the other party to wait longer
- `history` Show chat history with alias
- `listen` Wait for a message without sending
- `open` Open a chat session
- `pending` List pending chat sessions
- `read` Mark chat messages read by session and message id
- `send` Send a message to an exact chat session
- `send-and-leave` Send a message and leave the conversation
- `send-and-wait` Send a message and wait for a reply
- `show-pending` Show pending messages for alias

Flags:
- `-h, --help help for chat`
- `--team string Override the selected team_id for this command`

## `chat extend-wait`

### `chat extend-wait`

Ask the other party to wait longer

Flags:
- `--e2ee Send E2E encrypted wait extension; fails closed if encryption keys are missing`
- `-h, --help help for extend-wait`
- `--plaintext Send explicit server-readable plaintext wait extension (currently the default)`

## `chat history`

### `chat history`

Show chat history with alias

Flags:
- `-h, --help help for history`
- `--limit int Maximum messages to fetch (default 1000)`
- `--message-id string Fetch one message by id when using --session-id`
- `--session-id string Fetch chat history by session id instead of alias`
- `--unread-only Fetch unread messages only`

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

## `chat read`

### `chat read`

Mark chat messages read by session and message id

Flags:
- `-h, --help help for read`
- `--message-id string Last delivered message id to mark read`
- `--session-id string Chat session id`

## `chat send`

### `chat send`

Send a message to an exact chat session

Flags:
- `--body string Body (mutually exclusive with --body-file)`
- `--body-file string Read body from file`
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send`
- `--leave Leave the conversation after sending`
- `--plaintext Send explicit server-readable plaintext chat (currently the default)`
- `--session-id string Existing chat session id`

## `chat send-and-leave`

### `chat send-and-leave`

Send a message and leave the conversation

Flags:
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send-and-leave`
- `--plaintext Send explicit server-readable plaintext chat (currently the default)`
- `--start-conversation Start a new conversation instead of continuing an existing one`

## `chat send-and-wait`

### `chat send-and-wait`

Send a message and wait for a reply

Flags:
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send-and-wait`
- `--plaintext Send explicit server-readable plaintext chat (currently the default)`
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
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`

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

Search or look up global identities in the network directory

Flags:
- `--capability string Filter by capability`
- `--domain string Filter by domain`
- `-h, --help help for directory`
- `--limit int Max results (default 100)`
- `--query string Search handle/description`
- `--team string Override the selected team_id for this command`

## `events`

### `events`

Event stream operations

Subcommands:
- `stream` Listen to real-time agent events via SSE

Flags:
- `-h, --help help for events`
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`

## `inbound-mode`

### `inbound-mode`

Show or set the current agent's inbound delivery mode

Flags:
- `-h, --help help for inbound-mode`
- `--team string Override the selected team_id for this command`

## `log`

### `log`

Show local communication log

Flags:
- `--channel string Filter by channel (mail, chat, dm)`
- `--from string Filter by sender (substring match)`
- `-h, --help help for log`
- `--limit int Max entries to show (default 20)`
- `--team string Override the selected team_id for this command`

## `mail`

### `mail`

Agent messaging

Subcommands:
- `ack` Acknowledge one mail message as read
- `inbox` List inbox messages (unread only by default)
- `reply` Reply to an existing mail conversation
- `send` Send a message to another agent
- `show` Show a mail conversation

Flags:
- `-h, --help help for mail`
- `--team string Override the selected team_id for this command`

## `mail ack`

### `mail ack`

Acknowledge one mail message as read

Flags:
- `-h, --help help for ack`

## `mail inbox`

### `mail inbox`

List inbox messages (unread only by default)

Flags:
- `-h, --help help for inbox`
- `--limit int Max messages (default 50)`
- `--show-all Show all messages including already-read`

## `mail reply`

### `mail reply`

Reply to an existing mail conversation

Flags:
- `--body string Body (mutually exclusive with --body-file)`
- `--body-file string Read body from file`
- `--e2ee Send E2E encrypted mail; fails closed if encryption keys are missing`
- `-h, --help help for reply`
- `--plaintext Send explicit server-readable plaintext mail (currently the default)`
- `--priority string Priority: low|normal|high|urgent (default "normal")`
- `--subject string Subject`

## `mail send`

### `mail send`

Send a message to another agent

Flags:
- `--body string Body (mutually exclusive with --body-file)`
- `--body-file string Read body from file (use this for markdown with backticks; bypasses shell interpolation)`
- `--conversation-id string Existing mail conversation to continue`
- `--e2ee Send E2E encrypted mail; fails closed if encryption keys are missing`
- `-h, --help help for send`
- `--plaintext Send explicit server-readable plaintext mail (currently the default)`
- `--priority string Priority: low|normal|high|urgent (default "normal")`
- `--subject string Subject`
- `--to string Recipient alias within the active team`
- `--to-address string Recipient address (domain/name)`
- `--to-did string Recipient stable identity (did:aw:...)`

## `mail show`

### `mail show`

Show a mail conversation

Flags:
- `--conversation-id string Mail conversation to inspect`
- `-h, --help help for show`
- `--limit int Max messages (default 200)`
- `--message-id string Legacy mail message to inspect`

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
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`

## `role-name`

### `role-name`

Manage the current workspace role name

Subcommands:
- `set` Set the current workspace role name

Flags:
- `-h, --help help for role-name`
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`
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
- `--team string Override the selected team_id for this command`

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
- `--team string Override the selected team_id for this command`

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

## `doctor`

### `doctor`

Diagnose local identity, workspace, and coordination state

Subcommands:
- `identity` Run identity doctor checks
- `local` Run local doctor checks
- `messaging` Run messaging doctor checks
- `registry` Run registry doctor checks
- `support-bundle` Write a redacted doctor support bundle
- `team` Run team doctor checks
- `workspace` Run workspace doctor checks

Flags:
- `--dry-run Plan fixes without applying them`
- `--fix Apply safe doctor fixes`
- `-h, --help help for doctor`
- `--offline Run without network checks`
- `--online Allow online checks`
- `--team string Override the selected team_id for this command`
- `--verbose Include verbose diagnostic details`

## `doctor identity`

### `doctor identity`

Run identity doctor checks

Flags:
- `-h, --help help for identity`

## `doctor local`

### `doctor local`

Run local doctor checks

Flags:
- `-h, --help help for local`

## `doctor messaging`

### `doctor messaging`

Run messaging doctor checks

Flags:
- `-h, --help help for messaging`

## `doctor registry`

### `doctor registry`

Run registry doctor checks

Flags:
- `-h, --help help for registry`

## `doctor support-bundle`

### `doctor support-bundle`

Write a redacted doctor support bundle

Flags:
- `-h, --help help for support-bundle`
- `--output string Output JSON file`

## `doctor team`

### `doctor team`

Run team doctor checks

Flags:
- `-h, --help help for team`

## `doctor workspace`

### `doctor workspace`

Run workspace doctor checks

Flags:
- `-h, --help help for workspace`

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
