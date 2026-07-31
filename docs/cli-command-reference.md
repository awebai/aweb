---
title: "CLI command reference"
kicker: "Reference"
description: "Every aw command and flag, generated from the live help tree of the shipped binary."
weight: 90
---

# CLI Command Reference

This reference is generated from the live Cobra help tree emitted by the
`aw` binary built from [`cli/go/cmd/aw/`](../cli/go/cmd/aw). Run
[`scripts/regenerate-cli-reference.sh`](../scripts/regenerate-cli-reference.sh)
to refresh it.

## Command Families

| Family | Commands |
| --- | --- |
| Workspace Setup | `check`, `claim-human`, `init`, `reset`, `service`, `workspace` |
| Identity | `id`, `mcp-config`, `team`, `whoami` |
| Messaging & Network | `a2a`, `chat`, `contacts`, `control`, `directory`, `events`, `heartbeat`, `inbound-mode`, `log`, `mail` |
| Coordination & Runtime | `agent`, `instructions`, `lock`, `notify`, `role-name`, `roles`, `run`, `task`, `work` |
| Utility | `completion`, `doctor`, `help`, `plugin`, `upgrade`, `version` |
| Additional Commands | `blueprint`, `session` |

## Global Flags

- `--debug Log background errors to stderr`
- `-h, --help help for aw`
- `--identity-home string Use identity authority from this absolute credential root`
- `--json Output as JSON`
- `--server-name string Override the server host or name for this command`
- `--trace Trace redacted HTTP requests and responses to stderr`

## `check`

### `check`

Check local identity, workspace, team, and service connectivity.

This is the everyday setup diagnostic entrypoint. It runs the same checks as
`aw doctor` and is safe to run before asking a teammate or support for help.

Flags:
- `--dry-run Plan fixes without applying them`
- `--fix Apply safe doctor fixes`
- `-h, --help help for check`
- `--offline Run without network checks`
- `--online Allow online checks`
- `--team string Override the selected team_id for this command`
- `--verbose Include verbose diagnostic details`

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
- `--name string Identity/member name (global address name with --global, local routing name otherwise)`
- `--print-exports Print shell export lines after JSON output`
- `--role string Compatibility alias for --role-name`
- `--role-name string Workspace role name (must match a role in the active team roles bundle)`
- `--setup-channel Set up Claude Code aweb-channel plugin for real-time coordination`
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

## `workspace`

### `workspace`

Manage repo-local coordination workspaces

Subcommands:
- `add-worktree` Legacy convenience: create a sibling git worktree and coordination workspace
- `connect` Connect this workspace to a service using an existing team certificate
- `delete` Delete a local workspace and its local identity
- `migrate-multi-team` Rewrite a legacy single-team workspace into the canonical multi-team shape
- `status` Show coordination status for the current workspace/identity and team

Flags:
- `-h, --help help for workspace`
- `--team string Override the selected team_id for this command`

## `workspace add-worktree`

### `workspace add-worktree`

Legacy convenience for existing users: create a sibling git worktree and initialize a new coordination workspace in it.

New setup flows should prefer explicit git worktree/filesystem steps followed by aw init, invite/join, or service init primitives unless this command is reduced to a transparent wrapper with no identity/team orchestration.

Flags:
- `-h, --help help for add-worktree`
- `--name string Override the default workspace/member name`

## `workspace connect`

### `workspace connect`

Connect this workspace to a service using the existing .aw signing key and team certificate in this directory.

This is the first-class workspace connection verb. It does not create identities,
create teams, or change AWID team membership. It is equivalent to `aw service init`.

Flags:
- `-h, --help help for connect`
- `--role string Optional role name for this workspace`
- `--service string Service URL to connect to`
- `--team string Canonical AWID team id to activate before connecting`

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
- `--limit int Maximum team workspaces to show (default 50)`

## `id`

### `id`

Identity lifecycle, registry, settings, and key management

Subcommands:
- `address` Manage addresses for the current global identity
- `addresses` List registry addresses for a did:aw (defaults to the current global identity)
- `cert` Team certificate operations
- `create` Create a global identity by claiming a namespace address
- `encryption-key` Manage local E2E encryption keys for this self-custodial identity
- `log` Show an identity log
- `namespace` Protocol/admin namespace controller and address operations
- `register` Register the current global identity at the configured registry
- `request` Make a DIDKey-signed HTTP request with the local identity key
- `resolve` Resolve a did:aw to its current did:key
- `rotate-key` Rotate the current global identity signing key at the registry
- `show` Show the current identity and registry status
- `sign` Sign a canonical JSON payload with the local identity key
- `team` Team membership plus protocol/admin certificate operations
- `verify` Verify the full audit log for a did:aw

Flags:
- `-h, --help help for id`

## `id address`

### `id address`

Manage addresses for the current global identity

Subcommands:
- `claim` Claim an additional address for the current global identity

Flags:
- `-h, --help help for address`

## `id address claim`

### `id address claim`

Claim an additional address for the current global identity

Flags:
- `-h, --help help for claim`
- `--registry string Registry origin override`

## `id addresses`

### `id addresses`

List registry addresses for a did:aw (defaults to the current global identity)

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

Create a self-custodial global identity in .aw/ by claiming DOMAIN/NAME
in a namespace you control. This mints a did:aw, stores the local signing
key material, and atomically claims the global address in AWID.

Flags:
- `--domain string Namespace domain for the global identity address`
- `-h, --help help for create`
- `--name string Global identity name (address name under --domain)`
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

Protocol/admin namespace controller and address operations.

Use these commands when you hold a namespace controller key, are setting up BYOT,
are assigning or deleting namespace addresses, or are diagnosing AWID registry
state. Hosted happy-path setup should not require namespace controller commands.

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
- `--body string Request body to send. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read request body from a file; safe for Markdown or command examples`
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

Subcommands:
- `recover` Reconcile and safely finish a pending identity key rotation
- `status` Inspect pending identity key rotation state without changing it

Flags:
- `-h, --help help for rotate-key`

## `id rotate-key recover`

### `id rotate-key recover`

Reconcile and safely finish a pending identity key rotation

Flags:
- `-h, --help help for recover`

## `id rotate-key status`

### `id rotate-key status`

Inspect pending identity key rotation state without changing it

Flags:
- `-h, --help help for status`

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

Team membership plus protocol/admin certificate operations.

Everyday hosted setup normally uses invite and accept-invite. Controller-backed
commands such as create, add-member, remove-member, register, import-request,
cleanup-cloud, and delete are protocol/admin primitives for BYOT, controller
holders, service projection, or diagnostics.

Subcommands:
- `accept-invite` Accept a team invite and receive a membership certificate
- `add-member` Protocol/admin: add a member by signing a team certificate
- `cleanup-cloud` Protocol/admin: delete aweb Cloud's BYOT projection after registry team deletion
- `create` Protocol/admin: create a customer-controlled AWID team
- `delete` Protocol/admin: delete an AWID team using the namespace controller key
- `fetch-cert` Protocol/admin bridge: fetch and install an approved team certificate
- `import-request` Protocol/admin: create a signed BYOT import request for aweb cloud
- `invite` Generate an invite token for a team
- `leave` Remove a team membership from this identity
- `list` List team memberships for this identity
- `members` List a team's members from AWID certificates
- `register` Protocol/admin: register or sync a customer-controlled team with a service
- `remove-member` Protocol/admin: remove a member by revoking a team certificate
- `request` Protocol/admin bridge: print the add-member command the team owner should run
- `switch` Switch the active team for this identity

Flags:
- `-h, --help help for team`

## `id team accept-invite`

### `id team accept-invite`

Accept a team invite and receive a membership certificate.

Scope is explicit: --local is the default, and --global reuses the existing
self-custodial global identity in this workspace. --address never selects
global scope; pass --global when presenting an existing owned address.

Hosted aw_inv_ tokens are redeemed through the cloud. Local hosted accepts
create a fresh local signing key and refuse to overwrite completed local
state. Global hosted accepts reuse identity.yaml's stored did:aw and signing
key; they do not mint a new did:aw just because this identity joins another
team. Hosted --global accepts may use --address for an owned address or
--no-address for did:aw-only membership.
After accepting, run `aw init` in that directory to connect the
workspace.

Local-controller invite tokens are same-machine helpers: they require the
local invite record and local team controller key. Local-controller global
accepts default-claim team-domain/name only when the local namespace
controller key is also present; otherwise use --address for an owned address
or --no-address for did:aw-only membership. For cross-machine BYOT joins, use
`aw id team request`, have the controller run `aw id team add-member`, then
install with `aw id team fetch-cert` on the joining machine.

Flags:
- `--address string Advanced: existing owned address to place in the global member certificate`
- `--global Join by reusing the existing global identity in this workspace`
- `-h, --help help for accept-invite`
- `--local Join with a local workspace identity (default)`
- `--name string Member name for the accepting agent (defaults to identity name)`
- `--no-address For --global, join with did:aw continuity but no member address`

## `id team add-member`

### `id team add-member`

Protocol/admin: add a member by signing a team certificate

Flags:
- `--address string Global member address when using --did; must resolve to --did-aw`
- `--did string Member did:key for direct certificate issuance`
- `--did-aw string Optional stable did:aw when using --did`
- `--global Issue a global member certificate for --did`
- `-h, --help help for add-member`
- `--local Issue a local workspace member certificate for --did (default)`
- `--member string Member address (e.g. acme.com/alice)`
- `--name string Member name to use with --did`
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

Protocol/admin: create a customer-controlled AWID team

Flags:
- `--display-name string Team display name`
- `-h, --help help for create`
- `--name string Team name`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`

## `id team delete`

### `id team delete`

Protocol/admin: delete an AWID team using the local namespace controller key.

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

Protocol/admin bridge: fetch and install an approved team certificate

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
Invites create local workspace members unless --member-global is set. Hosted teams use cloud
invite authority; local-controller teams use the local team controller key.

Flags:
- `-h, --help help for invite`
- `--member-global Create global member invite`
- `--member-local Create local workspace member invite (default)`
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

## `id team members`

### `id team members`

List a team's members from AWID certificates.

Membership is represented by team certificates, so this identity-level
command lists the certificate roster for the selected team. By default it
shows active certificates; pass --include-revoked to include revoked rows.

Flags:
- `-h, --help help for members`
- `--include-revoked Include revoked membership certificates`
- `--namespace string Namespace domain; defaults to active team namespace`
- `--registry string Registry origin override`
- `--team string Team name; defaults to active team name`
- `--team-id string Canonical team id (<team>:<namespace>); defaults to active team`

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

Protocol/admin: remove a member by revoking a team certificate

Flags:
- `--api-key string Team API key for hosted removal (overrides AWEB_API_KEY; workspace-bound API keys are rejected by hosted aweb)`
- `--aweb-url string Hosted aweb API URL override for cloud-mediated removal`
- `--cert-id string Certificate id to revoke (hosted remove accepts --member or --cert-id)`
- `-h, --help help for remove-member`
- `--member string Member address (e.g. acme.com/alice)`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

## `id team request`

### `id team request`

Protocol/admin bridge: print the add-member command the team owner should run

Flags:
- `-h, --help help for request`
- `--name string Suggested member name for the new team membership`
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

## `team`

### `team`

Everyday team membership commands.

Use these commands for the normal hosted invite/join membership flow and for
checking or switching this identity's installed team memberships. Protocol/admin
controller operations remain under `aw id team`.

Subcommands:
- `add` Add agents to this team's agents/instances layout
- `adopt` Adopt a public-pinned agent profile onto the team's private Library shelf
- `agent-status` Read whether an agent still holds a certificate, a workspace, or task claims
- `create` Create a local empty-profile team workspace
- `extend` Add agents to an existing team by discovering membership authority
- `invite` Invite an agent or workspace to the active team
- `join` Join a team from an invite token
- `leave` Remove a team membership from this identity
- `list` List team memberships for this identity
- `refresh` Refresh a team member's profile and existing team-instructions block
- `remove-agent` Retire an agent: release its claims, then revoke its certificate
- `replace-key` Replace a local agent identity key under team-controller authority
- `switch` Switch the active team for this identity
- `up` Launch local team agents in tmux

Flags:
- `-h, --help help for team`

## `team add`

### `team add`

Add one or more agents to agents/instances/<name>/. Specs use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global] for empty-profile homes. Omitted names use the server-authoritative next classic name; omitted scope comes from profile.yaml. @VERSION is no longer supported.

Flags:
- `--attach Attach or switch to the tmux session after --start launch (default true)`
- `--blueprint string Default public Library blueprint for profile-only selectors (default: AWEB_BLUEPRINT or aweb.team)`
- `--global Add a global AWID identity/address-backed agent`
- `-h, --help help for add`
- `--home string Agent home directory override for a single added agent (default: agents/instances/<name>)`
- `--layout-only Only create agents/instances/<name>; do not create identity state`
- `--library-url string Public Library catalog base URL (default: AWEB_LIBRARY_URL or https://library.aweb.ai)`
- `--local Add a local team-scoped agent identity (default)`
- `--no-attach Do not attach or switch to the tmux session after --start launch`
- `--runtime string Materialization runtime for profile-bound agents (claude-code|codex|pi|local-shell; default claude-code)`
- `--session string tmux session name for --start (default: caller's session inside tmux, otherwise active team name or aw-team)`
- `--start Launch the added agent in tmux after materializing it`
- `--work-dir string Git repo to use for the agent's worktree (default: repo containing the home, if any)`

## `team adopt`

### `team adopt`

Adopt a public-pinned agents/instances/<name> profile onto the team's private Library shelf.
This reads .aw/profile/ref.json, imports the pinned public blueprint/profile onto the
team shelf through the installed Library plugin, binds the agent, and re-points the
local pin to the shelf copy by removing library_url. After adopt, aw team refresh
uses the shelf path and can pick up approved team-local profile mints.

Flags:
- `-h, --help help for adopt`
- `--home string Agent home directory override (default: agents/instances/<name>)`

## `team agent-status`

### `team agent-status`

Read the state of one agent across the stores retirement has to clear.

This reads and never writes. It exists so that the evidence an agent is
retired comes from somewhere other than the command that retired it.

Flags:
- `-h, --help help for agent-status`
- `--team-id string Canonical team id (<name>:<namespace>) to read from (defaults to active team)`

## `team create`

### `team create`

Create a local empty-profile team workspace.

This wraps aw init for the aw-local path. No --agent/--profile means no Library call
and no profile materialization. --agent accepts [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]
(or NAME[:local|global] for an empty-profile agent). Omitted names use the
server-authoritative next classic name; omitted scope comes from profile.yaml.
All --agent/--profile specs populate agents/instances for aw team up; only
--home with a single spec uses that spec for the root workspace profile.
Deprecated --profile is accepted as --agent for transition; @VERSION is dropped.

Flags:
- `--agent stringArray Agent spec [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global]`
- `--blueprint string With --agent/--profile, default public Library blueprint for profile-only selectors; without agents, materialize all profiles in a local blueprint directory`
- `--byot Create a customer-controlled AWID team with local namespace controller authority`
- `--display-name string Team display name`
- `--first-agent-global Enroll the first agent as a global identity, reusing an existing global identity or creating one when founding with hosted/namespace authority`
- `--first-agent-local Enroll the first agent as a local team-scoped identity (default)`
- `--first-agent-name string Initial workspace member name (defaults to <name>)`
- `-h, --help help for create`
- `--home string Agent home directory override for single-agent --profile create`
- `--library-url string Public Library catalog base URL (default: AWEB_LIBRARY_URL or https://library.aweb.ai)`
- `--name string Team name`
- `--namespace string Namespace domain for --byot`
- `--profile stringArray Deprecated alias for --agent; use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]`
- `--registry string Registry origin override for --byot`
- `--runtime string Materialization runtime for agent/profile homes (claude-code|codex|pi|local-shell; default claude-code)`
- `--service string Hosted service URL for dashboard guidance`
- `--username string Hosted username to create when founding through managed aweb onboarding`

## `team extend`

### `team extend`

Add agents to an existing team by discovering membership authority. Specs use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global] for empty-profile homes. Explicit --api-key or --team-id with AWEB_API_KEY wins. An ambient AWEB_API_KEY in a workspace with an active team uses that team as an assertion against the API key's team; explicit --api-key bypasses the workspace assertion.

Flags:
- `--api-key string Team API key for extending a team (overrides AWEB_API_KEY)`
- `--attach Attach or switch to the tmux session after --start launch (default true)`
- `--blueprint string Default public Library blueprint for profile-only selectors (default: AWEB_BLUEPRINT or aweb.team)`
- `--global Add a global AWID identity/address-backed agent`
- `-h, --help help for extend`
- `--library-url string Public Library catalog base URL (default: AWEB_LIBRARY_URL or https://library.aweb.ai)`
- `--local Add a local team-scoped agent identity (default)`
- `--no-attach Do not attach or switch to the tmux session after --start launch`
- `--runtime string Materialization runtime for profile-bound agents (claude-code|codex|pi|local-shell; default claude-code)`
- `--session string tmux session name for --start (default: caller's session inside tmux, otherwise active team name or aw-team)`
- `--start Launch the added agent in tmux after materializing it`
- `--team-id string Canonical team id (<name>:<namespace>) to extend when discovery is ambiguous or when asserting an API key's team`
- `--work-dir string Git repo to use for the agent's worktree (default: repo containing the home, if any)`

## `team invite`

### `team invite`

Invite an agent or workspace to the active team.

This creates an invite token using the current team's authority for a separate
workspace or machine, then the joining workspace runs `aw team join <token>`.
For local empty-profile homes under agents/instances/, use `aw team add`.

Flags:
- `-h, --help help for invite`
- `--member-global Create global member invite`
- `--member-local Create local workspace member invite (default)`
- `--team-id string Canonical team id (<name>:<namespace>) to invite from (defaults to active team)`

## `team join`

### `team join`

Join a team from an invite token.

Run this in a clean target directory. It refuses to overwrite an existing
.aw identity/key. After joining, run `aw init` if the output says the
workspace still needs to be connected to the service.

Flags:
- `--address string Advanced: existing owned address to place in the global member certificate`
- `--global Join by reusing the existing global identity in this workspace`
- `-h, --help help for join`
- `--local Join with a local workspace identity (default)`
- `--name string Member name for the accepting agent (defaults to identity name)`
- `--no-address For --global, join with did:aw continuity but no member address`

## `team leave`

### `team leave`

Remove a team membership from this identity

Flags:
- `-h, --help help for leave`

## `team list`

### `team list`

List team memberships for this identity

Flags:
- `-h, --help help for list`

## `team refresh`

### `team refresh`

Re-materialize agents/instances/<name> from the latest version of the profile it was
materialized from on the team's private Library shelf. This closes the learning loop: an
approved profile proposal mints a new shelf version, and `aw team refresh` re-applies it
locally and updates .aw/profile/ref.json - so the agent picks up the team's own improvement.
It reads the recorded profile ref locally and never asks a remote service which profile to use.

When the home already has exactly one complete AWEB:START/AWEB:END block, refresh also
re-injects the active team instructions. It never creates that block in an unmarked home; use
`aw instructions inject <directory>` when an explicit backfill is intended.

Upstream blueprint updates are a separate, composable step: run `aw library update-from-source`
first to pull them onto the shelf, then `aw team refresh` to re-materialize.

Flags:
- `-h, --help help for refresh`
- `--home string Agent home directory override (default: agents/instances/<name>)`
- `--runtime string Runtime harness to re-materialize for (claude-code|codex|pi|local-shell) (default "claude-code")`

## `team remove-agent`

### `team remove-agent`

Retire an agent from a team across the stores that hold its state.

It first deletes the agent's workspace record, which releases the task claims
held under it, and only then revokes its certificate. That order matters: an
agent can release its own claims until its certificate is revoked, and the
hosted removal deletes the same workspace record without releasing anything.

If the claims cannot be released the command stops before revoking and says
which store changed and which did not, rather than leaving an agent with no
credential and claims nobody can clear. To revoke access immediately and
accept that outcome, use `aw id team remove-member`.

Customer-controlled teams revoke with the local team controller key; hosted
aweb.ai teams call the cloud-mediated controller revoke endpoint.

STATUS VALUES. These are a contract; branch on them rather than on the prose.
Each says what its evidence supports, and the second column is the part that
matters, because the defect this command was built to remove was a status word
asserting more than the service had established.

  status (whole retirement)
    retired           every store reached the state retirement wants, and each
                      one established it. Exit 0.
    reported_retired  every store reached that state, but the certificate part
                      rests on a service reporting a no-op. It does NOT mean no
                      certificate exists. Exit 0. Confirm with agent-status.
    incomplete        a store did not reach that state; the per-store results
                      say which. Exit non-zero.

  certificate_result
    revoked                     this call revoked a certificate.
    already_revoked             the registry stated the certificate exists and
                                was already revoked. Only a registry says this;
                                it is never inferred from an absence.
    reported_nothing_to_revoke  the service reported it had nothing to revoke.
                                This says NOTHING about whether a certificate
                                exists: the hosted service answers from its own
                                membership records and may never consult the
                                registry, so a member holding a live certificate
                                with no hosted record is reported this way.

  per-store result: changed, unchanged, blocked, failed, not_attempted.
    changed and unchanged are terminal; the other three are not.

  claims_released is null when the server did not report a count, which is what
    a server older than that field does. Null is not zero.

Exit status answers one question only: did the request reach the service and get
an answer. It never carries a claim about certificate state. So on a
customer-controlled team, retiring a name that no longer resolves is an error
rather than a no-op, because that answer is indistinguishable from a request
that never arrived - while a registry saying already-revoked is success.

Flags:
- `--api-key string Team API key for hosted removal (overrides AWEB_API_KEY; workspace-bound API keys are rejected by hosted aweb)`
- `--aweb-url string Hosted aweb API URL override for cloud-mediated removal`
- `-h, --help help for remove-agent`
- `--registry string Registry origin override`
- `--team-id string Canonical team id (<name>:<namespace>) to remove from (defaults to active team)`

## `team replace-key`

### `team replace-key`

Replace a local team-scoped agent's did:key under locally-held team-controller authority.

This compare-and-swap operation updates the service roster, revokes the old
team certificate, registers a new certificate, and records the controller-authorized
transition. When a real local home has lost signing.key, --generate-new-key creates
and retains a replacement key without overwriting an existing one. Hosted teams require
the pending AC owner/admin integration or operator support.

Flags:
- `--aweb-url string Aweb service URL override`
- `--generate-new-key Generate a replacement signing key in --home when signing.key is absent (cannot be combined with --new-did-key)`
- `-h, --help help for replace-key`
- `--home string Agent home whose new signing identity is verified and where the replacement certificate is installed`
- `--new-did-key string Replacement local member did:key (required unless --generate-new-key is used)`
- `--old-cert-id string Old team certificate id (required without --home)`
- `--old-did-key string Expected current local member did:key (required)`
- `--registry string AWID registry URL override`
- `--team-id string Canonical team id (<name>:<namespace>; defaults to active team)`

## `team switch`

### `team switch`

Switch the active team for this identity

Flags:
- `-h, --help help for switch`

## `team up`

### `team up`

Launch local team agents in tmux. This is a local runtime convenience: it reads materialized agents/instances/<name> homes and starts one tmux window per supported interactive harness. Team definitions and profile provenance remain in aweb state and .aw/profile/ref.json.

Flags:
- `--attach Attach or switch to the tmux session after launch (default true)`
- `--dry-run Print the tmux launch plan without running it`
- `--force Start even when another process already has an agent home as its cwd`
- `--force-kill Allow --recreate to kill a tmux session that contains running agent windows`
- `-h, --help help for up`
- `--no-attach Do not attach or switch to the tmux session after launch`
- `--recreate Kill and recreate an existing tmux session`
- `--session string tmux session name (default: caller's session inside tmux, otherwise active team name or aw-team)`

## `whoami`

### `whoami`

Show the current identity

Flags:
- `-h, --help help for whoami`
- `--team string Override the selected team_id for this command`

## `a2a`

### `a2a`

Inspect and call A2A agents

Subcommands:
- `cancel` Cancel an A2A task
- `card` Fetch and verify an A2A Agent Card
- `publish` Publish an A2A Agent Card route to AWID
- `send` Send a task message to an A2A agent
- `status` Fetch an A2A task

Flags:
- `-h, --help help for a2a`

## `a2a cancel`

### `a2a cancel`

Cancel an A2A task

Flags:
- `-h, --help help for cancel`

## `a2a card`

### `a2a card`

Fetch and verify an A2A Agent Card

Flags:
- `--address string aweb address to verify through AWID, e.g. acme.com/help`
- `-h, --help help for card`
- `--registry-url string AWID registry URL for verification`

## `a2a publish`

### `a2a publish`

Publish an A2A Agent Card route to AWID

Flags:
- `--address string aweb address to publish; defaults to current identity address`
- `--assertion-id string Publication assertion id override`
- `--card-revision string Card revision recorded in AWID; defaults to Agent Card version`
- `--default-for-host Mark this route as the default A2A route for the host`
- `--delegation-id string Bridge delegation id override`
- `--expires-days int Publication/delegation lifetime in days (default 30)`
- `--gateway-identity string did:aw of the A2A gateway identity; defaults to current identity for direct publication`
- `-h, --help help for publish`
- `--registry-url string AWID registry URL override`
- `--route-id string Route id override; defaults to the card URL route`
- `--rpc-url string RPC URL override; defaults to supportedInterfaces[0].url`

## `a2a send`

### `a2a send`

Send a task message to an A2A agent. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--context string A2A context ID`
- `--data string Additional JSON metadata object`
- `-h, --help help for send`
- `--no-wait Return immediately after task creation`
- `--wait Wait for terminal or interrupted task state`

## `a2a status`

### `a2a status`

Fetch an A2A task

Flags:
- `-h, --help help for status`
- `--history int History length to request; -1 uses server default (default -1)`

## `chat`

### `chat`

Real-time chat

Subcommands:
- `extend-wait` Ask the other party to wait longer
- `history` Show chat history with a recipient name or address
- `listen` Wait for a message without sending
- `open` Open a chat session
- `pending` List pending chat sessions
- `read` Mark chat messages read by session and message id
- `send` Send a message to an exact chat session
- `send-and-leave` Send a message and leave the conversation
- `send-and-wait` Send a message and wait for a reply
- `show-pending` Show pending messages for a recipient name or address

Flags:
- `-h, --help help for chat`
- `--team string Override the selected team_id for this command`

## `chat extend-wait`

### `chat extend-wait`

Ask the other party to wait longer. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted wait extension; fails closed if encryption keys are missing`
- `-h, --help help for extend-wait`
- `--plaintext Send explicit server-readable plaintext wait extension (currently the default)`

## `chat history`

### `chat history`

Show chat history with a recipient name or address

Flags:
- `-h, --help help for history`
- `--limit int Maximum messages to fetch (default 1000)`
- `--message-id string Fetch one message by id when using --session-id`
- `--session-id string Fetch chat history by session id instead of recipient`
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
- `--body string Body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send`
- `--leave Leave the conversation after sending`
- `--plaintext Send explicit server-readable plaintext chat (currently the default)`
- `--session-id string Existing chat session id`

## `chat send-and-leave`

### `chat send-and-leave`

Send a message and leave the conversation. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send-and-leave`
- `--plaintext Send explicit server-readable plaintext chat (currently the default)`
- `--start-conversation Start a new conversation instead of continuing an existing one`

## `chat send-and-wait`

### `chat send-and-wait`

Send a message and wait for a reply. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send-and-wait`
- `--plaintext Send explicit server-readable plaintext chat (currently the default)`
- `--start-conversation Start conversation (5min default wait)`
- `--wait int Seconds to wait for reply (default 120)`

## `chat show-pending`

### `chat show-pending`

Show pending messages for a recipient name or address

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
- `--agent string Agent name to send signal to`
- `-h, --help help for interrupt`

## `control pause`

### `control pause`

Send pause signal to an agent

Flags:
- `--agent string Agent name to send signal to`
- `-h, --help help for pause`

## `control resume`

### `control resume`

Send resume signal to an agent

Flags:
- `--agent string Agent name to send signal to`
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
- `show` Show a mail conversation or exact message

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

List inbox messages, newest first and unread only by default. Messages shown by this command are acknowledged as read.

The response is one bounded page. Text output reports when more messages exist and prints a continuation command; JSON output carries has_more and next_cursor. Pass the returned value to --cursor to continue without overlap.

Flags:
- `--cursor string Continue from next_cursor in a previous inbox response`
- `-h, --help help for inbox`
- `--limit int Max messages per page (default 50)`
- `--show-all Show all messages including already-read`

## `mail reply`

### `mail reply`

Reply to an existing mail conversation

Flags:
- `--body string Body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted mail; fails closed if encryption keys are missing`
- `-h, --help help for reply`
- `--plaintext Send explicit server-readable plaintext mail (currently the default)`
- `--priority string Priority: low|normal|high|urgent (default "normal")`
- `--subject string Subject`

## `mail send`

### `mail send`

Send a message to another agent

Flags:
- `--body string Body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--conversation-id string Existing mail conversation to continue`
- `--e2ee Send E2E encrypted mail; fails closed if encryption keys are missing`
- `-h, --help help for send`
- `--plaintext Send explicit server-readable plaintext mail (currently the default)`
- `--priority string Priority: low|normal|high|urgent (default "normal")`
- `--subject string Subject`
- `--to string Recipient name within the active team, or a routable address`
- `--to-address string Recipient address (domain/name)`
- `--to-did string Recipient stable identity (did:aw:...)`

## `mail show`

### `mail show`

Show mail by conversation or exact message ID.

With --message-id, one unique message is selected. The conversation-window direction and 500-message ceiling below do not apply.

With --conversation-id, --limit caps how many messages are returned and defaults to 200. The messages returned are the OLDEST ones, so on a conversation longer than the limit the newest messages are the ones missing - which is the opposite of what someone checking for recent mail expects.

aw mail inbox windows from the other end and has a different default and ceiling. Do not carry an expectation from one command to the other.

To read a whole conversation, pass --limit above its length and check the returned count. If it equals the limit, there may be more; raise it and re-run, up to 500. At the 500-message ceiling, an exact full window cannot establish completeness. The conversation endpoint rejects higher limits and has no paging flag, so a conversation longer than 500 messages cannot be returned whole by this command.

Flags:
- `--conversation-id string Mail conversation to inspect`
- `-h, --help help for show`
- `--limit int For --conversation-id, max messages from the OLDEST end; exact --message-id reads are not windowed (default 200)`
- `--message-id string Legacy mail message to inspect`

## `agent`

### `agent`

Inspect local materialized agent homes under agents/instances/<name>.

Subcommands:
- `profile` Inspect the Library profile recorded in a local agent home

Flags:
- `-h, --help help for agent`

## `agent profile`

### `agent profile`

Inspect the Library profile recorded in a local agent home

Subcommands:
- `show` Show the recorded profile ref/snapshot (.aw/profile/ref.json) for a materialized agent

Flags:
- `-h, --help help for profile`

## `agent profile show`

### `agent profile show`

Show the Library profile a local agent home was materialized from - the blueprint and profile refs, versions, and content digests recorded in .aw/profile/ref.json. This is what `aw team refresh` updates and what the materialize seam records; it never asks a remote service which profile is in use.

Flags:
- `-h, --help help for show`
- `--home string Agent home directory override (default: agents/instances/<name>)`

## `instructions`

### `instructions`

Read and manage shared team instructions

Subcommands:
- `activate` Activate an existing shared team instructions version
- `history` List shared team instructions history
- `inject` Inject current team instructions into agent docs
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

## `instructions inject`

### `instructions inject`

Fetch the active team instructions through the current workspace and replace the
target's marker-delimited block. The exact target defaults to the current directory. This
explicit operation also adds the block when the target is not yet marked.

Flags:
- `-h, --help help for inject`

## `instructions reset`

### `instructions reset`

Reset shared team instructions to the server default

Flags:
- `-h, --help help for reset`

## `instructions set`

### `instructions set`

Create and activate a new shared team instructions version

Flags:
- `--body string Instructions Markdown body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read instructions Markdown from a file ('-' for stdin); safe for Markdown or command examples`
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
- `--mine Show only locks held by the current workspace name`
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

The role name is this workspace's operating responsibility on this team. It is
initialized from the materialized profile during setup, but remains independently mutable.
Changing it does not change which profile the workspace runs or grant additional authority.

Subcommands:
- `set` Set the current workspace operating role

Flags:
- `-h, --help help for role-name`
- `--team string Override the selected team_id for this command`

## `role-name set`

### `role-name set`

Set the current workspace operating role.

The role name is this workspace's operating responsibility on this team. It is
initialized from the materialized profile during setup, but remains independently mutable.
Changing it does not change which profile the workspace runs or grant additional authority.

Flags:
- `-h, --help help for set`

## `roles`

### `roles`

Read and manage team roles bundles and role definitions

Subcommands:
- `activate` Activate an existing team roles bundle version
- `add` Add or update one role in the active team roles bundle
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

## `roles add`

### `roles add`

Add or update one role in the active team roles bundle.

This is the novice-friendly way to build a roles bundle from resource-pack
role Markdown files one role at a time. It reads the active bundle, adds the
role, creates a new bundle version, and activates it.

Flags:
- `-h, --help help for add`
- `--playbook string Role playbook Markdown body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --playbook-file for Markdown or command examples`
- `--playbook-file string Read role playbook Markdown from a file ('-' for stdin); safe for Markdown or command examples`
- `--replace Replace an existing role with the same name`
- `--title string Human-readable role title (defaults to role name)`

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
- `--bundle-file string Read team roles bundle JSON from a file ('-' for stdin); safe for Markdown playbooks or command examples`
- `--bundle-json string Team roles bundle JSON. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --bundle-file for Markdown or command examples`
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
- `--reason string Reason for closing (replaces notes). Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --reason-file for Markdown or command examples`
- `--reason-file string Read closing reason from a file; safe for Markdown or command examples`

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

Add a comment to a task. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

Flags:
- `--body string Comment body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read comment body from a file; safe for Markdown or command examples`
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
- `--assignee string Assignee agent name`
- `--description string Task description. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --description-file for Markdown or command examples`
- `--description-file string Read task description from a file; safe for Markdown or command examples`
- `-h, --help help for create`
- `--labels string Comma-separated labels`
- `--notes string Task notes. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --notes-file for Markdown or command examples`
- `--notes-file string Read task notes from a file; safe for Markdown or command examples`
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
- `--assignee string Filter by assignee agent name`
- `-h, --help help for list`
- `--labels string Filter by labels (comma-separated)`
- `--parent string Filter by parent task ref`
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
- `--assignee string Assignee agent name (empty to unassign)`
- `--description string Description. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --description-file for Markdown or command examples`
- `--description-file string Read task description from a file; safe for Markdown or command examples`
- `-h, --help help for update`
- `--labels string Comma-separated labels`
- `--notes string Notes. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --notes-file for Markdown or command examples`
- `--notes-file string Read task notes from a file; safe for Markdown or command examples`
- `--parent string Parent task ref (empty to make root)`
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

## `plugin`

### `plugin`

Manage aw plugins

Subcommands:
- `install` Install a plugin into the trusted aw plugin directory
- `list` List installed plugins
- `remove` Remove an installed plugin
- `reserved-names` Emit reserved top-level aw app ids
- `update` Update an installed manifest plugin

Flags:
- `-h, --help help for plugin`

## `plugin install`

### `plugin install`

Install a plugin into the trusted aw plugin directory

Flags:
- `--app-id string App id to record in plugin provenance`
- `--app-version string App version to record in plugin provenance`
- `--dev-origin string Override the app origin to this base URL for a self-hosted or dev service; the request base URL becomes this, bypassing the manifest origin self-consistency check`
- `-h, --help help for install`
- `--manifest-version string Manifest version to record in plugin provenance`
- `--origin string App origin to record in plugin provenance`

## `plugin list`

### `plugin list`

List installed plugins

Flags:
- `-h, --help help for list`

## `plugin remove`

### `plugin remove`

Remove an installed plugin

Flags:
- `-h, --help help for remove`

## `plugin reserved-names`

### `plugin reserved-names`

Emit reserved top-level aw app ids

Flags:
- `-h, --help help for reserved-names`

## `plugin update`

### `plugin update`

Update an installed manifest plugin

Flags:
- `-h, --help help for update`

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

## `blueprint`

### `blueprint`

Inspect and manage Library blueprints

Subcommands:
- `inspect` Inspect a blueprint without importing or materializing it
- `materialize` Materialize one local blueprint profile into a local agent home
- `publish-profile` Publish one local blueprint profile to the team's private Library shelf

Flags:
- `-h, --help help for blueprint`

## `blueprint inspect`

### `blueprint inspect`

Inspect a blueprint without importing or materializing it

Flags:
- `-h, --help help for inspect`
- `--json Print machine-readable JSON`

## `blueprint materialize`

### `blueprint materialize`

Materialize one local blueprint profile into a local agent home

Flags:
- `--force Overwrite existing materialized files`
- `-h, --help help for materialize`
- `--json Print machine-readable JSON`
- `--profile string Profile id to materialize`
- `--target string Target local agent home directory`

## `blueprint publish-profile`

### `blueprint publish-profile`

Pack a profile from a local blueprint source and publish it to the team's private
Library shelf (create-shelf-profile). --profile is optional when the source has exactly
one profile and required when it has more than one. The request is signed with the
active team certificate (library:write).

Flags:
- `-h, --help help for publish-profile`
- `--json Print machine-readable JSON`
- `--profile string Profile id to publish (optional when the source has exactly one)`
- `--tag strings Tag to attach to the shelf profile (repeatable)`

## `session`

### `session`

Session-scoped coordination

Subcommands:
- `lease` Manage the principal's session admission lease

Flags:
- `-h, --help help for session`

## `session lease`

### `session lease`

Manage the principal's session admission lease

Subcommands:
- `acquire`
- `release`
- `renew`
- `status`
- `takeover` Explicit audited early takeover

Flags:
- `-h, --help help for lease`

## `session lease acquire`

### `session lease acquire`

Flags:
- `-h, --help help for acquire`
- `--session-id string Per-session identifier`
- `--session-key string Per-session secret (at least 32 characters; avoid shell history)`
- `--ttl-seconds int Lease TTL in seconds (default 300)`

## `session lease release`

### `session lease release`

Flags:
- `-h, --help help for release`
- `--session-id string Per-session identifier`
- `--session-key string Per-session secret (at least 32 characters; avoid shell history)`

## `session lease renew`

### `session lease renew`

Flags:
- `-h, --help help for renew`
- `--session-id string Per-session identifier`
- `--session-key string Per-session secret (at least 32 characters; avoid shell history)`
- `--ttl-seconds int Lease TTL in seconds (default 300)`

## `session lease status`

### `session lease status`

Flags:
- `-h, --help help for status`

## `session lease takeover`

### `session lease takeover`

Explicit audited early takeover

Flags:
- `-h, --help help for takeover`
- `--reason string Required audited reason`
- `--session-id string Per-session identifier`
- `--session-key string Per-session secret (at least 32 characters; avoid shell history)`
- `--ttl-seconds int Lease TTL in seconds (default 300)`
