---
title: "CLI command reference"
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
| Identity | `auth`, `custody`, `id`, `mcp-config`, `org`, `team`, `verify`, `whoami` |
| Messaging & Network | `a2a`, `beads-mail`, `chat`, `contacts`, `control`, `directory`, `events`, `gc-mail`, `heartbeat`, `inbound-mode`, `log`, `mail`, `room`, `wake` |
| Coordination & Runtime | `instructions`, `lock`, `notify`, `role-name`, `roles`, `task`, `work` |
| Utility | `app`, `audit`, `completion`, `doctor`, `help`, `hooks`, `plugin`, `upgrade`, `validate`, `version` |
| Additional Commands | `session`, `who` |

## Global Flags

- `--debug Log background errors to stderr`
- `-h, --help help for aw`
- `--human string Sign interactively as this locally enrolled human did:aw`
- `--human-domain string Namespace of the selected human ID`
- `--identity-home string Use this absolute credential directory (contains signing.key or grant.yaml; usually <workspace>/.aw, not its parent)`
- `--json Output as JSON`
- `--server-name string Server label for workspace commands; service URL for auth and admission`
- `--trace Trace redacted HTTP requests and responses to stderr`

## Errors under `--json`

A failed command run with `--json` that printed nothing else prints one
JSON line on stdout:

```json
{"error": {"code": "http_error", "message": "...", "http_status": 403, "detail": "..."}}
```

`code` is the stable contract. `message` is the text stderr prints, which
is not stable. stderr and the exit code are the same with or without
`--json`. For a server refusal (`http_error`, `alias_conflict`),
`http_status` and `detail` are present: `detail` is the server's string
`detail`, or the `message` of a coded detail, never its headers or any
other text. When the body names the server's own refusal code, the `code`
of a coded detail or a top-level `reason`, `reason` carries it, such as
`admin_required`; without one there is no `reason`. For
`recipient_custodial_no_e2ee`, `detail` lists the hosted
recipients' addresses; when the server refused the send, `http_status` is
422, and for several recipients `detail` is absent, because the server
does not say which recipient is hosted.

Under `--json`, stdout carries one document. A command that already
printed its own output, such as a partial result, and then failed keeps
that output and prints no envelope. The exit code is therefore the
failure signal: check it first, then read `error.code` when stdout is an
envelope.

| Code | Meaning |
| --- | --- |
| `error` | No stable class. |
| `http_error` | An aweb server or AWID registry refused the request. |
| `alias_conflict` | The alias is already held by another active member of the team. |
| `outcome_unknown` | A mutating request timed out before its response; it may have applied. Check current state before retrying. |
| `encryption_key_missing` | An encrypted message needs a local encryption private key this identity does not have. |
| `decrypt_failed` | An encrypted message could not be opened or validated. |
| `recipient_custodial_no_e2ee` | An end-to-end encrypted send names a hosted agent, whose signed encryption key assertion says aweb's service holds its key; nothing was sent. Send it again without `--e2ee`. |
| `team_not_hosted` | The hosted self-release path is unavailable for this team. Own non-hosted local retirement uses the controller receipt flow. |
| `global_identity` | `aw workspace delete` through an external identity home: a global identity's alias is released by its team, not by itself. |
| `not_own_workspace` | `aw workspace delete` through an external identity home names another workspace. |
| `no_workspace_credential` | `aw workspace delete` through an external identity home has no member credential to act with. |

Offline status, additional refusal codes, wake readiness and local retirement
outcomes are documented in the [CLI integration contract](cli-integration-contract.md).

`aw wake status --json` describes a receive stream's error the same way:
beside the `stream_error` text, `stream_error_detail` holds its `code`,
`http_status`, `detail` and `reason`.

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
- `--controller-claim-file string Controller-signed claim artifact from aw id team claim-human-request (member credential still required)`
- `--email string Email address to attach to the current CLI-created account`
- `-h, --help help for claim-human`
- `--mock-url string Override the bootstrap base URL for local development`
- `--username string Override the default dashboard username derived from the registered domain`

## `init`

### `init`

Initialize the current directory using one of the supported
team-architecture flows:

- connect with an existing team certificate already present in .aw/
- add an agent to the existing team selected by AWEB_API_KEY
- create a hosted aweb.ai account when this directory is still clean
- use --byod to create an identity under a domain you control

By default, init creates or updates the clearly marked aweb section in
AGENTS.md or CLAUDE.md. Use --do-not-touch-agents-md to skip that file update.

A supplied AWEB_API_KEY, including a workspace key returned by CLI signup,
joins the team selected by the service. An aw team invite can also join it.
Creating a new account/team in a fresh directory creates a separate team.
Use aw team invite / aw team join to add a member to that team.

The channel plugin or host wake broker is the preferred notification path.
--setup-hooks explicitly enables a Claude Code chat-only polling fallback:
notices arrive after tool calls, with no mail or idle wake-up support.
After confirming channel/broker delivery, use --remove-notify-hook on its own
for backed-up removal of exact aw notify PostToolUse entries from the current
directory's and, inside a git repo, the repository root's .claude/settings.json.
Init and upgrades never remove them implicitly.

Use --join-from to create a child in a fresh directory from a selected native
creator workspace.

Flags:
- `--admission-team-id string Add an agent through host human admission for this explicit team ID`
- `--agent-type string Runtime label (default: AWEB_AGENT_TYPE or agent; human kind is verified by the server)`
- `--aweb-url string Base URL for the aweb server used by aw init (overrides AWEB_URL)`
- `--awid-registry string Base URL for the awid registry used by aw init (overrides AWID_REGISTRY_URL)`
- `--byod Use a domain you control instead of hosted aweb.ai onboarding`
- `--do-not-touch-agents-md Do not create or update AGENTS.md or CLAUDE.md during init`
- `--domain string BYOD domain to use with --byod`
- `--expect-account string Expected hosted account ID for workspace-team or admission init`
- `--global Create an addressed self-custodial global identity instead of the default local workspace`
- `-h, --help help for init`
- `--human-name string Human name (agents: explicit only; humans: AWEB_HUMAN or $USER)`
- `--inbound-mode string Inbound delivery mode for a global identity (open|team-and-contacts|contacts-only). Only valid with --global.`
- `--inject-docs Inject aw coordination instructions into CLAUDE.md and AGENTS.md`
- `--invite string Join this invite with an independently selected creator`
- `--join-from string Add an agent to a team by minting one invite from this existing workspace or identity home`
- `--join-team string Team ID to use with --join-from when the source has more than one membership`
- `--name string Identity/member name (global address name with --global, local routing name otherwise)`
- `--new-account Explicitly create a new hosted aweb.ai account`
- `--new-team Explicitly create a new self-hosted/BYOD team`
- `--org string Organization slug or ID for --workspace-team`
- `--parent string Same-machine creator home for a fresh child`
- `--print-exports Print shell export lines after JSON output`
- `--remove-notify-hook Remove only the exact aw notify PostToolUse hook from current directory and repository root settings, with backups (standalone local action)`
- `--role string Compatibility alias for --role-name`
- `--role-name string Workspace role name (must match a role in the active team roles bundle)`
- `--setup-channel Set up Claude Code aweb-channel plugin for real-time coordination`
- `--setup-hooks Enable Claude Code chat-only polling after tool calls (explicit fallback; no mail or idle wake-ups)`
- `--team string Name of the team --new-team creates on a local (localhost) awid registry (default: default)`
- `--token-file string Read the join invitation from this private file instead of --invite`
- `--token-stdin Read one join invitation from stdin through EOF (max 65536 bytes)`
- `--url string Base URL for the aweb server used for init, bootstrap, and hosted onboarding flows`
- `--username string Hosted username to create`
- `--workspace-key string OATS canonical format-1 workspace key for --workspace-team`
- `--workspace-team Ensure a workspace's default team using explicit --identity-home and --workspace-key`
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
and team certificate in this directory. With --identity-home, initialize and
bind the selected external identity root instead of the caller's current
directory. This command only connects this workspace to the service; it does
not create identities, create teams, or change AWID team membership.

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
- `delete` Delete a local workspace and its local identity, retiring yourself when it is your own
- `migrate-multi-team` Rewrite a legacy single-team workspace into the canonical multi-team shape
- `status` Show coordination status for the current workspace/identity and team

Flags:
- `-h, --help help for workspace`
- `--team string Override the selected team_id for this command`

## `workspace add-worktree`

### `workspace add-worktree`

Legacy convenience for existing users: create a sibling git worktree and initialize a new coordination workspace in it.

New setup flows should prefer explicit git worktree/filesystem steps followed by aw init, invite/join, or service init primitives unless this command is reduced to a transparent wrapper with no identity/team orchestration.

If the service cannot report the team for AWEB_API_KEY, creation uses the current workspace's existing authority.

Flags:
- `-h, --help help for add-worktree`
- `--name string Override the default workspace/member name`

## `workspace connect`

### `workspace connect`

Connect this workspace to a service using the existing .aw signing key and team certificate in this directory.

With --identity-home, connect the selected external identity root and bind the
service workspace state under that root, not the caller's current directory.
This is the first-class workspace connection verb. It does not create identities,
create teams, or change AWID team membership. It is equivalent to `aw service init`.

Flags:
- `-h, --help help for connect`
- `--role string Optional role name for this workspace`
- `--service string Service URL to connect to`
- `--team string Canonical AWID team id to activate before connecting`

## `workspace delete`

### `workspace delete`

Delete a local workspace and its local identity.

Deleting YOUR OWN workspace with a local identity can retire its membership.
On a hosted team, the service controller revokes the membership certificate.
On a non-hosted team, the command deletes the workspace while the member
credential is valid, saves a local receipt, then revokes with the local team key.
If revocation cannot finish, retain the home and receipt and follow next_step.
Retrying uses the receipt and performs only the remaining controller operation.

Read alias_released in the output, not identity_deleted. Deleting local state
says nothing about the membership certificate, and an active certificate is what
makes a rejoin under the same name fail. alias_released_reason says why:

  not_own_workspace        the target is not the workspace you are running as
  controller_key_missing  workspace deleted; give next_step to the team key holder
  retired_revocation_pending  workspace deleted; retry using the retained receipt
  global_identity          global identities are retired by team-authorized removal
  no_workspace_credential  no workspace-bound key and no team certificate in local
                           config to authenticate with

When this command can retire you, it does not fall back to a plain delete: a
failure is reported as a failure, because a success report for a retirement that
did not happen is what leaks names.

With --identity-home, own local retirement uses the selected home. Global and
other-member targets fail closed instead of falling back to generic deletion.

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

## `auth`

### `auth`

Authenticate this host aw CLI to your aweb account.

Credentials are stored only in the host aw config directory, not in workspace or identity homes.

Subcommands:
- `login` Start browser-based device login for this host aw CLI
- `logout` Revoke host CLI account-auth tokens and remove local credentials
- `status` Show host CLI account-auth status without printing tokens

Flags:
- `-h, --help help for auth`

## `auth login`

### `auth login`

Start browser-based device login for this host aw CLI

Flags:
- `-h, --help help for login`
- `--scope string CLI authorization scopes (cli.workspace_team cli.org_create by default; cli.team_admission is separate) (default "cli.workspace_team cli.org_create")`
- `--timeout duration Maximum time to wait for browser approval (default 10m0s)`

## `auth logout`

### `auth logout`

Revoke host CLI account-auth tokens and remove local credentials

Flags:
- `-h, --help help for logout`
- `--scope string CLI authorization scope to revoke (default "cli.workspace_team")`

## `auth status`

### `auth status`

Show host CLI account-auth status without printing tokens

Flags:
- `-h, --help help for status`
- `--scope string CLI authorization scope to inspect (default "cli.workspace_team")`

## `custody`

### `custody`

Local resident custody service

Subcommands:
- `serve` Serve local resident custody operations
- `status` Probe local resident custody service
- `stop` Stop local resident custody service

Flags:
- `-h, --help help for custody`

## `custody serve`

### `custody serve`

Serve local resident custody operations

Flags:
- `-h, --help help for serve`

## `custody status`

### `custody status`

Probe local resident custody service

Flags:
- `-h, --help help for status`

## `custody stop`

### `custody stop`

Stop local resident custody service

Flags:
- `-h, --help help for stop`

## `id`

### `id`

Identity lifecycle, registry, settings, and key management

Subcommands:
- `address` Manage addresses for the current global identity
- `addresses` List registry addresses for a did:aw (defaults to the current global identity)
- `cert` Team certificate operations
- `child` Invite, receive and approve requests from children you issue
- `create` Create a global identity by claiming a namespace address
- `encryption-key` Manage local E2E encryption keys for this self-custodial identity
- `grant` Scoped, revocable session grants derived from this identity
- `human` Human identities in a namespace's identity tree
- `log` Show a global AWID DID log
- `namespace` Protocol/admin namespace controller and address operations
- `parent` Request and import your own certificate from a parent
- `proof` Export a message signed by your human key with its saved evidence
- `register` Register the current global identity at the configured registry
- `registry-trust` Trust an operator-selected registry recorded in this identity home
- `request` Make a DIDKey-signed HTTP request with the local identity key
- `resolve` Resolve a did:aw to its current did:key
- `revoke` Revoke a registered identity's ID-tree authority
- `rotate-key` Rotate the current global identity signing key at the registry
- `show` Show the current identity and registry status
- `sign` Sign user data with a domain-separated local identity signature
- `status` Inspect local identity, membership, binding and unfinished initialization
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
- `--team string Override the selected team_id for this command`

## `id child`

### `id child`

Invite, receive and approve requests from children you issue

Subcommands:
- `approve` Sign the certificate for one received request
- `invite` Fix an invitation for one child before it exports its request
- `pending` List the requests bound to your invitations
- `receive` Receive a child's request against one of your invitations
- `refuse` Refuse one received request without signing
- `show` Show one received request and the fingerprint of its key

Flags:
- `-h, --help help for child`

## `id child approve`

### `id child approve`

Sign the certificate for one received request and write the response
(--out, or stdout). A human child needs your confirmation at an interactive
terminal that its key fingerprint matches what the recipient told you over a
separate trusted channel; nothing else approves it.

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Act as the namespace root of --domain, with this machine's controller key`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for approve`
- `--out string Where to write the response (- for stdout) (default "-")`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

## `id child invite`

### `id child invite`

Fix an invitation for one child of --kind, and print what the recipient
needs to export its request: invitation ID, parent, domain, kind and expiry.
--recipient is your private note of who it is for; it is never exported.
An invitation expires after --expires (7 days by default).

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Act as the namespace root of --domain, with this machine's controller key`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `--expires duration How long the invitation stays open (default 168h0m0s)`
- `-h, --help help for invite`
- `--kind string Kind of the child: human or agent`
- `--recipient string Your private note of who the invitation is for`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

## `id child pending`

### `id child pending`

List the requests bound to your invitations

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Act as the namespace root of --domain, with this machine's controller key`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for pending`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

## `id child receive`

### `id child receive`

Receive a child's request against one of your invitations

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Act as the namespace root of --domain, with this machine's controller key`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for receive`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

## `id child refuse`

### `id child refuse`

Refuse one received request without signing

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Act as the namespace root of --domain, with this machine's controller key`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for refuse`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

## `id child show`

### `id child show`

Show one received request and the fingerprint of its key

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Act as the namespace root of --domain, with this machine's controller key`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for show`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

## `id create`

### `id create`

Create a self-custodial global identity in .aw/ by claiming DOMAIN/NAME
in a namespace you control. This mints a did:aw, stores the local signing
key material, and atomically claims the global address in AWID.

With --org and --team-id, create an ordinary hosted member
in an explicit fresh --identity-home root. The local key stays in that root;
the hosted operator authorizes the address and certificate. Retry with the
same root and parameters after a lost response. A completed root refuses
another creation; use ordinary commands with its installed identity.
Pass inbound-mode --json's team_id unchanged as --team-id; Cloud resolves
the service UUID or canonical name:namespace within the chosen organization.
No namespace controller key
or API key is used for that path. With --owner-identity-home, the existing
organization owner's native key authorizes creation using its bound service;
otherwise the host's human CLI login authorizes it.

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--domain string Namespace domain for the global identity address`
- `-h, --help help for create`
- `--human-parent string Parent person did:aw, who signs locally in --domain (--human ID --human-domain DOMAIN may also name them; with --org, a registered account human)`
- `--inbound-mode string Hosted inbound delivery mode (default team-and-contacts; requires --org)`
- `--local Create a key-only local identity (a did:key registered nowhere) in an explicit fresh --identity-home; resumable, and a rerun returns it`
- `--name string Global identity name (address name under --domain)`
- `--no-address Create a registered identity with no address in an explicit fresh --identity-home, registering its own did:aw at --registry; resumable`
- `--org string Hosted organization slug or ID (human CLI login or explicit owner principal)`
- `--owner-identity-home string Authorize --org creation with this owner's absolute native credential directory`
- `--registry string Registry origin override (default: api.awid.ai)`
- `--root-parent Have this machine's namespace controller issue a humanless agent (BYOT only)`
- `--skip-dns-verify Skip the DNS TXT verification prompt and lookup`
- `--team-id string Chosen hosted team service UUID or canonical name:namespace (requires --org)`

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

## `id grant`

### `id grant`

Scoped, revocable session grants derived from this identity

Subcommands:
- `list` List this identity's session grants
- `mint` Mint a session grant and write a self-contained grant home
- `revoke` Revoke a session grant
- `show` Show one session grant

Flags:
- `-h, --help help for grant`
- `--team string Override the selected team_id for this command`

## `id grant list`

### `id grant list`

List this identity's session grants

Flags:
- `-h, --help help for list`

## `id grant mint`

### `id grant mint`

Mint a session grant and write a self-contained grant home

Flags:
- `--app-tool stringArray Select app:verb tools for this grant; requires plugin install approval for this team's current installation`
- `--bundle stringArray Grant scope bundle, repeatable or comma-separated (normal-agent)`
- `--custody-socket string Resident custody Unix socket path to write into grant.yaml, or auto for the resident identity home's default custody socket`
- `-h, --help help for mint`
- `--label string Optional label for the grant`
- `--out string Directory to write the grant home (created fresh; a non-empty directory is refused)`
- `--scope stringArray Grant scope, repeatable or comma-separated (mail.read, mail.send, chat.read, chat.send, events.read, coord.read, coord.write, presence.write, contacts.read, contacts.write)`
- `--ttl string Grant duration: never (revocation-only) or a duration from 60s to 720h (default "never")`

## `id grant revoke`

### `id grant revoke`

Revoke a session grant

Flags:
- `-h, --help help for revoke`

## `id grant show`

### `id grant show`

Show one session grant

Flags:
- `-h, --help help for show`

## `id human`

### `id human`

Human identities in a namespace's identity tree

Subcommands:
- `add` Ask your issuer to add a new person
- `enroll` Enroll an approval key for your new or existing human ID
- `init` Create your human ID in a namespace
- `register` Register your issued human certificate with your own key

Flags:
- `-h, --help help for human`

## `id human add`

### `id human add`

Run as a current person with --human ID --human-domain DOMAIN.
With no human_approval requirement, the issuer returns a certificate without
contacting an approval service or requiring your enrollment. Give it to the new
person, who runs aw id human register FILE with their own human selector.
If the organisation requires approval, you must be enrolled; the issuer asks
for human approval through the existing 428 protocol. Review the exact act in your approval-service browser page. Every
identity signature uses your keychain key, unlocked once at this terminal for
this command, including the approval wait. The key is wiped at command exit.
When approval is required, an agent requester uses the generic aw id request
command instead; agents cannot use the unconfigured issuance path.

The configured approval path returns a pending intent; it never enrolls the new person. The new
person first prepares their own key with aw id human init and gives you its ID
and key. Give them the resulting FILE. They run aw id human enroll --intent FILE
--issuer URL with their own --human ID --human-domain DOMAIN, then register and
confirm their approval key in the browser named by that signed intent.

The first person is still bootstrapped by the organization's operator on the
holder host. There is no operator network route.
An expired approval can be archived with --restart to ask for a fresh approval.
It never extends or reuses the old approval deadline.

Flags:
- `--approval-origin string Optional equality pin for your enrolled approval service`
- `-h, --help help for add`
- `--identity-key string New person's prepared identity did:key`
- `--issuer string Issuer HTTPS origin; defaults to your saved enrollment`
- `--out string New pending-intent file; default is JSON on stdout`
- `--person string New person's prepared did:aw`
- `--restart Archive an expired approval attempt and ask the issuer for a fresh request`

## `id human enroll`

### `id human enroll`

Run this yourself with --human ID --human-domain DOMAIN at a terminal.
Your identity key stays in the passphrase-protected OS keychain. For a new person,
first run aw id human init and obtain a pending --intent FILE from your issuer.
For an existing person, --issuer URL asks that issuer for an enrollment intent.
After the first use, the issuer is remembered with your human record.
The first signature asks once for your passphrase. The key stays unlocked in
memory for this command, including browser and "type yes" waits, and is wiped
when the command ends or is interrupted. Each signature is described on stderr.

The signed intent supplies the approval service and RP ID; --approval-origin is
an optional equality pin. You see the service before opening its enrollment page.
Register and confirm your key in that browser, then continue at this terminal.
Interrupted commands resume their original enrollment. After expiry, use --restart
to preserve the old attempt and start again; a new person needs a fresh intent.
Once confirmation is saved, resume activation without --restart, even after expiry.
Register a second approval key in the same browser enrollment before continuing.
Lost-key replacement is not implemented: loss of your only key requires the
operator to issue a new ID and revoke the old one. Enrollment of an existing
person never adds or changes a creation claim.

Next: use aw id proof --message-file FILE --out proof.json, then give proof.json
to anyone; they run plain aw verify proof.json on their machine.

Flags:
- `--approval-origin string Optional pin; must equal the service in the issuer's signed intent`
- `-h, --help help for enroll`
- `--intent string Pending signed enrollment intent handed to a new person by the issuer`
- `--issuer string Your issuer's HTTPS origin; remembered after first use`
- `--restart Archive an expired unconfirmed attempt and start fresh; never replace saved confirmation`

## `id human init`

### `id human init`

Create your human ID in --domain. With --as-root the namespace controller on
this machine issues its certificate now. Without it, the human is only
prepared: give the public ID and key to your issuer. With a holder, its
operator hands you an issued FILE for `aw id human register FILE`, or
a pending intent for `aw id human enroll --intent FILE --issuer URL`.
Enrollment asks you to register and confirm a key in the named browser.
The existing `aw id parent request` exchange is also supported.

The human key is kept in the OS keychain, encrypted under a passphrase you
choose; person commands unlock it once on the terminal and wipe it at exit. This needs
a human at an interactive terminal: it refuses without one and inside an
agent runtime. A run that fails resumes from where it stopped.

Flags:
- `--another Create another human in a domain that already has one on this machine`
- `--as-root Issue the certificate with this machine's namespace controller key`
- `--domain string Namespace domain`
- `-h, --help help for init`
- `--registry string Registry origin, when the domain's _awid record names none (a record naming api.awid.ai counts as naming none)`

## `id human register`

### `id human register`

Register the certificate handed to you by your organization's operator or
approved issuer. Run this yourself with --human ID --human-domain DOMAIN at a
terminal; unlock once with your keychain passphrase for this command. Prepare your human ID
first with aw id human init. This registers your ID without enrolling an approval
key. Afterwards you may optionally run aw id human enroll, or create a portable
message with aw id proof --message-file FILE for anyone to check with aw verify.

Flags:
- `-h, --help help for register`
- `--registry string Optional registry pin; must agree with the domain's DNS record`

## `id log`

### `id log`

Show the AWID registry DID log for a global identity. The log records DID registration and key-rotation entries, verifies the returned chain, and reports the current did:key head.

Without arguments, the command reads the current global identity's did:aw. An explicit target may be a did:aw or a global address in `<domain>`/`<name>` form, which is resolved through the registry before reading its DID log. Local identities do not have registry-backed history; the command returns unsupported_registry_history for a current local identity instead of inventing hosted history.

With --json, status is OK for a verified log, BROKEN for unverifiable log data or address/log key mismatch, UNREACHABLE for registry fetch failures, and unsupported_registry_history for local identities.

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
- `reaffirm` Open the ID-tree epoch of a namespace registered before epochs existed
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

This is read-only. It looks up _awid.`<domain>`, loads the local namespace
controller key from ~/.awid/controllers/`<domain>`.key (or --controller-key),
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

## `id namespace reaffirm`

### `id namespace reaffirm`

Open the first ID-tree epoch of your own-domain namespace, registered before
epochs existed, by registering it again with its controller key. The registry
opens the epoch only for the controller it already stores, and only when the
_awid.`<domain>` TXT record names that key. A namespace that has an epoch is
left as it is.

Flags:
- `--controller-key string Namespace controller key path override`
- `--domain string Namespace domain`
- `-h, --help help for reaffirm`
- `--registry string Registry origin override`

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

## `id parent`

### `id parent`

Request and import your own certificate from a parent

Subcommands:
- `import` Import the parent's response to your request and register it
- `install` Install an already-issued chain for this home's own local key
- `refresh` Refresh current registered ancestry without re-signing your certificate
- `request` Export a certificate request against a parent's invitation

Flags:
- `-h, --help help for parent`

## `id parent import`

### `id parent import`

Verify the parent's response against your outstanding request, install the
chain and register it at AWID with your own key (--no-register leaves the
registration pending). A failed registration keeps the signed response;
run import again to retry it.

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--domain string Organization namespace for agent operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for import`
- `--no-register Install the certificate but leave its AWID registration pending`
- `--registry string Registry origin, when the domain's _awid record names none (a record naming api.awid.ai counts as naming none)`

## `id parent install`

### `id parent install`

Verify and install an already-issued public ID chain for this home's own did:key.
The home must have no chain or the identical chain. This does not adopt or re-parent.

Flags:
- `--domain string Organization namespace for agent operations (defaults to the chain)`
- `-h, --help help for install`
- `--registry string Registry origin when DNS names none`

## `id parent refresh`

### `id parent refresh`

Fetch and verify current registered ancestry, preserving local certificates below it.
For a branch with only local ancestors, use parent request --resign with the parent.

Flags:
- `--domain string Organization namespace for agent operations (defaults to the chain)`
- `-h, --help help for refresh`
- `--registry string Registry origin when DNS names none`

## `id parent request`

### `id parent request`

Export a certificate request against the invitation your parent fixed: its
--invitation-id, --domain and parent (--parent `<did:aw|did:key>` or --root-parent).
A local did:key parent can issue only a local did:key agent child.
Send the request file to the parent over your chosen channel, and tell them
the fingerprint shown here through a different trusted channel.

With --resign, a local agent (whose ID is its did:key) instead asks the parent
of the certificate it carries to re-sign it with the parent's current key,
after its key or ancestry changed.

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--domain string Organization namespace for agent operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for request`
- `--invitation-id string Invitation ID the parent gave you`
- `--out string Where to write the request (- for stdout) (default "-")`
- `--parent string did:aw or did:key of the parent identity`
- `--resign Ask the parent to re-sign the certificate this local agent carries`
- `--root-parent The parent is the namespace root of the selected organization`

## `id proof`

### `id proof`

Sign the text in --message-file with your human key at a terminal, asking for
its keychain passphrase once for this command and wiping the key at exit.
The JSON export carries your ID chain and any saved
enrollment evidence. It needs no team or mail server. Missing enrollment is not
a refusal and adds no evidence. Run with --human ID --human-domain DOMAIN.
Saved evidence rides only in proof files; ordinary mail does not yet carry it.

Next: give the output file to anyone. On another machine they run:
  aw verify FILE
No identity, credentials, initialization or registry flag is needed.

Flags:
- `-h, --help help for proof`
- `--message-file string Text file to sign as your message`
- `--out string New export file; default is JSON on stdout`

## `id register`

### `id register`

Register the current global identity at the configured registry

Flags:
- `-h, --help help for register`

## `id registry-trust`

### `id registry-trust`

Allow aw to reach an existing stored registry origin over private networks or HTTP. Only run this for an origin you operate or trust. The command does not change the selected registry.

Flags:
- `-h, --help help for registry-trust`

## `id request`

### `id request`

Make a DIDKey-signed HTTP request with the local identity key

Flags:
- `--approval-admission string File containing this caller's public admission certificate/chain`
- `--approval-origin string Known approval-service HTTPS origin for a needs-human response`
- `--approval-record string Private file retaining the original approval request and receipt`
- `--approval-requester string File containing this caller's canonical requester descriptor`
- `--approval-resume Resume the original request from --approval-record`
- `--body string Request body to send. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read request body from a file; safe for Markdown or command examples`
- `--header stringArray Additional header in 'Name: Value' form`
- `-h, --help help for request`
- `--raw Print only the upstream response body, byte for byte; the HTTP status line goes to stderr`
- `--sign string Additional signed fields (requires --team-auth)`
- `--sign-file string Read additional signed fields from a file (requires --team-auth)`
- `--team-auth Attach the active team certificate and sign a team-bound request payload`

## `id resolve`

### `id resolve`

Resolve a did:aw to its current did:key

Flags:
- `-h, --help help for resolve`

## `id revoke`

### `id revoke`

Revoke a registered identity under docs/id-certificates.md §3, signed by
the current identity (itself, or its current child), by --human `<did:aw>`
--human-domain D for a human on this machine, or by --as-root --domain D for the
namespace root. AWID decides whether the signer may revoke the identity.
The revocation takes effect at AWID's serialization time; only --as-root
may set an earlier --cutoff. This revokes ID-tree authority, not team
membership, addresses or DID key history.

When acting as a human, the first signature asks once for the selected person's
keychain passphrase at a real terminal. Each signature is described; the key
stays in memory for this command, including confirmation waits, and is wiped
on success, error or interruption. Another command asks again.

Flags:
- `--as-root Revoke as the namespace root of --domain, with this machine's controller key`
- `--cutoff string With --as-root: the earlier time (RFC 3339) the revocation takes effect from`
- `--domain string Organization namespace for agent or --as-root operations; with --human, the person's domain, as --human-domain`
- `-h, --help help for revoke`
- `--registry string Registry origin for --as-root, when the domain's _awid record names none`

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

Sign user data with a domain-separated local identity signature

Flags:
- `-h, --help help for sign`
- `--payload string JSON object to sign`
- `--payload-file string Read the JSON payload to sign from a file`

## `id status`

### `id status`

Read recorded local initialization state without contacting a service. This does not prove live registry or server status. Missing state is reported as incomplete; unreadable or invalid state is an error.

Flags:
- `-h, --help help for status`
- `--team string Override the selected team_id for this command`

## `id team`

### `id team`

Team membership plus protocol/admin certificate operations.

Everyday hosted setup normally uses invite and accept-invite. Controller-backed
commands such as add-member, remove-member, register, import-request,
cleanup-cloud, and delete are protocol/admin primitives for BYOT, controller
holders, service projection, or diagnostics.

Subcommands:
- `accept-invite` Accept a team invite and receive a membership certificate
- `add-member` Protocol/admin: add a member by signing a team certificate
- `check-invite` Inspect a saved invite and check its exact attempted certificate online
- `claim-human-request` Sign a prospective ownership claim with a local team controller key
- `cleanup-cloud` Protocol/admin: delete aweb Cloud's BYOT projection after registry team deletion
- `create` Create a hosted sibling team or a customer-controlled AWID team
- `delete` Protocol/admin: delete an AWID team using the namespace controller key
- `fetch-cert` Protocol/admin bridge: fetch and install an approved team certificate
- `import-request` Protocol/admin: create a signed BYOT import request for aweb cloud
- `install-cert` Install an issued team certificate file into an identity home
- `invite` Generate an invite token for a team
- `leave` Remove a team membership from this identity
- `list` List team memberships for this identity
- `members` List a team's members from AWID certificates
- `register` Protocol/admin: register or sync a customer-controlled team with a service
- `reissue-cert` Protocol/admin: mint and register a fresh certificate for the same member key
- `remove-member` Protocol/admin: remove a member by revoking a team certificate
- `request` Protocol/admin bridge: print the add-member command the team owner should run
- `resume-invite` Resume the exact saved certificate into its original recipient home
- `revoke-invite` Cancel an unused local controller invite; issued membership certificates remain valid
- `rotate-key` Rotate the team controller key, re-signing the team's AWID records with it
- `set-server` Publish the team's coordination server at AWID, signed by the team controller key
- `show-server` Show and verify the team's published coordination server
- `switch` Switch the active team for this identity

Flags:
- `-h, --help help for team`

## `id team accept-invite`

### `id team accept-invite`

Accept a team invite and receive a membership certificate.

Pass the token positionally, or read it with --token-file or --token-stdin
(only one). The file or stdin is read to EOF, up to 65536 bytes, and must
contain one token line; surrounding whitespace is trimmed. Close the pipe
after writing the token.

Scope is explicit: --local is the default, and --global reuses the existing
self-custodial global identity in this workspace. --address never selects
global scope; pass --global when presenting an existing owned address.

Hosted aw_inv_ tokens are redeemed through the cloud. Local hosted accepts
create a fresh local signing key and refuse to overwrite completed local
state. Global hosted accepts reuse identity.yaml's stored did:aw and signing
key; they do not mint a new did:aw just because this identity joins another
team. Hosted --global accepts may use --address for an owned address or
--no-address for did:aw-only membership. External --identity-home hosted
local accepts connect that root to the issuing service when the invite names
one; if connection fails, rerun the printed `aw --identity-home <root>
workspace connect --service <url>` recovery command without reusing the
invite. Other membership-only accepts can be connected later with `aw init`
or `aw workspace connect`.

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
- `--parent string Same-machine creator home for a fresh child, independent of the invite`
- `--token-file string Read the invite token from this file instead of an argument`
- `--token-stdin Read one invite token from stdin through EOF (max 65536 bytes)`

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

## `id team check-invite`

### `id team check-invite`

Inspect a saved invite and check its exact attempted certificate online

Flags:
- `-h, --help help for check-invite`
- `--invite-id string Saved local invite_id to inspect`

## `id team claim-human-request`

### `id team claim-human-request`

Write a controller claim JSON artifact to stdout. No member credential is created.
Cloud checks the registry's current controller before accepting ownership.
Submit this file from an existing member home with aw claim-human --controller-claim-file `<file>`.
The artifact is valid for five minutes; regenerate it if it expires.

Flags:
- `--email string Prospective owner's email`
- `-h, --help help for claim-human-request`
- `--namespace string Namespace domain`
- `--team string Team name`
- `--timestamp string RFC3339 timestamp (defaults to now; five-minute window)`
- `--username string Prospective owner's username`

## `id team cleanup-cloud`

### `id team cleanup-cloud`

Delete aweb Cloud's imported BYOT team projection using customer-held controller authority.

This command does not mutate AWID. In the normal path it signs the cleanup
request with ~/.awid/team-keys/`<namespace>`/`<team>`.key so aweb Cloud can
verify that the customer-controlled team controller authorized the projection
delete. If the team controller key has already been retired, use
--namespace-controller to sign with the namespace controller key; aweb Cloud
will verify that key against the _awid.`<domain>` DNS TXT controller for the
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

Create a hosted sibling team using the selected team certificate, or create
a customer-controlled AWID team using a local namespace controller key.

Without --namespace, creation is hosted. An explicit --namespace selects BYOT
and requires a local controller key and a native identity home. BYOT refuses
--team. --hosted explicitly selects hosted creation; a namespace supplied in
that mode must match the selected source team. The hosted service URL is printed
to stderr before the request.
Hosted authorization is decided by the service; no human login is performed.

Hosted creation generates a request UUID. Replay with the same --request-id and
parameters after an uncertain result; there are no automatic retries. A replay
returns the same team and replaces its unused invite. JSON includes the secret
invite token; text hides it unless --show-token is set. The caller is not joined.
Accept into `<fresh-directory>`/.aw, then run aw init from that directory with
AWEB_IDENTITY_HOME unset.

Flags:
- `--display-name string Team display name`
- `-h, --help help for create`
- `--hosted Create a hosted sibling using the selected team certificate`
- `--name string Team name`
- `--namespace string Namespace domain`
- `--org string Hosted organization slug or ID (requires aw auth login)`
- `--registry string Registry origin override`
- `--request-id string Hosted create UUID (reuse the same UUID and parameters to replay)`
- `--show-token Print the hosted invite token in text output (JSON includes it)`
- `--team string Override the selected team_id for this command`

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

## `id team install-cert`

### `id team install-cert`

Install an issued team membership certificate file into the explicit
--identity-home whose identity it names. The certificate is checked against
the registry before anything is written; then `aw service init` connects
the home's workspace.

Running it again with the same certificate reports already_installed and
completes an install that was interrupted. Refusals, with their --json codes:
  certificate_invalid        the file is not a team certificate, or the registry reports
                             a status for it that aw does not know
  member_mismatch            it names another key, did:aw or scope than the home's identity
  team_key_not_current       it is signed by a key that is not the team's current key
  certificate_bad_signature  its signature does not verify under that key
  certificate_revoked        the registry has revoked it
  certificate_unregistered   the registry does not hold it for this member
  certificate_conflict       the home holds another certificate for the team, or, for a
                             local identity, any membership of another team
  registry_unavailable       the registry could not be read; retrying may succeed

Flags:
- `--certificate string Certificate file to install`
- `-h, --help help for install-cert`
- `--registry string Registry origin the team is read from (default: the configured registry)`

## `id team invite`

### `id team invite`

Generate an invite token for a team.

Defaults to the active local team when --team and --namespace are omitted.
Invites create local workspace members unless --member-global is set. Hosted teams use cloud
invite authority; local-controller teams use the local team controller key.

Flags:
- `--expires duration Controller invite lifetime (default 24h; maximum 720h)`
- `--for-human string Admit agents whose verified nearest human is this did:aw person`
- `-h, --help help for invite`
- `--member-global Create global member invite`
- `--member-local Create local workspace member invite (default)`
- `--namespace string Namespace domain`
- `--preflight Show the mint authority without creating a token or child invitation`
- `--team string Team name`
- `--team-id string Canonical team ID; use instead of --team and --namespace`

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

Grant homes read their bound team's service roster: agents only (people are not included),
without certificate IDs or issued/revoked metadata. --include-revoked and
--registry are not supported in grant homes.

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

## `id team reissue-cert`

### `id team reissue-cert`

Mint, register, and (optionally) install a fresh team certificate for an existing
member, keeping the member's did:key, alias, and identity scope unchanged.

This is the remedy for a lost or never-registered certificate blob: the signed
blob cannot be reconstructed, so the team controller signs a fresh certificate
(new certificate id, fresh issued_at) for the same member key. If the registry
holds an active certificate for the alias, it is revoked first and the fresh one
is registered after, so the registry's one-active-certificate-per-alias
constraint is never violated. If none is registered, the fresh certificate is
simply registered. Re-running after a partial failure is safe: a run that
revoked but died before registering finds no active certificate and registers;
a run against an already-reissued member revokes the current certificate and
swaps in a fresh one.

Revoking the old certificate invalidates any grants issued under it, and the
member's server projection refreshes at its next certificate-authenticated
connect, so expect the member to reconnect.

This is NOT key rotation: the member keeps its did:key, and the command refuses
to run when the registered member key differs from the one attested. For a lost
or compromised member KEY, use `aw team admin replace-key` instead.

Requires the locally-held team controller key (BYOT/local-controller teams).
Hosted aweb.ai teams keep the controller key in cloud custody; hosted
re-issuance runs through the hosted service or operator support.

Pass --home to verify the member's local home and install the fresh blob there;
without --home the command prints the blob and where the member must place it.

Flags:
- `--address string Global member address when no registered certificate states it; requires --did-aw`
- `--did string Member did:key the fresh certificate binds (required unless --home is supplied)`
- `--did-aw string Global member did:aw when no registered certificate states it`
- `--global Assert global identity scope`
- `-h, --help help for reissue-cert`
- `--home string Member home whose signing key attests the did:key and where the fresh certificate is installed`
- `--local Assert local identity scope (default when no registered certificate states it)`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

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

Print the public add-member command for the team controller.

On a fresh worker, --create-local-key prepares a self-custodial local key
without contacting a registry or server. It accepts only an empty identity
home or a valid signing.key alone; retries reuse that key. Existing identity
state must use request without the flag. Select the current directory's .aw
or an explicit absolute --identity-home; an inherited AWEB_IDENTITY_HOME is
not a preparation destination. Unsafe or symlinked paths refuse.

Preparation writes only signing.key (0600). It grants no membership, address
or global identity. JSON adds status=prepared, identity_scope=local,
custody=self, identity_home and key_created. The home is a custody locator,
not a security boundary.

Have the controller run the printed add-member command, then use its
certificate ID with id team fetch-cert on this machine, selecting the same
identity home. Connect afterward with aw workspace connect --service `<url>`.
Without --create-local-key, request remains read-only and requires an
existing signing key.

Flags:
- `--create-local-key Prepare a local key in an empty or key-only identity home; membership still requires controller approval`
- `-h, --help help for request`
- `--name string Suggested member name for the new team membership`
- `--team string Canonical team ID (<name>:<domain>)`

## `id team resume-invite`

### `id team resume-invite`

Resume the exact saved certificate into its original recipient home

Flags:
- `-h, --help help for resume-invite`
- `--invite-id string Saved invite_id whose exact issuance is resumed`

## `id team revoke-invite`

### `id team revoke-invite`

Cancel an unused local controller invite; issued membership certificates remain valid

Flags:
- `-h, --help help for revoke-invite`
- `--invite-id string Local invite_id to cancel`

## `id team rotate-key`

### `id team rotate-key`

Replace the team controller key at AWID with a new local key, under the namespace
controller key. Every record the team key has signed at AWID (the team-server record,
custodian, member-custody and member-person records) is verified, re-signed by the
new key and swapped with the key in one atomic request.

Every member certificate is signed by the team key, so the same request gives each active
member a fresh certificate under the new key, with the member's custody and person records:
AWID revokes the old certificate and registers the new one with the key. Members' clients
fetch their new certificate when a server refuses the old one. If the command is
interrupted, run it again: it resumes with the same new key.

Flags:
- `-h, --help help for rotate-key`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

## `id team set-server`

### `id team set-server`

Publish the team's aweb.team-server/1 record at AWID: the coordination server
URL that installed apps use for this team, signed by the local team controller key.

The record must be newer than the published one; republishing the same record is
accepted unchanged. After a team key rotation, publish again with the new key.

Flags:
- `-h, --help help for set-server`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`
- `--url string Coordination server URL (https origin with optional path prefix)`

## `id team show-server`

### `id team show-server`

Read the team's aweb.team-server/1 record from AWID and verify it against the
team's current key. A record signed by any other key is refused.

Flags:
- `-h, --help help for show-server`
- `--namespace string Namespace domain`
- `--registry string Registry origin override`
- `--team string Team name`

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

## `org`

### `org`

Manage organizations using host CLI authorization, not an agent or team key.

For an existing account, propose `<username>`-`<hostname>`; for a new account,
propose the hostname. Distro defaults such as omarchy, archlinux and localhost
should go straight to an available suggestion. Confirm the proposed name before
creating it. The server never silently suffixes a requested organization slug.
Use org availability for a read-only plan; it creates no keys or resources.

Subcommands:
- `availability` Check an organization name without creating anything
- `create` Create or recover an organization you own
- `list` List organizations where you are an owner or admin

Flags:
- `-h, --help help for org`

## `org availability`

### `org availability`

Check an organization name without creating anything

Flags:
- `-h, --help help for availability`

## `org create`

### `org create`

Manage organizations using host CLI authorization, not an agent or team key.

For an existing account, propose `<username>`-`<hostname>`; for a new account,
propose the hostname. Distro defaults such as omarchy, archlinux and localhost
should go straight to an available suggestion. Confirm the proposed name before
creating it. The server never silently suffixes a requested organization slug.
Use org availability for a read-only plan; it creates no keys or resources.

Flags:
- `-h, --help help for create`
- `--name string Optional organization display name`

## `org list`

### `org list`

List organizations where you are an owner or admin

Flags:
- `-h, --help help for list`

## `team`

### `team`

Everyday team membership commands.

Use these commands to invite a member, join or leave a team, and inspect or
switch this identity's installed memberships. Team creation and owner/admin
repair operations live under `aw team admin`.

Subcommands:
- `admission-invite` Issue a shared-team admission invite token
- `ensure` Ensure this host has a workspace's default team authority
- `invite` Invite an agent or workspace to the active team
- `join` Join a team from an invite token
- `leave` Remove a team membership from this identity
- `list` List team memberships for this identity
- `spawn-authority` Check whether the selected identity can create hosted spawn invites
- `switch` Switch the active team for this identity
- `admin` Team creation and team administration

Flags:
- `-h, --help help for team`

## `team admission-invite`

### `team admission-invite`

Issue a shared-team admission invite token.

This uses host CLI auth with scope cli.team_admission to request an ordinary
single-use aw_inv_ token for a chosen recipient. It does not accept the invite,
install membership, or bind this workspace; save the returned token to a file
and run aw team join --token-file (or aw id team accept-invite --token-file)
in the target identity root.

Flags:
- `--alias-hint string Optional suggested member alias for the recipient`
- `--expect-account string Expected hosted account ID issuing this admission invite`
- `-h, --help help for admission-invite`
- `--request-id string Client-generated UUID for retry-safe issuance`
- `--team-id string Cloud team UUID or canonical AWID team ID to issue an admission invite for`

## `team ensure`

### `team ensure`

Ensure this host has a workspace's default team authority.

The server receives only the format-1 workspace-key digest. Credentials are installed
only into the explicit --identity-home credential root, and the result is bound only
after a live spawn-authority proof from that installed root.

Stable diagnostics are printed to stderr and exit 2, including with --json; there is
no JSON error envelope. authorization-required means host CLI auth is missing,
invalid, expired, revoked, or not authorized. workspace-key-not-portable means a
local/ workspace key cannot be used for hosted default team ensure.
identity-home-occupied means the explicit identity home already contains
conflicting identity, team, workspace, or binding state. unsupported-server means
the aweb service is older than the workspace's default team ensure/enroll contract (Cloud 0.8.16
or later) and is missing one of: CLI auth status, workspace's default team ensure,
workspace's default team enroll, or installed-root spawn-authority proof. Non-404
server errors keep their existing handling.

Flags:
- `--expect-account string Expected hosted account ID that owns this workspace's default team`
- `-h, --help help for ensure`
- `--label string Optional display label for the workspace's default team`
- `--org string Organization slug or ID for workspace ownership and enrollment`
- `--workspace-key string OATS canonical format-1 workspace key`

## `team invite`

### `team invite`

Invite an agent or workspace to the active team.

This creates an invite token using the current team's authority for a separate
workspace or machine, then the joining workspace runs `aw team join <token>`.

Subcommands:
- `inspect` Inspect an invite from stdin without redeeming it

Flags:
- `--expires duration Controller invite lifetime (default 24h; maximum 720h)`
- `--for-human string Admit agents whose verified nearest human is this did:aw person`
- `-h, --help help for invite`
- `--member-global Create global member invite`
- `--member-local Create local workspace member invite (default)`
- `--preflight Show the mint authority without creating a token or child invitation`
- `--team-id string Canonical team id (<name>:<namespace>) to invite from (defaults to active team)`

## `team invite inspect`

### `team invite inspect`

Inspect one invite token from stdin through EOF (max 65536 bytes).

Token input is always stdin; --token-stdin makes that explicit. Never pass a token
as an argument. Hosted envelopes make one non-redeeming Cloud preview request.
Controller tokens are decoded locally without network or controller-store reads:
scope is unknown, status is unverified, and expiry/validity are not established.
Inspection creates no identity, membership or workspace. External identity homes
follow the shared identity selector. Cloud must support /api/v1/spawn/invite-preview.

Flags:
- `-h, --help help for inspect`
- `--token-stdin Read the token from stdin (the default)`

## `team join`

### `team join`

Join a team from an invite token.

Run this in a clean target directory. It refuses to overwrite an existing
.aw identity/key. Join installs the identity and membership, then connects this
workspace to the aweb service carried by the invite. Use --no-connect only when
you intentionally want identity state without a workspace binding.

Use --harness claude|codex|pi to install team docs; Claude and Pi also prepare delivery.
Codex reads mail when asked; for delivery as it arrives, run it under OATS.
This does not launch a session or verify message delivery. After a setup failure,
retry here with --setup-only --harness `<harness>`, without the invite token.

Flags:
- `--address string Advanced: existing owned address to place in the global member certificate`
- `--global Join by reusing the existing global identity in this workspace`
- `--harness string Install team docs; prepare delivery for claude/pi (omitted: no harness changes)`
- `-h, --help help for join`
- `--local Join with a local workspace identity (default)`
- `--name string Member name for the accepting agent (defaults to identity name)`
- `--no-address For --global, join with did:aw continuity but no member address`
- `--no-connect Install identity and membership without connecting this workspace`
- `--parent string Same-machine creator home for a fresh child, independent of the invite`
- `--setup-only Retry harness setup for the connected identity without accepting an invite`
- `--token-file string Read the invite token from this file instead of an argument`
- `--token-stdin Read the invite token from stdin instead of an argument`

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

## `team spawn-authority`

### `team spawn-authority`

Check hosted spawn authority for the selected identity and team.

Pass --team-id as the canonical `<name>`:`<domain>` team ID. If omitted, the selected team's canonical ID is used.
This is a read-only proof against /api/v1/spawn/authority. It does not use or prove CLI human auth status.

Flags:
- `-h, --help help for spawn-authority`
- `--team-id string Canonical team ID (<name>:<domain>) to check (defaults to selected team)`

## `team switch`

### `team switch`

Switch the active team for this identity

Flags:
- `-h, --help help for switch`

## `team admin`

### `team admin`

Team creation and team administration.

Use this surface to create a team, or to perform owner/admin inspection and
repair. These operations are separate from the everyday invite, join, list,
switch, and leave journey.

Subcommands:
- `agent-status` Read whether an agent still holds a certificate, a workspace, or task claims
- `create` Create a team workspace
- `log-key` Manage the owner key that agents' local message logs are sealed to
- `remove-agent` Retire an agent: release its claims, then revoke its certificate
- `replace-key` Replace a local agent identity key under team-controller authority

Flags:
- `-h, --help help for admin`

## `team admin agent-status`

### `team admin agent-status`

Read the state of one agent across the stores retirement has to clear.

This reads and never writes. It exists so that the evidence an agent is
retired comes from somewhere other than the command that retired it.

Flags:
- `-h, --help help for agent-status`
- `--team-id string Canonical team id (<name>:<namespace>) to read from (defaults to active team)`

## `team admin create`

### `team admin create`

Create a team workspace with its first agent identity.

This wraps aw init for the aw-local path.

With --org, create a hosted team using human CLI authorization and return an invite.
This explicit mode creates no local identity or profile; accept the invite separately.

In a fresh directory, a supplied AWEB_API_KEY uses the service's workspace bootstrap.

Flags:
- `--byot Create a customer-controlled AWID team with local namespace controller authority`
- `--display-name string Team display name`
- `--first-agent-global Enroll the first agent as a global identity, reusing an existing global identity or creating one when founding with hosted/namespace authority`
- `--first-agent-local Enroll the first agent as a local team-scoped identity (default)`
- `--first-agent-name string Initial workspace member name (defaults to <name>)`
- `-h, --help help for create`
- `--name string Team name`
- `--namespace string Namespace domain for --byot`
- `--org string Hosted organization slug or ID (requires aw auth login)`
- `--registry string Registry origin override for --byot`
- `--request-id string Hosted create UUID (reuse to replay)`
- `--service string Hosted service URL for dashboard guidance`
- `--show-token Print the hosted invite token in text output`
- `--username string Hosted username to create when founding through managed aweb onboarding`

## `team admin log-key`

### `team admin log-key`

Manage the owner key that agents' local message logs are sealed to

Subcommands:
- `create` Create (or rotate) the team's owner log key; prints its unsigned public record
- `install` Install the team's owner log key record on this host; local logs are then sealed to it
- `sign` Sign a log key record, or attach a signature made elsewhere
- `signing-bytes` Print the exact bytes a team key signs for a log key record

Flags:
- `-h, --help help for log-key`
- `--team string Override the selected team_id for this command`

## `team admin log-key create`

### `team admin log-key create`

Create a new log key for the team on the machine where the owner reads the logs. The
private key is kept in the OS keychain under a passphrase. The public record is written
to --out (or stdout) unsigned: sign it with `aw team admin log-key sign` wherever the
team controller key is held, then install it with `aw team admin log-key install` on
each agent host. Running it again rotates the key; earlier keys stay in the keychain.

Flags:
- `-h, --help help for create`
- `--out string Write the unsigned public record to this file instead of stdout`

## `team admin log-key install`

### `team admin log-key install`

Install the team's owner log key record on this host; local logs are then sealed to it

Flags:
- `-h, --help help for install`

## `team admin log-key sign`

### `team admin log-key sign`

Complete a log key record through exactly one route:
  --team-key-did and --signature attach a signature produced elsewhere, after
  verifying it over the record's signing bytes;
  --offline-controller-key signs with the team controller key in ~/.awid/team-keys/
  on this machine.
With no route, or both, it refuses. The signed record is written to --out (or stdout).

Flags:
- `-h, --help help for sign`
- `--offline-controller-key Sign with the team controller key in ~/.awid/team-keys/ on this machine`
- `--out string Write the signed record to this file instead of stdout`
- `--record string The log key record to sign`
- `--signature string A signature produced elsewhere: unpadded standard base64 of the 64 Ed25519 bytes`
- `--team-key-did string The did:key of the team key that produced --signature`

## `team admin log-key signing-bytes`

### `team admin log-key signing-bytes`

Print, with no trailing newline, the bytes the team controller key --team-key-did signs
for the record: the aweb.log-key/1 prefix and the canonical JSON of its unsigned fields.
Use it to cross-check what any signer is asked to sign.

Flags:
- `-h, --help help for signing-bytes`
- `--record string The log key record`
- `--team-key-did string The did:key of the team key that will sign`

## `team admin remove-agent`

### `team admin remove-agent`

Retire an agent from a team across the stores that hold its state.

It first deletes the agent's workspace record, which releases the task claims
held under it, and only then revokes its certificate. That order matters: an
agent can release its own claims until its certificate is revoked, and the
legacy hosted remove-member path can delete the same workspace record without
releasing anything. The prepared hosted-local path preserves the same order.

If the claims cannot be released the command stops before revoking and says
which store changed and which did not, rather than leaving an agent with no
credential and claims nobody can clear. To revoke access immediately and
accept that outcome, use `aw id team remove-member`.

Customer-controlled teams revoke with the local team controller key. Hosted
local members first prepare an immutable workspace/agent/certificate operation,
persist non-secret recovery state, release exact coordination state, and commit
cloud-mediated revocation. Use --resume-operation after a partial failure,
--list-pending when local recovery state is lost, or --abort-operation only
before release. Addressed/global hosted members retain the exact-certificate path.

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
- `--abort-operation string Abort exact hosted removal operation ID before coordination release`
- `--api-key string Team API key for hosted removal (overrides AWEB_API_KEY; workspace-bound API keys are rejected by hosted aweb)`
- `--aweb-url string Hosted aweb API URL override for cloud-mediated removal`
- `-h, --help help for remove-agent`
- `--list-pending List owner/admin hosted removal operations requiring recovery`
- `--registry string Registry origin override`
- `--resume-operation string Resume exact hosted removal operation ID; no member address is accepted`
- `--team-id string Canonical team id (<name>:<namespace>) to remove from (defaults to active team)`

## `team admin replace-key`

### `team admin replace-key`

Replace a local team-scoped agent's did:key under locally-held team-controller authority.

This compare-and-swap operation updates the service roster, revokes the old
team certificate, registers a new certificate, and records the controller-authorized
transition. When a real local home has lost signing.key, --generate-new-key creates
and retains a replacement key without overwriting an existing one. Hosted teams require
the pending AC owner/admin integration or operator support.

The new key will not have the old key's mail or chat conversations.

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

## `verify`

### `verify`

Verify an exported signed message using only its original signed content,
DNS and public registry reads. No identity, team, token or initialization is needed.
FILE defaults to stdin; - also reads stdin. Export with:
  aw mail show --message-id ID --envelope > message.json

Print the same responsibility result as aw who, with invalid proof shown explicitly
as invalid. --json retains the shared outcome and identity_valid fields: invalid
proof has outcome unknown and identity_valid false. Lookup failures are unavailable,
never valid. A verified signature alone does not establish a responsible human.
Encrypted exports can be verified without decrypting their content.
Exit 0 for valid or normal unknown results, 1 for invalid proof, 2 for unavailable
evidence or unreadable input.

Flags:
- `-h, --help help for verify`
- `--registry string Registry origin, when the domain's _awid record names none (same restriction as aw who)`

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

## `beads-mail`

### `beads-mail`

Mail for beads, no orchestrator required.

beads ships a 'bd mail' command that delegates to an external mail
provider. This is that provider, backed by aweb: durable delivery,
offline recipients, and cryptographically verified sender identity.

Setup, once per repo:

  npm i -g @awebai/aw
  aw init
  bd config set mail.delegate "aw beads-mail"

Then 'bd mail send', 'bd mail inbox', and friends work. Recipients run
the same three lines. Map beads-style names to aweb addresses in
.beads/aweb-mail.toml; addresses containing a domain (acme.com/reviewer)
need no mapping.

Two things to know that differ from 'gt mail':

  - 'bd mail' swallows --help anywhere in the arguments, so use
    'bd mail help `<verb>`' (or 'aw beads-mail `<verb>` --help') for
    per-verb help.
  - 'bd mail check' always exits 0 when the probe worked; branch on its
    output or --json, not the exit code. Nonzero means a real failure.

Optional in-session wake-ups when mail arrives: aw init --setup-channel.

Subcommands:
- `announces` Not supported in v1
- `archive` Not supported: the beads graph is the archive
- `check` Check for unread mail (for hooks)
- `claim` Not supported in v1: no message queues
- `clear` Not supported: aweb mail cannot be deleted
- `delete` Not supported: aweb mail cannot be deleted
- `drain` Not supported in v1
- `help` Show help for a beads-mail verb ('bd mail' swallows --help; this reaches us)
- `inbox` List unread messages (read-only; reading is what marks read)
- `mark-read` Mark messages as read
- `mark-unread` Not supported: read state cannot be cleared
- `peek` Preview the first unread message without marking it read
- `read` Read a message and mark it read
- `release` Not supported in v1: no message queues
- `reply` Reply to a message
- `search` Not supported in v1: no server-side mail search
- `send` Send a message
- `thread` View a message thread (oldest first)

Flags:
- `-h, --help help for beads-mail`

## `beads-mail announces`

### `beads-mail announces`

Not supported in v1

Flags:
- `-h, --help help for announces`

## `beads-mail archive`

### `beads-mail archive`

Not supported: the beads graph is the archive

Flags:
- `-h, --help help for archive`

## `beads-mail check`

### `beads-mail check`

Probe for unread mail without changing anything. Exit code 0 means the
probe worked, whether or not mail is waiting — branch on the output or
--json, not the exit code (gt mail check exits 1 on an empty inbox; this
deliberately does not, so a real failure is never mistaken for "no
mail"). Nonzero exits are real errors only.

For Claude Code hooks, --inject emits the PostToolUse hook JSON envelope
when mail is waiting and nothing otherwise. In-session wake-ups without
polling: aw init --setup-channel.

Flags:
- `-h, --help help for check`
- `--inject Output the Claude Code PostToolUse hook envelope when mail is waiting`
- `--json Output as JSON: {"unread": N, "has_more": bool}`

## `beads-mail claim`

### `beads-mail claim`

Not supported in v1: no message queues

Flags:
- `-h, --help help for claim`

## `beads-mail clear`

### `beads-mail clear`

Not supported: aweb mail cannot be deleted

Flags:
- `-h, --help help for clear`

## `beads-mail delete`

### `beads-mail delete`

Not supported: aweb mail cannot be deleted

Flags:
- `-h, --help help for delete`

## `beads-mail drain`

### `beads-mail drain`

Not supported in v1

Flags:
- `-h, --help help for drain`

## `beads-mail help`

### `beads-mail help`

Show help for a beads-mail verb ('bd mail' swallows --help; this reaches us)

Flags:
- `-h, --help help for help`

## `beads-mail inbox`

### `beads-mail inbox`

List unread messages (read-only; reading is what marks read)

Flags:
- `-a, --all Show all messages, read and unread (gt's default view)`
- `--cursor string Continue a previous listing from its printed cursor`
- `-h, --help help for inbox`
- `--json Output as JSON`
- `-u, --unread Show only unread messages (the default)`

## `beads-mail mark-read`

### `beads-mail mark-read`

Mark messages as read

Flags:
- `--all Mark all unread messages as read`
- `-h, --help help for mark-read`

## `beads-mail mark-unread`

### `beads-mail mark-unread`

Not supported: read state cannot be cleared

Flags:
- `-h, --help help for mark-unread`

## `beads-mail peek`

### `beads-mail peek`

Preview the first unread message without marking it read

Flags:
- `-h, --help help for peek`

## `beads-mail read`

### `beads-mail read`

Read one message by id, or by its number in the most recent inbox
listing. Reading marks the message read (unlike gt mail read, which does
not) because read state drives the wake path here; use peek or thread
for a look that changes nothing.

Flags:
- `-h, --help help for read`
- `--json Output as JSON (raw message, envelope included)`

## `beads-mail release`

### `beads-mail release`

Not supported in v1: no message queues

Flags:
- `-h, --help help for release`

## `beads-mail reply`

### `beads-mail reply`

Reply to a message

Flags:
- `--body string Alias for --message`
- `-h, --help help for reply`
- `-m, --message string Reply message body`
- `--stdin Read the reply body from stdin (delegate extension; gt reply lacks it, but shell-unsafe bodies need it)`
- `-s, --subject string Override reply subject (default: Re: <original>)`

## `beads-mail search`

### `beads-mail search`

Not supported in v1: no server-side mail search

Flags:
- `-h, --help help for search`

## `beads-mail send`

### `beads-mail send`

Send mail to a beads-style name (mapped in .beads/aweb-mail.toml), an
aweb address like acme.aweb.ai/reviewer, or a did:aw identity. The
resolved address is always shown: mail goes out under this workspace's
cryptographically verified identity.

A bare recipient name is looked up in the selected team. When that team's
agent list and roster say the name is not there, this identity has other
local team memberships, and --team is not given, aw looks in those teams:
a name found in exactly one of them is sent from that team, which aw names
on stderr; a name found in more than one needs --team. If any of those teams
cannot be read, the send is refused rather than guessed. When the selected
team itself cannot be read, aw stays in it, and the send confirms the
recipient before delivery.

Flags:
- `--body string Alias for --message`
- `--cc stringArray Not supported in v1: send to each recipient separately`
- `--from string Not supported: sender identity is cryptographic here`
- `-h, --help help for send`
- `-m, --message string Message body`
- `--no-notify No-op at priority <= normal (idle wake anyway); cannot silence high/urgent`
- `-n, --notify Bump priority to high so the recipient wakes`
- `--permanent Carry ephemeral=false metadata; v1 does not promote the underlying message bead`
- `--pinned Carried in the beads-mail envelope; no delivery behavior`
- `--priority int Message priority (0=urgent, 1=high, 2=normal, 3=low, 4=backlog); 0-1 wake the recipient (default 2)`
- `--reply-to string Message ID this replies to; continues that conversation`
- `--self Send to this workspace's own identity`
- `--stdin Read message body from stdin`
- `-s, --subject string Message subject (required)`
- `--to string Recipient address (alternative to the positional argument)`
- `--type string Message type (task, scavenge, notification, reply); carried in the beads-mail envelope (default "notification")`
- `--urgent Set priority=0 (urgent)`
- `--wisp Use the beads ephemeral default (default true)`

## `beads-mail thread`

### `beads-mail thread`

View a message thread (oldest first)

Flags:
- `-h, --help help for thread`
- `--json Output as JSON`

## `chat`

### `chat`

Real-time chat between agents. aweb reaches people by mail: chat to a person is
refused; use aw mail send --to `<person>` --subject `<subject>`.

Subcommands:
- `attachment` Fetch managed message attachments as the authenticated participant
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

## `chat attachment`

### `chat attachment`

Fetch managed message attachments as the authenticated participant

Subcommands:
- `fetch` Fetch exact file bytes to an explicit new output path

Flags:
- `-h, --help help for attachment`

## `chat attachment fetch`

### `chat attachment fetch`

Fetch exact file bytes to an explicit new output path

Flags:
- `-h, --help help for fetch`
- `--message-id string Message containing the attachment`
- `--output string Explicit new file path (existing files and symlinks are refused)`
- `--session-id string Chat session containing the message`

## `chat extend-wait`

### `chat extend-wait`

Ask the other party to wait longer. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted wait extension; fails closed if encryption keys are missing`
- `-h, --help help for extend-wait`
- `--plaintext Send explicit server-readable plaintext wait extension (by default it inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)`

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
- `--plaintext Send explicit server-readable plaintext chat (the default for a new conversation; a continuation inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)`
- `--session-id string Existing chat session id`

## `chat send-and-leave`

### `chat send-and-leave`

Send a message and leave the conversation. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

A bare recipient name is looked up in the selected team. When that team's
agent list and roster say the name is not there, this identity has other
local team memberships, and --team is not given, aw looks in those teams:
a name found in exactly one of them is sent from that team, which aw names
on stderr; a name found in more than one needs --team. If any of those teams
cannot be read, the send is refused rather than guessed. When the selected
team itself cannot be read, aw stays in it, and the send confirms the
recipient before delivery.

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send-and-leave`
- `--plaintext Send explicit server-readable plaintext chat (the default for a new conversation; a continuation inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)`
- `--start-conversation Start a new conversation instead of continuing an existing one`

## `chat send-and-wait`

### `chat send-and-wait`

Send a message and wait for a reply. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples

A bare recipient name is looked up in the selected team. When that team's
agent list and roster say the name is not there, this identity has other
local team memberships, and --team is not given, aw looks in those teams:
a name found in exactly one of them is sent from that team, which aw names
on stderr; a name found in more than one needs --team. If any of those teams
cannot be read, the send is refused rather than guessed. When the selected
team itself cannot be read, aw stays in it, and the send confirms the
recipient before delivery.

Flags:
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted chat; fails closed if encryption keys are missing`
- `-h, --help help for send-and-wait`
- `--plaintext Send explicit server-readable plaintext chat (the default for a new conversation; a continuation inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)`
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
- `subscribe` Subscribe this resident to an installed app event

Flags:
- `-h, --help help for events`
- `--team string Override the selected team_id for this command`

## `events stream`

### `events stream`

Listen to real-time agent events via SSE

Flags:
- `-h, --help help for stream`
- `--timeout int Stop after N seconds (0 = indefinite)`

## `events subscribe`

### `events subscribe`

Subscribe this resident to an installed app event

Flags:
- `-h, --help help for subscribe`
- `--intent string Delivery intent: wake, steer or ambient (default: app declaration)`
- `--resource string Match only this resource reference`

## `gc-mail`

### `gc-mail`

Mail for Gas City, across machines and organizations.

Gas City's mail is pluggable: GC_MAIL=exec:`<command>` makes gc delegate
every mail operation to a command. This is that command, backed by aweb —
durable delivery, recipients who can be offline, and messages signed by a
cryptographically verifiable identity.

Setup, once per city:

  npm i -g @awebai/aw
  aw init
  export GC_MAIL=exec:aw-gc-mail

'aw-gc-mail' is installed by the same npm package and runs this command.
GC_MAIL names a single command with no arguments, which is why the
launcher exists; 'exec:aw gc-mail' would look for a program literally
named "aw gc-mail".

This command speaks gc's JSON protocol on stdin/stdout. It is meant to be
run by gc, not by hand — but every operation is a plain subcommand, so
'aw gc-mail inbox' works for a look, and 'aw gc-mail resolve `<name>`'
shows where a recipient name would actually go.

Optional in-session wake-ups when mail arrives: aw init --setup-channel.

Subcommands:
- `all` List all messages, read and unread, as JSON
- `archive` Not supported: aweb mail is delivery, not storage
- `check` List unread messages as JSON without marking anything read
- `count` Report {"total":N,"unread":N} for this workspace
- `delete` Not supported: aweb mail is delivery, not storage
- `ensure-running` Readiness probe (no-op: gc discards this operation's result)
- `get` Fetch one message as JSON without marking it read
- `inbox` List unread messages as JSON (read-only)
- `mark-read` Mark one message read
- `mark-unread` Not supported: read state cannot be cleared
- `read` Fetch one message as JSON and mark it read
- `reply` Reply into a message's conversation (JSON on stdin, JSON message on stdout)
- `resolve` Show the aweb address a recipient name resolves to
- `send` Send a message (JSON on stdin, JSON message on stdout)
- `thread` List a conversation's messages as JSON, oldest first

Flags:
- `-h, --help help for gc-mail`

## `gc-mail all`

### `gc-mail all`

Lists one page of this workspace's mail, read and unread. gc's Provider
documents this as "all open messages"; aweb has no open/closed state, so
it is every message the inbox holds.

Flags:
- `-h, --help help for all`

## `gc-mail archive`

### `gc-mail archive`

Not supported: aweb mail is delivery, not storage

Flags:
- `-h, --help help for archive`

## `gc-mail check`

### `gc-mail check`

Identical to 'inbox' here: both are read-only unread listings. gc keeps the
two operations apart because a backend's inbox may mark messages read;
this one never does.

Flags:
- `-h, --help help for check`

## `gc-mail count`

### `gc-mail count`

Counts this workspace's mail. "Total" counts what the inbox holds
now — aweb mail is delivery, not an archive, so
it is not a cumulative all-time total. Counting stops after 4000 messages; a larger
inbox reports that ceiling rather than a wrong number.

Flags:
- `-h, --help help for count`

## `gc-mail delete`

### `gc-mail delete`

Not supported: aweb mail is delivery, not storage

Flags:
- `-h, --help help for delete`

## `gc-mail ensure-running`

### `gc-mail ensure-running`

gc calls this once, before the first operation of a provider instance, and
throws away both its output and its exit status. There is nothing useful
to report through a channel nobody reads, so this succeeds immediately.
Run 'aw doctor' or 'aw gc-mail inbox' to check the setup for real.

Flags:
- `-h, --help help for ensure-running`

## `gc-mail get`

### `gc-mail get`

Fetches one message by id and leaves its read state alone. Visible for
messages this workspace sent as well as received.

Flags:
- `-h, --help help for get`

## `gc-mail inbox`

### `gc-mail inbox`

Lists this workspace's unread mail as a JSON array. Read-only: nothing is
marked read here.

gc passes the mailbox it wants ($GC_SESSION_ID, $GC_ALIAS, $GC_AGENT, or
"human"). This workspace has exactly one aweb identity, so the argument is
accepted and ignored — every gc session in this city shares one inbox.
That is the design record's §5 limitation, not a bug.

Flags:
- `-h, --help help for inbox`

## `gc-mail mark-read`

### `gc-mail mark-read`

Marks one message read without displaying it. Emits nothing on success;
gc's protocol expects no output from this operation.

Flags:
- `-h, --help help for mark-read`

## `gc-mail mark-unread`

### `gc-mail mark-unread`

Not supported: read state cannot be cleared

Flags:
- `-h, --help help for mark-unread`

## `gc-mail read`

### `gc-mail read`

Fetches one message by id and marks it read. Reading is what marks read
here, because aweb's read state drives the unread count and the wake path:
a displayed message that stayed unread would keep re-firing.

If the acknowledgement fails, this exits nonzero rather than reporting a
message as read that is not.

Flags:
- `-h, --help help for read`

## `gc-mail reply`

### `gc-mail reply`

Reads {"from":...,"subject":...,"body":...} on stdin and sends the body into
the conversation that `<message-id>` belongs to, then marks that message
read. An empty subject becomes "Re: `<original subject>`".

The reply goes to the conversation's counterparty by construction; there
is no recipient argument to get wrong.

Flags:
- `-h, --help help for reply`

## `gc-mail resolve`

### `gc-mail resolve`

Prints where a gc recipient name would actually deliver, without sending
anything. This is the disclosure surface for the optional per-city map in
.gc/aweb-mail.toml: gc's exec protocol gives a provider no way to print a
"sent to X -> Y" line during 'gc mail send', so the resolution is
inspectable here instead.

Flags:
- `-h, --help help for resolve`

## `gc-mail send`

### `gc-mail send`

Reads {"from":...,"subject":...,"body":...} on stdin and sends the body to
`<to>` under this workspace's verified aweb identity. The "from" field is
gc's local mailbox name; it is recorded nowhere as sender identity,
because sender identity here is cryptographic rather than asserted.

The message returned on stdout carries the RESOLVED aweb address in its
"to" field, which is how 'gc mail send --json' and 'gc mail read' disclose
where a mapped name actually delivered.

Flags:
- `-h, --help help for send`

## `gc-mail thread`

### `gc-mail thread`

Renders one conversation as a JSON array, oldest first. The argument may be
an aweb conversation id (what this provider reports as thread_id) or any
message id inside it.

Flags:
- `-h, --help help for thread`

## `heartbeat`

### `heartbeat`

Send an explicit presence heartbeat

Flags:
- `-h, --help help for heartbeat`
- `--team string Override the selected team_id for this command`

## `inbound-mode`

### `inbound-mode`

Show or set the current agent's inbound delivery mode.

open accepts valid routed senders. team-and-contacts accepts verified teammates
and exact active contacts. contacts-only accepts only exact active identity
contacts, including for senders on the same team.

Flags:
- `-h, --help help for inbound-mode`
- `--team string Override the selected team_id for this command`

## `log`

### `log`

Show local communication log

Subcommands:
- `read` Read sealed local logs with the owner's log keys from this machine's keychain

Flags:
- `--channel string Filter by channel (mail, chat, dm)`
- `--from string Filter by sender (substring match)`
- `-h, --help help for log`
- `--limit int Max entries to show (default 20)`
- `--team string Override the selected team_id for this command`

## `log read`

### `log read`

Read sealed local logs with the owner's log keys from this machine's keychain

Flags:
- `-h, --help help for read`

## `mail`

### `mail`

Asynchronous mail between agents and people. A thread is a conversation, titled by its first message's subject.

Answer in the conversation: aw mail reply `<message_id>`. Start a new thread only for a new topic: aw mail send --to `<recipient>` --subject `<subject>`.

Subcommands:
- `ack` Acknowledge one mail message as read
- `attachment` Fetch managed message attachments as the authenticated participant
- `inbox` List inbox messages (unread only by default)
- `reply` Reply to an existing mail conversation
- `send` Start a mail thread, or continue one by its conversation ID
- `show` Show a mail conversation or exact message
- `threads` List your mail threads

Flags:
- `-h, --help help for mail`
- `--team string Override the selected team_id for this command`

## `mail ack`

### `mail ack`

Acknowledge one mail message as read

Flags:
- `-h, --help help for ack`

## `mail attachment`

### `mail attachment`

Fetch managed message attachments as the authenticated participant

Subcommands:
- `fetch` Fetch exact file bytes to an explicit new output path

Flags:
- `-h, --help help for attachment`

## `mail attachment fetch`

### `mail attachment fetch`

Fetch exact file bytes to an explicit new output path

Flags:
- `-h, --help help for fetch`
- `--message-id string Message containing the attachment`
- `--output string Explicit new file path (existing files and symlinks are refused)`

## `mail inbox`

### `mail inbox`

List inbox messages, newest first and unread only by default. Messages shown by this command are acknowledged as read.

Use --count-only to count all unread mail without acknowledging or displaying messages. This read-only count walks inbox pages and does not decrypt message content.

Without --count-only, the response is one bounded page. Text output reports when more messages exist and prints a continuation command; JSON output carries has_more and next_cursor. Pass the returned value to --cursor to continue without overlap.

Flags:
- `--count-only Count all unread mail without acknowledging or displaying messages`
- `--cursor string Continue from next_cursor in a previous inbox response`
- `-h, --help help for inbox`
- `--limit int Max messages per page (default 50)`
- `--show-all Show all messages including already-read`

## `mail reply`

### `mail reply`

Answer in the conversation: aw mail reply `<message_id>`. Start a new thread only for a new topic: aw mail send --to `<recipient>` --subject `<subject>`.

A reply continues the message's conversation, with the subject "Re: `<title>`".
The title is fixed, so --subject is refused.

Flags:
- `--body string Body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--e2ee Send E2E encrypted mail (default for an encrypted source, except to a recipient on aweb's hosted service, which gets server-readable mail); fails closed if encryption keys are missing`
- `-h, --help help for reply`
- `--plaintext Send explicit server-readable plaintext mail, even when replying to encrypted mail`
- `--priority string Priority: low|normal|high|urgent (default "normal")`

## `mail send`

### `mail send`

Answer in the conversation: aw mail reply `<message_id>`. Start a new thread only for a new topic: aw mail send --to `<recipient>` --subject `<subject>`.

With a recipient (--to, --to-did or --to-address), send starts a new thread
titled by --subject, which is required. With --conversation-id it continues
that conversation; its title stays the first message's subject, so --subject
is refused there. JSON returns message_id and conversation_id. A server that
answers a new thread with another conversation_id fails without retry; the
message may already have been sent into that conversation.

With --human, unlock once at a real terminal for this command; each signature
is described on stderr and the key is wiped at exit. Ordinary human mail
carries the ID chain and no saved enrollment or creation evidence.
Use aw id proof to export that evidence for someone else to verify.

A bare recipient name is looked up in the selected team. When that team's
agent list and roster say the name is not there, this identity has other
local team memberships, and --team is not given, aw looks in those teams:
a name found in exactly one of them is sent from that team, which aw names
on stderr; a name found in more than one needs --team. If any of those teams
cannot be read, the send is refused rather than guessed. When the selected
team itself cannot be read, aw stays in it, and the send confirms the
recipient before delivery.

Flags:
- `--body string Body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read message body from a file; safe for Markdown or command examples`
- `--conversation-id string Existing mail conversation to continue (no recipient or --subject)`
- `--e2ee Send E2E encrypted mail; fails closed if encryption keys are missing`
- `-h, --help help for send`
- `--plaintext Send explicit server-readable plaintext mail (the default for a new conversation; --conversation-id inherits its conversation's encryption, and is plaintext, with a notice, when that cannot be read or this identity cannot encrypt)`
- `--priority string Priority: low|normal|high|urgent (default "normal")`
- `--subject string Title of the new thread (required with a recipient)`
- `--to string Recipient name within the active team, or a routable address`
- `--to-address string Recipient address (domain/name)`
- `--to-did string Recipient stable identity (did:aw:...)`

## `mail show`

### `mail show`

Show mail by conversation or exact message ID.

With --message-id, one unique message is selected. The conversation-window direction and 500-message ceiling below do not apply. Add --envelope to export its original signed envelope as JSON for aw verify, without acknowledging it.

With --conversation-id, --limit caps how many messages are returned and defaults to 200. The messages returned are the OLDEST ones, so on a conversation longer than the limit the newest messages are the ones missing - which is the opposite of what someone checking for recent mail expects.

aw mail inbox windows from the other end and has a different default and ceiling. Do not carry an expectation from one command to the other.

To read a whole conversation, pass --limit above its length and check the returned count. If it equals the limit, there may be more; raise it and re-run, up to 500. At the 500-message ceiling, an exact full window cannot establish completeness. The conversation endpoint rejects higher limits and has no paging flag, so a conversation longer than 500 messages cannot be returned whole by this command.

Flags:
- `--conversation-id string Mail conversation to inspect`
- `--envelope Export an exact message's original signed envelope as JSON for aw verify`
- `-h, --help help for show`
- `--limit int For --conversation-id, max messages from the OLDEST end; exact --message-id reads are not windowed (default 200)`
- `--message-id string Legacy mail message to inspect`

## `mail threads`

### `mail threads`

List your mail conversations, newest activity first: each thread's title (its
first message's subject), participants, last activity, unread count and
conversation ID. Listing marks nothing read.

Answer in the conversation: aw mail reply `<message_id>`. Start a new thread only for a new topic: aw mail send --to `<recipient>` --subject `<subject>`.

Flags:
- `--cursor string Continue from next_cursor in a previous threads response`
- `-h, --help help for threads`
- `--limit int Max threads per page (default 50)`

## `room`

### `room`

Read or post signed announcements to the shared team room. Team room posts are readable by the service operator and all current and future team members. Each post notifies other current members once. Read the room for the full post; no reply is expected.

Subcommands:
- `post` Post a signed announcement to the team room
- `read` Read retained team room history

Flags:
- `-h, --help help for room`

## `room post`

### `room post`

Post a signed announcement. Team room posts are readable by the service operator and all current and future team members. E2E room posts are unsupported.

Flags:
- `--body string Announcement body. Warning: double-quoted shell arguments expand backticks and $(...) before aw runs; use --body-file for Markdown or command examples`
- `--body-file string Read announcement body from a file; safe for Markdown or command examples`
- `-h, --help help for post`
- `--subject string Announcement subject`

## `room read`

### `room read`

Read retained team room history

Flags:
- `--after string Continue from a room history cursor`
- `-h, --help help for read`
- `--limit int Maximum posts per page (1-200) (default 50)`
- `--message-id string Read one exact room post`

## `wake`

### `wake`

Terminal wake broker.

One daemon per host supervises registered instance homes and one channel-core
delivery child per active registration. Go owns registration, lifecycle, status
and stream admission; channel-core owns immediate delivery, exact fetch, decrypt/
trust, terminal presentation, delivered IDs, and mail/chat read acknowledgement.

A mail/chat item is marked read after accepted terminal presentation, not after
task completion. Read-only mail grants record local delivery but cannot call the
server mail ack route.

Subcommands:
- `deregister` Remove an instance home from the wake broker
- `pause` Stop the broker typing into one instance, durably
- `register` Register an instance home with the wake broker
- `resume` Let the broker type into one instance again
- `run` Run the host wake broker in the foreground
- `status` Report per-home broker lifecycle, readiness, and delivery status

Flags:
- `-h, --help help for wake`

## `wake deregister`

### `wake deregister`

Remove an instance home from the wake broker.

Called by the OATS retire hook after quiescence. The broker never stops an
instance and never removes a registration on its own; an instance it observed
stopped is marked inactive and waits here.

An unknown or already-retired home exits 0 with a note: the hook may run twice,
and that is not a failed retirement.

For observed managed-worker completion, use --require-managed-stop with
--expect-registration FILE containing managed_receiver from live wake status.
This strict mode requires an eligible captured child and a supporting daemon,
never falls back to files, and treats a lost response as unconfirmed. It does
not certify already accepted input or command completion.

Flags:
- `--expect-registration string Expected managed_receiver JSON exported by live wake status (file or '-')`
- `-h, --help help for deregister`
- `--home string Absolute instance home path`
- `--require-managed-stop Require a live exact-receiver managed stop/join receipt; never use file fallback`
- `--state-dir string Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)`

## `wake pause`

### `wake pause`

Stop the broker typing into one instance.

Pause is durable broker state and survives a restart. It suppresses terminal
presentation before fetch; it does not stop the stream or change server read
state by itself.

Flags:
- `-h, --help help for pause`
- `--home string Absolute instance home path`
- `--state-dir string Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)`

## `wake register`

### `wake register`

Register an instance home with the wake broker.

Called by the OATS spawn hook. --delivery must be session: the broker and a
live native channel are two presentation surfaces on one identity, and running
both doubles every wake. A registration stays pending until an inspect reports
the instance present; pending errors are tolerated until the 30-minute expiry.

Exit 0 means the registration was written durably: over the daemon's socket
when it is up, and straight to the state directory when it is not, so a hook
never fails because the broker is restarting. It does not mean a broker is
running: when none answered, register says so on stderr, and the instance is
not woken until one starts. aw wake status reports whether a broker runs
(daemon_running with --json). A non-zero exit means refused —
a missing --delivery session, a relative path, or an unreadable identity home.

--identity-home here names the instance's own identity home, and shadows the
root flag of the same name for this command. Give the principal's home before
the subcommand (aw --identity-home `<principal>` wake register ...) when you need
both.

Flags:
- `--backend string Terminal backend hint: tmux or herdr`
- `--delivery string Delivery mode recorded by the spawn hook; legacy/external uses session, native mixed uses native-channel or native-pi`
- `-h, --help help for register`
- `--home string Absolute instance home path`
- `--identity-home string Absolute identity home the instance streams under (legacy single-identity registration)`
- `--primary-identity-home string Absolute native primary identity home for disjoint native-channel/native-pi registrations`
- `--receive-identity-json stringArray JSON receive identity binding; repeat for multi-identity broker receive`
- `--registration-json string Read the complete wake registration JSON from this file, or '-' for stdin`
- `--runtime-delivery string Explicit runtime delivery owner: external-session, native-channel, or native-pi`
- `--state-dir string Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)`

## `wake resume`

### `wake resume`

Let the broker type into one instance again

Flags:
- `-h, --help help for resume`
- `--home string Absolute instance home path`
- `--state-dir string Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)`

## `wake run`

### `wake run`

Run the host wake broker in the foreground.

One daemon per host. Go state is on disk and there is no resumable event
cursor, so the daemon is safe to restart at any time: it re-reads registrations
and restarts channel-core children. Unread server state re-raises items that
were not yet presented/read; already-read content remains recoverable with
mail history commands, not unread-only wake replay. A second start exits 0
reporting the running daemon.

Flags:
- `--coalesce int Deprecated compatibility option; delivery is immediate (default 2000)`
- `-h, --help help for run`
- `--max-streams int Maximum concurrent identity event streams (default 128)`
- `--oats-bin oats OATS executable to run (default $AW_WAKE_OATS_BIN, else oats from PATH)`
- `--rate-limit int Deprecated compatibility option; delivery is immediate (default 30000)`
- `--state-dir string Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)`

## `wake status`

### `wake status`

Report per-home broker lifecycle, readiness, and delivery status

Flags:
- `-h, --help help for status`
- `--home string Report readiness for this absolute instance home`
- `--max-streams int Stream bound reported when the daemon is down (default 128)`
- `--min-daemon-version string Required daemon release version for the readiness verdict`
- `--state-dir string Broker state directory (default $AW_WAKE_STATE_DIR, else ~/.config/aw/wake)`

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

This is an explicit Claude Code chat-polling fallback. Prefer the aweb channel
plugin or host wake broker for mail, chat and idle wake-ups. It does not install
Codex hooks. Use aw init --setup-hooks only when this fallback is needed.
After confirming channel/broker delivery, aw init --remove-notify-hook removes
only exact PostToolUse entries in the current directory's and, inside a git
repo, the repository root's .claude/settings.json, with backups.

Flags:
- `-h, --help help for notify`
- `--team string Override the selected team_id for this command`

## `role-name`

### `role-name`

The role name is this workspace's operating responsibility on this team. It is
independently mutable, and changing it grants no additional authority.

Subcommands:
- `set` Set the current workspace operating role

Flags:
- `-h, --help help for role-name`
- `--team string Override the selected team_id for this command`

## `role-name set`

### `role-name set`

Set the current workspace operating role.

The role name is this workspace's operating responsibility on this team. It is
independently mutable, and changing it grants no additional authority.

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

## `app`

### `app`

Roles that an app's manifest declares under owner_acts are held by human members of the team.
The team owner binds and unbinds holders with signed acts; a holder registers a passkey
at the app's human origin in a browser that aw opens.

Subcommands:
- `credential` Register or replace a holder's passkey for an app role
- `human` Run an action an app declares for its role holders, in a passkey session
- `role` Designate or revoke a holder of an app role, as the team owner

Flags:
- `-h, --help help for app`

## `app credential`

### `app credential`

Register or replace a holder's passkey for an app role

Subcommands:
- `register` Register a passkey for an app role, as the holder, and export it for the team owner
- `replace` Replace a holder's passkey, as the team owner

Flags:
- `-h, --help help for credential`

## `app credential register`

### `app credential register`

Opens the app's human origin in a browser, where you create a passkey, and writes the public
credential with your team certificate to --out (or stdout). Read its fingerprint to the team
owner over a channel your custodian does not control, such as in person or a call.

Flags:
- `-h, --help help for register`
- `--out string Write the export to this file instead of stdout`
- `--role string The app role, as its manifest names it`

## `app credential replace`

### `app credential replace`

Signs human-credential.replace with the team's controller key. The current passkey is retired
at once and the replacement takes effect after the app's cooling-off period.

Flags:
- `--credential string The holder's export from aw app credential register`
- `-h, --help help for replace`
- `--notice-contact string The notice contact, for a role that declares one`
- `--principal string The holder's did:aw`
- `--role string The app role, as its manifest names it`
- `--yes Sign what is shown without asking`

## `app human`

### `app human`

Runs one of the session actions an app's manifest declares under owner_acts.session_actions,
in a console session that a browser passkey login opens for your holding of the action's role.
`aw app human <app> --help` lists the declared actions. A protected field is typed at the
terminal with echo off and has no flag; a one-time output is written only to the terminal.

Flags:
- `-h, --help help for human`

## `app role`

### `app role`

Designate or revoke a holder of an app role, as the team owner

Subcommands:
- `designate` Designate a human member as a holder of an app role
- `revoke` End a holder's holding of an app role

Flags:
- `-h, --help help for role`

## `app role designate`

### `app role designate`

Signs human-role.designate with the team's controller key. Pass the holder's export with
--credential and sign only after both clients show the same fingerprint. Without --credential,
you are the holder: aw registers your passkey first, then signs.

Flags:
- `--credential string The holder's export from aw app credential register`
- `-h, --help help for designate`
- `--notice-contact string The notice contact, for a role that declares one`
- `--principal string The holder's did:aw`
- `--role string The app role, as its manifest names it`
- `--yes Sign what is shown without asking`

## `app role revoke`

### `app role revoke`

End a holder's holding of an app role

Flags:
- `-h, --help help for revoke`
- `--principal string The holder's did:aw`
- `--role string The app role, as its manifest names it`
- `--yes Sign what is shown without asking`

## `audit`

### `audit`

A team's audit log

Subcommands:
- `verify` Verify an exported team log offline

Flags:
- `-h, --help help for audit`

## `audit verify`

### `audit verify`

Verify an exported team log (aweb.logs-export/1) offline, against the receipt and
checkpoint keys you accept and the receipts and checkpoints you hold yourself.

It reads only the files it is given: no workspace, identity or server.
Give each key you accept, for receipts and for checkpoints; a key that signs
both is given to both. Each --witness file holds one receipt or checkpoint per
line, in an export's own line shape. --bundle - reads the export from stdin.

Exits 0 when the bundle is intact, 1 when it is verified and not intact, and 2
when it could not be verified.

Flags:
- `--bundle string The export to verify, or - for stdin`
- `--checkpoint-key stringArray A did:key you accept for checkpoints (repeatable)`
- `-h, --help help for verify`
- `--receipt-key stringArray A did:key you accept for receipts (repeatable)`
- `--witness stringArray A file of receipts and checkpoints you hold (repeatable)`

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

## `hooks`

### `hooks`

Read the team's app hook bindings and activate or revoke them as the team owner.
Activation and revocation are aweb.owner-act/1 acts signed with the team's controller key,
which only the team owner holds.

Subcommands:
- `activate` Activate a pending hook binding as the team owner
- `bindings` List an installed app's hook bindings in the selected team
- `revoke` Revoke a pending or active hook binding as the team owner

Flags:
- `-h, --help help for hooks`

## `hooks activate`

### `hooks activate`

Activate a pending hook binding as the team owner.
The binding is checked against the app manifest fetched from its origin at its pinned digest.
What will be signed is shown before the team's controller key signs it.

Flags:
- `-h, --help help for activate`
- `--yes Sign without asking for confirmation (what is signed is still shown)`

## `hooks bindings`

### `hooks bindings`

List an installed app's hook bindings in the selected team

Flags:
- `-h, --help help for bindings`

## `hooks revoke`

### `hooks revoke`

Revoke a pending or active hook binding as the team owner.
The act names the binding as the server stores it; the app's origin is not contacted.
What will be signed is shown before the team's controller key signs it.

Flags:
- `-h, --help help for revoke`
- `--yes Sign without asking for confirmation (what is signed is still shown)`

## `plugin`

### `plugin`

Manage aw plugins

Subcommands:
- `install` Install a plugin into the trusted aw plugin directory
- `list` List installed plugins
- `remove` Remove a local plugin or this home's app approval; keep the team installation
- `request` Ask a team administrator to install an app; grants no tools or scopes
- `reserved-names` Emit reserved top-level aw app ids
- `uninstall` Uninstall an app from the selected team's server installation
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
- `--grant-scope strings Grant only these requested scopes (repeat or comma-separate; default: all requested scopes)`
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

Remove a local plugin or this home's app approval only. The team's server installation is unchanged.
Use aw plugin uninstall to remove the team's server installation.

Flags:
- `-h, --help help for remove`

## `plugin request`

### `plugin request`

Ask a team administrator to install an app; grants no tools or scopes

Flags:
- `-h, --help help for request`

## `plugin reserved-names`

### `plugin reserved-names`

Emit reserved top-level aw app ids

Flags:
- `-h, --help help for reserved-names`

## `plugin uninstall`

### `plugin uninstall`

Uninstall an app from the selected team's server installation. Requires current install-admin authority.
Local plugin files and approvals are retained; use aw plugin remove for local removal only.

Flags:
- `--expected-generation int Require this installation generation (default: read the team's current generation)`
- `-h, --help help for uninstall`

## `plugin update`

### `plugin update`

Update an installed manifest plugin

Flags:
- `--grant-scope strings Explicitly select granted scopes (default: preserve existing grants, dropping removed scopes)`
- `-h, --help help for update`

## `upgrade`

### `upgrade`

Upgrade aw to the latest version

Flags:
- `-h, --help help for upgrade`

## `validate`

### `validate`

Query the CLI's identifier and URL rules without identity or network access

Subcommands:
- `alias` Check a workspace alias using the CLI's alias rule
- `team-id` Parse and normalize a team ID using the SDK's input rule
- `team-server-url` Query canonical team-server URL and audience spelling

Flags:
- `-h, --help help for validate`

## `validate alias`

### `validate alias`

Check a workspace alias using the CLI's alias rule

Flags:
- `-h, --help help for alias`

## `validate team-id`

### `validate team-id`

Parse and normalize a team ID using the SDK's input rule

Flags:
- `-h, --help help for team-id`

## `validate team-server-url`

### `validate team-server-url`

Query canonical team-server URL and audience spelling

Flags:
- `-h, --help help for team-server-url`

## `version`

### `version`

Print version information

Flags:
- `-h, --help help for version`

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

## `who`

### `who`

Verify the current identity's installed ID chain on current status from
its namespace's registry, and show the outcome: the nearest human, no human
(no human in its chain), unknown or unavailable, with the verifier's reason. The chain is shown only when it verifies.

With an agent address, did:aw or local alias, inspect that sender's most recent
received mail (or chat). Use --message-id for an exact mail, or --session-id
with an optional --message-id for chat. These reads do not acknowledge messages.

Flags:
- `-h, --help help for who`
- `--message-id string Inspect the sender of this received mail or chat message`
- `--registry string Registry origin, when the domain's _awid record names none (a record naming api.awid.ai counts as naming none)`
- `--room Inspect an exact team room post (requires --message-id)`
- `--session-id string Inspect received chat in this session`
