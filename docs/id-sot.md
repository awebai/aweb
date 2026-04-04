# Agent Web — Identity Model (2026-03-23)

This document replaces the muddled "agent = identity = address" language that
has crept into the product. It separates runtime, identity, alias, and address
so the system is explainable, implementable, and trustworthy.

The system has been too loose about four different things:

- the **agent** that runs
- the **workspace** where a local agent runs
- the **identity** the agent uses
- the **handle** others use to reach that identity

These are not the same object and must not be presented as if they are.

## Core Objects

### Agent

An **agent** is a running participant.

- A local CLI runtime is an agent.
- A hosted OAuth MCP runtime is an agent.
- An agent uses exactly one identity at a time.
- An identity may be inactive even when no agent is currently running under it.

### Workspace

A **workspace** is a local runtime container.

- It is represented by a local `.aw/` directory.
- It stores local runtime state and configuration.
- It may also store secret key material for self-custodial permanent identities.
- A workspace belongs to one local machine/path, but it may be moved by moving
  the `.aw/` directory.
- A workspace has one active identity.
- Hosted OAuth MCP runtimes do **not** have a local workspace.

### Identity

An **identity** is the principal the agent uses for messaging, coordination,
and trust.

Two identity classes exist:

- **Ephemeral identity**
- **Permanent identity**

They have different creation paths, lifecycle rules, and trust semantics.

Identity material:

- an ephemeral identity has a `did:key` only
- a permanent identity has both `did:key` and `did:aw`

Trust continuity is only promised for permanent identities.

Permanent identity continuity is part of OSS `aweb` itself. It is not a
separate product line.

Inside OSS `aweb`, this identity system lives under the explicit internal
subpackage `aweb.awid`. It remains a first-class boundary within `aweb`, not a
separate product or repo.

## Identity Classes

### Ephemeral Identity

Ephemeral identities are the default internal coordination identity.

Properties:

- disposable
- intended for internal coordination within a hosted owner/org scope
- can have exactly one alias
- do not carry public trust continuity semantics
- are deleted, not archived
- are eligible for automatic cleanup
- are workspace-bound and disposable by design

Ephemeral identities are created:

- by project-scoped workspace init
- or by accepting a spawn invite created by another identity in the same
  project

Ephemeral identities are the normal result of CLI bootstrap into an existing
project.

Ephemeral lifecycle:

- deleting the workspace deletes the ephemeral identity
- explicit user teardown of an ephemeral identity is the same delete operation
- the alias becomes reusable after deletion
- there is no separate lingering server-side lifecycle after the workspace is
  gone
- `delete` is the single public lifecycle concept for ephemeral teardown
  identities; the user-facing concept is simply delete

### Permanent Identity

Permanent identities are the durable trust-bearing identity class.

Properties:

- durable
- not subject to automatic cleanup
- can be archived but not casually deleted
- can have one or more public addresses
- support rotation, archival, and controlled replacement

### Stable Identity and Audit Log

Every permanent identity has:

- a current `did:key`
- a stable `did:aw`
- an append-only audit log that records key continuity mutations

The stable identity model is:

- `did:key` may change over time
- `did:aw` does not change
- clients may resolve the current key for a `did:aw`
- clients may list the current active addresses for a `did:aw`
- clients may verify the latest signed audit-log head without fetching the full
  log

This audit-log-backed verification model is part of canonical OSS `aweb`.
The verifier rules live in
[identity-key-verification.md](identity-key-verification.md).

The runtime implementation for this model belongs under `aweb.awid`.

Permanent identities come in two custody modes:

- **self-custodial**
- **custodial**

## Custody Modes

### Self-Custodial Permanent Identity

A self-custodial permanent identity holds its secret key locally.

Properties:

- created only from the CLI
- requires a local workspace
- secret key material is stored locally and the CLI must say where
- may be moved to another directory by moving the `.aw/` workspace
- cannot be used by hosted OAuth MCP runtimes
- is owned by the agent running in the workspace where the `.aw/` directory and
  secret key material live

Creation must be explicit, for example:

```bash
aw init --permanent --name "Alice"
```

This must never be an accidental side effect of the default init flow.

### Custodial Permanent Identity

A custodial permanent identity is held by the hosted service.

Properties:

- created from the dashboard
- no local workspace required
- usable by hosted OAuth MCP runtimes
- supports dashboard-driven archive and replacement flows

The dashboard creates **permanent custodial identities**, not generic "agents".

## Names: Alias vs Address

### Alias

An **alias** is the routing name for an ephemeral identity.

Formats:

- `alias`
- `project~alias`

Rules:

- alias is internal/project/org scoped
- alias is not the external public trust surface
- alias is never the public-network name for an ephemeral identity
- an ephemeral identity can have exactly one alias
- aliases may be auto-assigned

### Address

An **address** is the stable handle for a permanent identity.

Formats:

- `name`
- `project~name`
- `namespace/name`

Rules:

- only permanent identities may have addresses
- a permanent identity may have more than one address
- every permanent identity is assigned a permanent address in its project
  address space
- address assignment is separate from reachability
- public trust semantics attach to the permanent address, not to ephemeral
  aliases
- DNS-backed domains are only for permanent identities
- DNS-verified namespace registration is the default for bring-your-own domains
- subdomains under an already-registered parent namespace may be authorized by
  the parent controller instead of per-subdomain DNS verification
- permanent identity names/addresses are explicit user choices, not
  auto-assigned defaults

Address assignment makes the address owned by that permanent identity.
Reachability determines who can discover and use that address from outside the
immediate local scope.

Permanent addresses have explicit reachability states:

- **private**
- **org-visible**
- **contacts-only**
- **public**

Reachability semantics:

- `private` means the permanent identity still owns the address, but callers
  outside the project should experience it as if it does not exist
- `org-visible` means identities in the same org may resolve and use it, but it
  is not externally discoverable
- `contacts-only` means outside callers may use it only if they are in the
  recipient project's contacts model
- `public` means any caller may resolve and use it subject to normal delivery
  rules

Reachability is a property of use and discovery. It is not what creates the
address in the first place.

Audience-relative address forms:

- `name` — same project
- `project~name` — same org
- `namespace/name` — canonical external form

These are audience-relative renderings of the same permanent identity's
addressability.

Canonical trust form:

- `namespace/name` is the canonical public trust-bearing form
- `name` and `project~name` are convenience/routing forms for narrower
  audiences

### Project Slug vs Namespace Slug

`project_slug` and `namespace_slug` are not the same concept.

- `project_slug` identifies the project
- `namespace_slug` identifies the authoritative address namespace when
  addressing identities

They may coincide, but the model must not assume that they always do.

Rules:

- routing and trust use the authoritative namespace, not the project slug
- automatic cleanup and alias reuse for ephemeral identities must use the
  authoritative namespace when one is present
- when a server or workspace payload includes both fields, `namespace_slug`
  wins for addressing semantics whenever it differs from `project_slug`
- payloads that are used for addressing, cleanup, or replacement must expose the
  authoritative namespace explicitly; `project_slug` alone is not sufficient

## Creation Rules

### CLI: Init Existing Project Workspace

When the user has a project-scoped API key and runs `aw init` inside a local
directory, the default behavior is:

- initialize the local workspace
- create that workspace's identity
- assign one alias
- make the local agent usable immediately

This flow uses an existing project/namespace context supplied by the project
API key.

Default outcome:

- ephemeral identity

Permanent self-custodial identity creation from init must be explicit.

### CLI: Create Project

Creating the first project from the CLI creates:

- a project
- that project's default managed namespace
- the first workspace in that project
- the first identity in that workspace

Default outcome:

- ephemeral identity

Explicit alternative:

- permanent self-custodial identity, if the user explicitly asks for it

The namespace is attached to the project. It is not owned by the first
identity.

Namespace authority rules:

- BYOD namespace registration is DNS-verified
- parent-owned subdomains may be registered by the parent controller without a
  child DNS TXT record
- controller rotation must always include proof that the caller holds the new
  controller key
- for parent-owned subdomains, parent authorization may replace DNS
  re-verification during controller rotation
- exact-domain DNS verification uses `_awid.<domain>` TXT records, not `_aweb`
- TXT format is `awid=v1; controller=<did:key>; [registry=<origin>;]`
- when `registry=` is absent, clients default to `https://api.awid.ai`
- client-side registry discovery may inherit the nearest parent `_awid` record
  for subdomains so parent-authorized namespaces remain resolvable

Creating a project must not silently imply "create a durable public permanent
identity" unless the user explicitly asked for that.

### CLI: Explicit Permanent Identity Creation

Permanent self-custodial identities are created explicitly from the CLI only at
workspace creation time.

The explicit permanent entry points are:

- `aw project create --permanent --name <name>`
- `aw init --permanent --name <name>`
- `aw spawn accept-invite --permanent --name <name>`

These flows must:

- require `--name`
- reject alias auto-suggestion
- record where the secret key is stored
- explain that the identity is durable and not auto-cleaned

### CLI: Spawn

Spawn is delegated creation of **another workspace's identity** in the same
project.

It is a workspace-plus-identity creation authorization flow.

Properties:

- parent identity already exists in the current workspace
- child identity is created for a different workspace
- the child workspace may be another directory on the same machine or another
  host
- spawn stays within the same project
- hosted/public spawn is represented operationally by invite create + accept

Spawn may create:

- **ephemeral identities**
- **permanent self-custodial identities**

Spawn may not create:

- **permanent custodial identities**

The default spawn outcome should be ephemeral unless the user explicitly asks
for a permanent self-custodial identity.

Hosted spawn is invite-only:

- parent workspace creates a single-use short-lived invite
- child workspace accepts that invite
- no other hosted route should create sibling identities from an agent-scoped
  key

### Dashboard

The dashboard creates only **permanent custodial identities**.

It does not create ephemeral identities.
It does not create self-custodial identities.
It does not require a local workspace.

This is the right model for:

- OAuth MCP
- hosted non-terminal runtimes
- durable public-facing identities managed by a project owner

## Runtime Matrix

### Local CLI Runtime

- has a workspace
- may use an ephemeral identity
- may use a permanent self-custodial identity
- may authorize spawn of other workspaces in the same project

### Hosted OAuth MCP Runtime

- has no local workspace
- must use a permanent custodial identity
- cannot use a self-custodial identity
- should never be described as "creating an agent" when the dashboard is
  really creating the underlying custodial identity

## Lifecycle

### Ephemeral Identity Lifecycle

Ephemeral identities:

- are deleted when explicitly torn down or when their workspace disappears
- can be deleted
- may be automatically cleaned up
- do not support public continuity claims
- do not participate in replacement semantics

`Delete` is the user-facing lifecycle verb for ephemeral identities.
Deleting an ephemeral identity should release its alias.

### Permanent Identity Lifecycle

Permanent identities:

- can be archived
- are not auto-cleaned
- may keep historical/audit records after archival

Permanent identities support two distinct trust-sensitive transitions:

- **rotation**, when the old key still exists
- **replacement**, when the owner has lost the key but still controls the
  dashboard and public address surface

Permanent self-custodial identities do **not** require dashboard claim in order
to exist. A CLI-first project may create and use permanent self-custodial
identities before any human claims the hosted dashboard account.

Dashboard claim is required only for hosted/admin capabilities such as:

- permanent custodial identities
- owner-driven replacement flows
- hosted OAuth MCP usage

## Archive vs Replace

### Archive

Archive is the normal "we do not use this anymore" action for permanent
identities.

Properties:

- stops the identity from active participation
- keeps history
- makes no continuity claim

### Replace

Replace is the "we lost the key / we need a new durable identity but must keep
the public trust surface" action.

Properties:

- old permanent identity is retired from active use
- a new permanent identity becomes the successor
- the owner/dashboard operator authorizes moving the public address(es)
- this is distinct from cryptographic old-key rotation

This must be invokable from the dashboard because the whole point is to handle
the case where the old secret key is gone but the human owner still controls
the hosted project and its addresses.

## Trust Model

Trust attaches to permanent public addresses, not ephemeral aliases.

If a client has pinned `acme.com/support` to one permanent identity and later
sees a different identity at the same address:

- if the old key authorized the change, this is a **rotation**
- if the old key is gone but the dashboard owner authorized the change, this is
  a **replacement**
- otherwise, the client must treat it as an identity mismatch

For stable identity lookup:

- `GET /v1/did/{did_aw}/key` returns the current `did:key` plus a signed
  `log_head`
- clients verify `entry_hash`, signature, and monotonic cache behavior
- `OK_VERIFIED`, `OK_DEGRADED`, and `HARD_ERROR` are the normative verification
  outcomes

For message-level continuity:

- old-key authorization proves **rotation**
- controller authorization proves **replacement**
- otherwise the client must keep the event in **identity mismatch**
- server-side verification of signed self-custodial ingress resolves the
  sender's current `did:key` from `awid.ai` when a stable `did:aw` exists
- `agents.did` and `agents.public_key` remain local cache/display fields and
  are only used as a last resort when registry lookup is unavailable or the
  sender has no stable identity
- this fallback is explicitly `OK_DEGRADED`: if a stable identity rotated
  outside the local server and `awid.ai` is unavailable, the server may accept
  the last cached local key until registry connectivity returns

Ephemeral alias reuse does not carry the same continuity semantics and should
not be marketed as if it does.

## Conformance Assets

OSS `aweb` publishes deterministic conformance vectors for:

- stable ID derivation
- message signing
- audit-log entry hashing and signing
- rotation-announcement signing

These vectors live in
[docs/vectors](vectors/README.md) and are part of the canonical OSS contract.

## Product Language Requirements

The product must stop using vague language like "create agent" when it really
means one of the following:

- create local workspace
- create ephemeral identity
- create permanent self-custodial identity
- create permanent custodial identity

The default user-facing language should become:

- CLI init: creates a local workspace and default ephemeral identity
- CLI explicit permanent creation: creates a durable self-custodial identity in
  the current workspace
- CLI spawn: authorizes another workspace to join the same project with its own
  identity
- Dashboard create flow: creates a durable custodial identity for hosted use

## Immediate Product Implications

### CLI

- `aw init` should default to ephemeral identity creation
- permanent identity creation should be explicit
- spawn in the CLI should be treated as delegated creation of another workspace
  in the same project
- the CLI must say where self-custodial keys are stored
- moving a workspace must be a supported story for self-custodial permanent
  identities

### Dashboard

- the dashboard should describe its flow as creating a hosted identity, not a
  generic agent
- OAuth MCP setup should bind to a permanent custodial identity
- dashboard replacement should be explicit and framed as owner-authorized
  continuity

### Documentation

We need to document separately:

- workspace
- identity class
- custody mode
- alias
- address
- archive
- replace

Without those distinctions, trust claims will remain confusing.

## Target Endpoint Model

The target API should be named by intent, not by legacy implementation history.
These names describe where we are going.

### 1. Create project

- `POST /api/v1/create-project`
  - unauthenticated
  - heavily rate-limited
  - creates project
  - attaches the default managed namespace to that project
  - creates the first workspace in that project
  - creates the first identity in that workspace
  - default first identity outcome is ephemeral
  - explicit permanent self-custodial first identity is allowed

### 2. Existing project workspace init

- `POST /v1/workspaces/init`
  - auth: project authority
  - project-scoped API key flow
  - initializes a local workspace into an existing project
  - creates the workspace's default identity
  - default identity outcome is ephemeral
  - explicit permanent self-custodial identity is allowed

### 3. Spawn another workspace in the same project

- `POST /api/v1/spawn/create-invite`
  - auth: identity authority
  - authenticated as the current identity
  - creates a short-lived single-use spawn invite
  - used when one workspace authorizes another workspace to join the same
    project
  - authorizes child workspace identity creation; it does not pre-create the
    child identity

- `POST /api/v1/spawn/accept-invite`
  - auth: invite token
  - unauthenticated; the invite token is the credential
  - child workspace accepts the parent-authorized spawn
  - default identity outcome is ephemeral
  - explicit permanent self-custodial spawn is allowed
  - custodial permanent spawn is not allowed

Spawn in the hosted/public system must use invite create + accept. There should
not be multiple overlapping creation routes that all partially work for
agent-scoped keys.

### 4. Dashboard hosted permanent identity creation

- `POST /api/v1/identities/create-permanent-custodial`
  - auth: owner/dashboard authority
  - dashboard/cloud authority flow
  - creates a permanent custodial identity in an existing hosted project
  - this is the identity class used by dashboard-created OAuth MCP identities

The dashboard flow must say that it creates a hosted permanent identity, not a
generic "agent".

## Endpoint Transition Map

This section exists so the SOT can describe the target shape without losing the
migration path from the current code.

| Current endpoint                        | Target endpoint                                      | Authority in target model         | Meaning in target model                                   |
|-----------------------------------------|------------------------------------------------------|-----------------------------------|-----------------------------------------------------------|
| `POST /api/v1/bootstrap/headless-agent` | `POST /api/v1/create-project`                        | unauthenticated, rate-limited     | create project, attached namespace, first workspace, first identity |
| `POST /v1/init`                         | `POST /v1/workspaces/init`                           | project authority                 | local workspace init into existing project                |
| `POST /api/v1/invites/cli`              | `POST /api/v1/spawn/create-invite`                   | identity authority                | create spawn invite for another workspace in same project |
| `POST /api/v1/invites/cli/accept`       | `POST /api/v1/spawn/accept-invite`                   | invite token                      | accept spawn invite for child workspace                   |
| `POST /api/v1/agents/bootstrap`         | `POST /api/v1/identities/create-permanent-custodial` | owner/dashboard authority         | dashboard/hosted permanent custodial identity creation    |

## Default Principle

If the user did not explicitly ask for durable public trust semantics, we
should create an **ephemeral** identity, not a permanent one.

## Appendix A: Current `aw` CLI Reference (2026-03-23)

This appendix records the current shipped CLI surface as of 2026-03-23. It is
intended as an implementation reference for CLI, dashboard, docs, and test
work. If the public CLI changes, this appendix should be updated in the same
change.

The conceptual model above is normative. This appendix is the concrete command
map that currently implements that model.

Common global flags:

- `--server-name`: override the server host or name for this command
- `--json`: JSON output
- `--debug`: log background errors to stderr

### Top-Level Grouping

Current `aw --help` groups commands into:

- Workspace Setup
- Identity
- Messaging & Network
- Coordination & Runtime
- Utility

### Workspace Setup

- `aw init`: initialize a local workspace in an existing project
- `aw project`: show the current project
- `aw reset`: remove the local workspace binding in the current directory
- `aw spawn`: authorize another workspace to join this project
- `aw workspace`: manage repo-local coordination workspaces

Subcommands:

- `aw project create`: create a project and initialize its first workspace
- `aw project namespace`: manage project namespaces
- `aw project namespace add`: add a BYOD namespace to the current project
- `aw project namespace delete`: delete a namespace from the current project
- `aw project namespace list`: list namespaces attached to the current project
- `aw project namespace verify`: verify DNS and register a BYOD namespace for the current project
- `aw spawn accept-invite`: accept a spawn invite into a new workspace
- `aw spawn create-invite`: create a spawn invite for another workspace
- `aw spawn list-invites`: list active spawn invites
- `aw spawn revoke-invite`: revoke a spawn invite by token prefix
- `aw workspace add-worktree`: create a sibling git worktree and initialize a new coordination workspace in it
- `aw workspace status`: show coordination status for the current agent/context and team

Notable help/usage details:

- `aw project create` uses `--project <slug>` for the project slug; it may also fall back to `AWEB_PROJECT`/`AWEB_PROJECT_SLUG` or a TTY prompt
- `aw project create --namespace <slug>` optionally sets an authoritative namespace slug distinct from the project slug; when omitted, the namespace defaults to the project slug
- `aw init` supports `--permanent --name <name>` for explicit durable self-custodial creation
- `aw spawn accept-invite` remains an explicit delegated bootstrap command; unlike `aw run`, it should stay non-prompting
- `aw reset` is local-only; it removes `.aw/workspace.yaml` and `.aw/context`
  without mutating server-side identity state

### Identity

- `aw claim-human`: attach a human account to your org for dashboard access
- `aw identities`: list identities in the current project
- `aw id`: identity lifecycle, registry, settings, and key management
- `aw whoami`: show the current identity
- `aw mcp-config`: output MCP server configuration for the current agent

Subcommands:

- `aw id access-mode [open|contacts_only]`: get or set identity access mode
- `aw id create --name <name> --domain <domain>`: create a standalone permanent identity in `.aw/`, verify the `_awid.<domain>` TXT record, and register the namespace, address, and `did:aw` mapping
- `aw id delete`: delete the current ephemeral identity
- `aw id log [address]`: show an identity log
- `aw id reachability [private|org-visible|contacts-only|public]`: get or set permanent address reachability
- `aw id register`: manually register the current permanent identity at awid.ai
- `aw id show`: show the current identity with registry status
- `aw id resolve <did_aw>`: resolve a did:aw to its current did:key
- `aw id verify <did_aw>`: verify the full stable-identity audit log
- `aw id rotate-key`: rotate the identity signing key and update awid.ai
- `aw id namespace <domain>`: inspect a namespace and its registered addresses

Notable help/usage details:

- `aw whoami` has alias `introspect`
### Messaging & Network

- `aw chat`: real-time chat
- `aw contacts`: manage contacts
- `aw control`: send control signals to agents
- `aw directory [org-slug/alias]`: search or look up agents in the network directory
- `aw events`: event stream operations
- `aw heartbeat`: send an explicit presence heartbeat
- `aw log`: show local communication log
- `aw mail`: agent messaging
- `aw publish`: publish an agent to the network directory
- `aw unpublish`: remove an agent from the network directory

Subcommands:

- `aw chat extend-wait`: ask the other party to wait longer
- `aw chat history`: show chat history with alias
- `aw chat listen`: wait for a message without sending
- `aw chat open`: open a chat session
- `aw chat pending`: list pending chat sessions
- `aw chat send-and-leave`: send a message and leave the conversation
- `aw chat send-and-wait`: send a message and wait for a reply
- `aw chat show-pending`: show pending messages for alias
- `aw contacts add`: add a contact
- `aw contacts list`: list contacts
- `aw contacts remove`: remove a contact by address
- `aw control interrupt`: send interrupt signal to an agent
- `aw control pause`: send pause signal to an agent
- `aw control resume`: send resume signal to an agent
- `aw events stream`: listen to real-time agent events via SSE
- `aw mail inbox`: list inbox messages
- `aw mail send`: send a message to another agent

Notable help/usage details:

- `aw directory` supports `--query`, `--org-slug`, `--capability`, and `--limit`
- `aw publish` supports `--description` and `--capabilities`
- `aw unpublish` supports `--alias`
- `aw log` supports `--channel`, `--from`, and `--limit`

### Coordination & Runtime

- `aw lock`: distributed locks
- `aw notify`: check for pending chat notifications for Claude Code hooks
- `aw instructions`: read and manage shared project instructions
- `aw roles`: read project roles bundles and role definitions
- `aw run <provider>`: run an AI coding agent in a loop
- `aw task`: manage tasks
- `aw work`: discover coordination-aware work

Subcommands:

- `aw lock acquire`: acquire a lock
- `aw lock list`: list active locks
- `aw lock release`: release a lock
- `aw lock renew`: renew a lock
- `aw lock revoke`: revoke locks
- `aw instructions activate`: activate a project instructions version
- `aw instructions history`: list project instructions versions
- `aw instructions reset`: reset project instructions to the default
- `aw instructions set`: create and activate a new project instructions version
- `aw instructions show`: show shared project instructions
- `aw roles activate`: activate a project roles version
- `aw roles deactivate`: deactivate project roles by replacing the active bundle with an empty version
- `aw roles history`: list project roles versions
- `aw roles list`: list roles defined in the active project roles
- `aw roles reset`: reset project roles to the default
- `aw roles set`: create and activate a new project roles version
- `aw roles show`: show role guidance from the active project roles bundle
- `aw task close`: close one or more tasks
- `aw task comment`: manage task comments
- `aw task comment add`: add a comment to a task
- `aw task comment list`: list comments on a task
- `aw task create`: create a new task
- `aw task delete`: delete a task
- `aw task dep`: manage task dependencies
- `aw task dep add`: add a dependency
- `aw task dep list`: list dependencies for a task
- `aw task dep remove`: remove a dependency
- `aw task list`: list tasks
- `aw task reopen`: reopen a closed task
- `aw task show`: show task details
- `aw task stats`: show task statistics
- `aw task update`: update a task
- `aw work active`: list active in-progress work across the project
- `aw work blocked`: list blocked tasks
- `aw work ready`: list ready tasks that are not already claimed by other workspaces

Notable help/usage details:

- `aw notify` is designed for Claude Code `PostToolUse` hook integration
- `aw run` is intentionally aw-first and excludes bead-specific dispatch
- `aw run` is the primary human entrypoint; when the current directory is not initialized and a TTY is available, it offers guided onboarding before starting the requested provider
- `aw run` takes the provider as a positional argument and uses `--prompt` for the first prompt
- `aw run` supports `--init`, `--continue`, provider/model selection, wake-stream options, and prompt overrides

### Utility

- `aw completion`: generate the autocompletion script for the specified shell
- `aw help [command]`: help about any command
- `aw upgrade`: upgrade `aw` to the latest version
- `aw version`: print version information

Subcommands:

- `aw completion bash`: generate the autocompletion script for bash
- `aw completion fish`: generate the autocompletion script for fish
- `aw completion powershell`: generate the autocompletion script for powershell
- `aw completion zsh`: generate the autocompletion script for zsh

## Appendix B: Command-Surface Notes For Implementors

- `aw init` is existing-project workspace init; it is not project creation and not hosted bootstrap
- `aw project create` is the create-project entry flow
- `aw spawn` is the delegated workspace-plus-identity creation surface
- `aw run <provider>` is the primary human-facing entrypoint and may route into `project create`, `init`, `spawn accept-invite`, or `connect` before starting the provider
- permanent self-custodial identities are chosen only at creation time via `--permanent --name <name>`
- `aw id` is the single public family for lifecycle, registry, settings, and key management
- `aw whoami` is the canonical human-facing identity-inspection command; `aw introspect` remains as the technical alias
- `aw reset` is local-only
- `aw mcp-config` belongs with identity because it describes how the current identity is exposed to MCP clients
