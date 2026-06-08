---
title: "aw setup surface taxonomy"
kicker: "Product SOT"
description: "How aw presents team, identity, workspace, template, and protocol/admin setup operations."
weight: 23
---

# aw setup surface taxonomy

This document is the source of truth for the customer-facing `aw` setup
surface. It classifies team, identity, workspace, template, and BYOT operations
so the CLI, docs, dashboard copy, and agent skills all teach the same model.

The goal is not to remove protocol power from `aw`. The goal is to make the
normal path match what people actually want to do, and to keep protocol/admin
plumbing available without presenting it as the happy path.

Do **not** use "advanced" as the bucket name for hidden or uncommon operations.
The distinction is not beginner versus expert. The distinction is:

1. everyday human intent;
2. safe primitive an agent can compose;
3. protocol/admin operation for controller holders and debugging;
4. obsolete/legacy compatibility surface.

## Why this taxonomy exists

The current bootstrap-era product center combines too many boundaries in one
command. A single `aw agents bootstrap` invocation may read a template, create
or join a team, create identities, install roles/instructions, write files,
edit gitignore, and create worktrees. A partial failure can strand local layout
state before hosted team/account setup completes. Retrying then fails because
`agents/` already exists, while `provision` cannot create the missing hosted
team.

That failure mode is a symptom of the wrong abstraction. Setup must keep these
concerns separate:

- identity and team membership authority;
- workspace connection to a coordination service;
- role/instruction/team operating context;
- template/resource-pack application;
- local filesystem and git worktree mutation.

A convenience command may compose primitives, but it must never make the
boundaries invisible in ways that create unrecoverable partial state.

## Vocabulary

### Everyday human intents

Everyday intents are the verbs people expect when they are setting up or
operating a team. They should be visible in primary docs and easy to discover
from CLI help.

Canonical intents:

- **Create a team** — create a hosted team by default; choose BYOT only when the
  user explicitly brings a customer-controlled domain/team.
- **Create an identity** — create or prepare the identity an agent will act as.
- **Invite/add an agent** — produce a join path for another agent/workspace;
  invite-and-accept is the normal hosted flow.
- **Join a team** — accept an invite or install an approved membership in a
  clean workspace.
- **Remove an agent** — remove or deprovision a member while respecting hosted
  versus BYOT authority and preserving global addresses unless explicitly
  deleted.
- **Connect workspace** — make this directory's existing identity/certificate
  usable against a coordination service.
- **Set team context** — publish or select team instructions, role bundles, and
  workspace role names.
- **Check/doctor** — explain who this directory is, which team it acts in,
  whether the service connection is live, and how to repair mismatches.

### Agent primitives

Agent primitives are small, scriptable commands that skills can safely compose.
They should have clear preconditions, refuse unsafe overwrites, produce useful
plain output, and support `--json` where practical.

A primitive may still use protocol concepts in its flags when that is the
lowest-risk interface. Skills are responsible for selecting the right primitive
and explaining why.

### Protocol/admin primitives

Protocol/admin primitives expose controller, certificate, registry, BYOT,
projection, and recovery operations. They are legitimate and supported, but
they are not the everyday hosted setup story.

Use this label when the user is:

- holding a namespace or team controller key;
- importing/syncing a customer-controlled BYOT team;
- minting, fetching, revoking, or diagnosing AWID certificates;
- assigning namespace addresses;
- cleaning up service projections;
- debugging trust or registry state.

### Obsolete/legacy compatibility

Obsolete/legacy compatibility commands are kept for existing users and scripts,
but should not be taught as the product center. These are usually commands that
combine identity/team mutation with filesystem/template/git mutation, or that
represent a retired setup model.

The term "obsolete" is a product signal, not permission to make the commands
unsafe. Legacy commands must still preserve identity/key safety and fail before
partial side effects when required inputs are missing.

## Command classification

This table classifies today's surface and gives the intended presentation. It
is a planning SOT; implementation may add wrappers or aliases, but should keep
the categories stable unless this document is updated.

### Everyday human-facing commands

| Current command/action | Classification | Intended presentation |
| --- | --- | --- |
| `aw run <provider>` | Everyday intent + runtime entrypoint | Primary way to start an agent session; may suggest setup, but setup mutations stay explicit and should not become hidden orchestration. |
| `aw init` | Everyday connect/create workspace intent | Keep prominent. Copy should say it initializes/connects this directory as a workspace. |
| `aw service init` | Everyday connect workspace intent | Keep prominent for already-certified AWID identities connecting to a service. |
| `aw whoami` | Everyday check | Keep prominent. |
| `aw workspace status` | Everyday check/doctor | Keep prominent. It should explain active team, identity, claims, locks, service binding, and mismatch symptoms. |
| `aw doctor` | Everyday check/repair | Keep prominent as the support entrypoint for confusing local state. |
| `aw id team list` / `switch` / `leave` | Everyday membership management backed by primitives | Keep discoverable; consider human-facing aliases if taxonomy implementation adds `aw team ...`. |
| `aw roles`, `aw role-name`, `aw instructions` | Everyday team context + agent primitives | Keep prominent for team operating context. |
| `aw mail`, `aw chat`, `aw work`, `aw task`, `aw lock` | Everyday coordination | Out of setup scope, but remain primary day-to-day commands. |

### Agent primitives to keep sharp

| Current command/action | Classification | Notes |
| --- | --- | --- |
| `aw id team invite` | Agent primitive / human invite verb | Normal hosted add-agent starts here. It may use hosted cloud authority or local controller authority depending on team context. |
| `aw id team accept-invite <token>` | Agent primitive / human join verb | Must refuse to overwrite existing `.aw` identity/key state. Prints `aw init`/connect next step when needed. |
| `aw id create --domain --name` | Agent primitive for standalone self-custodial global identity | Identity-only. Skills must distinguish it from `aw init --global`, which also connects a workspace. |
| `aw id encryption-key setup|rotate|show` | Agent primitive for E2E readiness | Keep in identity skills; not a team setup happy path. |
| `aw service init` | Agent primitive / everyday connect workspace | Connects an existing identity+cert to a service; does not create team/identity/membership. |
| `aw roles set|activate|show|list` | Agent primitive for team context | Publishing roles is a team-context mutation, not template bootstrap side effect. |
| `aw instructions set|activate|show` | Agent primitive for team context | Publishing instructions is a team-context mutation, not template bootstrap side effect. |
| `aw contacts`, `aw inbound-mode` | Agent primitives for addressability policy | Keep in identity/messaging skills. |

### Protocol/admin primitives

| Current command/action | Classification | Presentation rule |
| --- | --- | --- |
| `aw id namespace prepare-controller` | Protocol/admin BYOT primitive | Show only in BYOT/controller setup docs and skills. It is local-only and creates controller authority. |
| `aw id namespace check-txt` | Protocol/admin BYOT primitive | BYOT DNS verification; not hosted happy path. |
| `aw id namespace assign-address` / `delete-address` / `set-delivery-origin` / `rotate-controller` / `delete` | Protocol/admin primitives | Controller-holder operations. Keep documented in protocol/admin reference. |
| `aw id team create` | Protocol/admin BYOT primitive; possible human BYOT create-team step | Creates AWID team with customer controller. Do not present as hosted default create-team. |
| `aw id team add-member` / `remove-member` | Protocol/admin certificate primitives | Controller signs/revokes membership. Hosted users should normally use invite/dashboard flows. BYOT controller holders use these directly. |
| `aw id team fetch-cert` | Protocol/admin/agent primitive bridge | Installs a cert minted elsewhere. Use in BYOT cross-machine and hosted add-existing-identity flows. |
| `aw id team request` | Protocol/admin bridge primitive | Joiner prints the controller-side add-member command. Useful for BYOT; not the hosted invite happy path. |
| `aw id team register` | Protocol/admin service projection primitive | Registers/syncs customer-controlled AWID team with a service; does not initialize workspaces. |
| `aw id team import-request` | Protocol/admin BYOT import primitive | Signs customer-controller import/sync payload for AC/aweb Cloud. Never ask for private controller keys in dashboard. |
| `aw id team cleanup-cloud` | Protocol/admin cleanup primitive | Projection cleanup after registry team deletion or recovery. |
| `aw id team delete` | Protocol/admin destructive primitive | AWID team deletion after revocation; controller-holder only. |
| `aw id register` / `resolve` / `verify` / `addresses` / `log` / `sign` / `request` | Protocol/admin or diagnostic identity primitives | Keep available for debugging, automation, and registry-aware tooling. |
| hidden `aw connect --bootstrap-token` | Protocol/bootstrap plumbing | Keep hidden unless a current dashboard flow still emits it; prefer clearer connect/join wording where possible. |

### Obsolete/legacy compatibility candidates

| Current command/action | Classification | Required compatibility behavior |
| --- | --- | --- |
| `aw agents bootstrap` | Obsolete/legacy compatibility once replacement resource-pack flow lands | Keep callable short-term. Stop teaching as happy path. Fail before filesystem/git side effects when team source cannot be resolved. Provide recovery for partial state. |
| `aw agents provision` | Obsolete/legacy compatibility | Keep for existing `agents/` layouts. Make error messages point to invite/API key/BYOT/current-workspace sources and resource-pack replacement guidance. |
| `aw agents plan` | Compatibility diagnostic for old layout | Keep while old layouts exist; avoid teaching as new template planning model. |
| `aw agents add` | Obsolete/legacy compatibility if it mutates shared layout + identity state | Prefer separate primitives: invite/join/connect workspace, then resource-pack/application steps. |
| `aw agents add-worktree` | Obsolete/legacy compatibility if it couples template layout with identity/worktree setup | Prefer explicit git/filesystem primitives, then `aw init`/invite/join/connect primitives and skills/resource application. |
| `aw workspace add-worktree` | Local convenience/compatibility for existing users | Future skills should prefer explicit `git worktree`/filesystem steps followed by `aw init`/invite/join/connect primitives, unless this command is reduced to a transparent wrapper with no identity/team/template magic. |
| `aw agents remove` | Compatibility command with strong safety constraints | Removal/deprovision may remain useful, but must clearly separate layout removal, membership revocation, local `.aw` state movement, worktree cleanup, and address deletion. |
| `aw init --byod` wording | Retired middle-ground risk unless carefully scoped | If retained, copy must not imply the BYOT controller-first import path. BYOT docs should teach controller primitives. |
| bootstrap-era template repos | Obsolete template model | Replace with resource-pack templates. Old repos should redirect or clearly mark legacy/compatibility. |

## Desired everyday flows

### Create a hosted team

The hosted happy path should not require namespace, controller, certificate, or
AWID vocabulary. The user wants a team they can invite agents into.

Implementation may be dashboard-first or CLI-first, but the copy should be:

1. create team;
2. invite/connect agents;
3. set instructions/roles;
4. check status.

### Invite/add an agent to a hosted team

Canonical flow:

1. inviter creates an invite from a workspace or dashboard that has hosted team
   authority;
2. joiner accepts the invite in a clean directory;
3. joiner connects the workspace if the accept step did not already bind it;
4. both sides verify with `aw workspace status` / dashboard agent list.

The user should not have to understand certificate IDs on the hosted default
path.

### Join a BYOT team

BYOT is explicit. The joining identity can request membership, but the customer
controller holder signs the team certificate.

Canonical cross-machine BYOT flow:

1. joiner has or creates the identity;
2. joiner prints a request/add-member command;
3. controller holder runs the customer-controller command;
4. joiner fetches the certificate and connects the workspace;
5. controller holder imports/syncs the team projection to a service when needed.

This is protocol/admin because the customer chose BYOT.

### Remove an agent

Removal must diagnose authority and split effects:

- membership revocation/deprovision;
- local `.aw` state preservation or explicit move-aside;
- generated worktree cleanup if any;
- shared template/resource references;
- global address deletion only when explicitly requested and authorized.

Never imply that removing a layout resource automatically revokes another
human's certificate.

### Connect workspace and check/doctor

The support entrypoint should answer:

- does this directory have `.aw/signing.key` or custodial context?
- does it have a team certificate for the selected team?
- is `active_team` correct?
- is `workspace.yaml` connected to the intended service?
- can the service see the workspace/identity?
- what exact next command fixes the mismatch?

This deserves first-class visibility because many failures look like "files are
initialized" locally but the team/service view is disconnected.

## Resource-pack template contract summary

New templates are resource packs. They may include:

- harness-neutral Markdown roles, instructions, playbooks, and operating notes;
- AGENTS.md fragments/resources;
- skills and references;
- adapter examples for Claude Code, Pi, Codex, Cursor, or other harnesses;
- suggested application steps that agents can perform with ordinary file/git
  primitives.

They must not include canonical harness-specific files as the source of truth.
In particular, a template core should not treat `CLAUDE.md` as canonical.
CLAUDE/Pi/Cursor-specific outputs are adapters or generated examples. The core
resources should be harness-neutral Markdown so skills can adapt them to the
current runtime.

They must not include final aliases, DIDs, addresses, certificates, `.aw` state,
or generated work symlinks.

Applying a resource pack is separate from creating identities, inviting agents,
connecting workspaces, and creating git worktrees.

## Implementation plan

1. Land this SOT and get review before broad CLI/help churn.
2. Update CLI grouping/help and generated reference docs to reflect the
   categories.
3. Add or sharpen first-class human verbs/aliases for create team, invite/join,
   remove, connect workspace, and check/doctor.
4. Fix bootstrap/provision recoverability immediately for compatibility users.
5. Update skills so agents compose primitives and no longer center monolithic
   bootstrap.
6. Define and validate resource-pack templates.
7. Replace `aweb-team-coord-worktrees` and `aweb-team-company-surfaces` with
   resource-pack designs or clear successor repos.
8. Update AC dashboard, site, and public docs copy.
9. Add release gates for help/docs drift, no-TTY partial-bootstrap regression,
   skills packaging, template validation, and end-to-end invite/join/remove
   journeys.

## Compatibility guardrails

All compatibility commands, including obsolete/legacy ones, must obey these
rules:

- no automatic overwrite of `.aw` identity state;
- no automatic deletion of private signing, encryption, namespace controller,
  or team controller keys;
- no partial filesystem/git side effects before required hosted inputs are
  available in non-TTY flows;
- explicit dry-run or plan output where mutation spans more than one boundary;
- structured errors that identify whether the fix is hosted, BYOT,
  protocol/admin, or local workspace state;
- recovery paths must inspect and preserve state before cleanup.

## Docs and skills rules

- Hosted happy-path docs should not introduce namespace/team controller concepts
  unless the user chose BYOT or is debugging/administering.
- BYOT docs must be precise about customer-held namespace and team controller
  authority.
- Skills should teach decision policy and safe primitive composition. They
  should not be long flag references; `aw --help` and generated command docs are
  the syntax reference.
- Any command shown in a skill must be source-grep verified against current CLI
  help before release.
