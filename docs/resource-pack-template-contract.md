---
title: "aweb resource-pack template contract"
kicker: "Product SOT"
description: "Contract for new-design templates that package roles, instructions, playbooks, skills, and harness adapters without owning identity or workspace state."
weight: 24
---

# aweb resource-pack template contract

This document defines the replacement model for the bootstrap-era template
repos such as `aweb-team-coord-worktrees` and `aweb-team-company-surfaces`.

A new-design template is a **resource pack**. It packages reusable team
operating resources that a human or agent can inspect and adapt. It is not an
identity, team, workspace, filesystem, or git-worktree mutation plan.

## Design goals

Resource packs should make it easy to answer:

- What roles should this team have?
- What shared instructions should agents read?
- What operating playbooks, checklists, handoff shapes, and review patterns are
  useful?
- What harness adapters should be generated or copied for Claude Code, Codex,
  Pi, Cursor, or other runtimes?
- Which aweb skills should an agent load while applying the pack?

Resource packs must not make setup unrecoverable by mixing these resources with
team membership, identity keys, generated worktrees, or `.aw` state.

## Authority boundaries

A resource pack **never** controls:

- namespace controller keys;
- team controller keys;
- identity signing or encryption keys;
- DIDs, addresses, aliases, team certificates, or cert IDs;
- the active team in `.aw/teams.yaml`;
- service connection state in `.aw/workspace.yaml`;
- git branches or worktrees in the target repo.

Those are created or connected with explicit primitives such as:

```bash
aw team invite
aw team join <invite-token>
aw init
aw workspace connect --service <service-url> --team <team>:<namespace>
aw roles set --bundle-file <path>
aw instructions set --body-file <path>
```

BYOT/controller operations remain protocol/admin primitives and are not hidden
inside templates.

## Required shape

A resource-pack repo should use this shape unless a later versioned schema says
otherwise:

```text
resource-pack.yaml
README.md
resources/
  instructions.md
  roles/
    <role>.md
  playbooks/
    <playbook>.md
  fragments/
    agents.md
skills/
  <skill-name>/
    SKILL.md
adapters/
  claude/
    README.md
  codex/
    README.md
  pi/
    README.md
examples/
  apply.md
```

Only `resource-pack.yaml` and `README.md` are required. Everything else is
optional, but packs that define roles or shared instructions should keep them
under `resources/`.

## `resource-pack.yaml`

The manifest is identity-free. It describes resources and suggested adapters,
not concrete workspaces.

Minimal example:

```yaml
schema_version: 1
name: coordinator-with-dev-review
summary: Coordinator, developer, and reviewer operating resources.
resources:
  instructions: resources/instructions.md
  roles:
    coordinator: resources/roles/coordinator.md
    developer: resources/roles/developer.md
    reviewer: resources/roles/reviewer.md
  playbooks:
    review-loop: resources/playbooks/review-loop.md
skills:
  - skills/aweb-coordination/SKILL.md
adapters:
  claude: adapters/claude/README.md
  codex: adapters/codex/README.md
  pi: adapters/pi/README.md
```

Allowed top-level fields:

| Field | Required | Meaning |
| --- | --- | --- |
| `schema_version` | yes | Integer schema version. Current version: `1`. |
| `name` | yes | Stable resource-pack name. Not an identity alias or team name. |
| `summary` | no | Human-readable description. |
| `resources.instructions` | no | Path to harness-neutral shared instructions Markdown. |
| `resources.roles` | no | Map of role name to harness-neutral role Markdown. |
| `resources.playbooks` | no | Map of playbook key to Markdown. |
| `resources.fragments` | no | Map of fragment key to Markdown snippets. |
| `skills` | no | List of included skill entrypoints. |
| `adapters` | no | Map of harness/runtime name to adapter docs or generators. |
| `examples` | no | List or map of example application docs. |

Forbidden manifest fields:

- `alias`, `default_alias`, `default_name`, `did`, `did_aw`, `address`,
  `certificate`, `cert_id`, `team_id`, `active_team`, `workspace_id`;
- any field whose value is a private key, token, API key, or `.aw` path;
- any field that instructs a tool to create git worktrees or mutate a target
  repo automatically without an explicit applying step.

## Harness-neutral core

The core resources must be harness-neutral Markdown. A resource pack must not
treat `CLAUDE.md`, `.cursorrules`, Pi config, Codex config, or any other
runtime-specific file as the canonical source of truth.

Allowed:

- `resources/instructions.md` as canonical shared team instructions;
- `resources/roles/developer.md` as a canonical role playbook;
- `resources/fragments/agents.md` as a reusable AGENTS.md fragment;
- `adapters/claude/README.md` explaining how to render or copy resources into
  Claude Code-specific files;
- generated examples that are clearly examples, not identity-bearing state.

Forbidden:

- committing final `CLAUDE.md` as the pack's canonical source of truth;
- committing final `.aw/`, `team-certs/`, generated `work` symlinks, or private
  keys;
- embedding final aliases, addresses, DIDs, or certificate IDs;
- relying on a monolithic `aw agents bootstrap` command as the normal apply
  path.

## Applying a pack

An agent applying a resource pack should:

1. Inspect `resource-pack.yaml` and README.
2. Confirm the target team/workspace is already created or choose the correct
   primitive setup path (`aw team invite`, `aw team join`, `aw init`, `aw
   workspace connect`).
3. Copy/adapt harness-neutral resources into a reviewable location in the
   target repo.
4. Publish shared team context explicitly:

   ```bash
   aw instructions set --body-file <adapted-instructions.md>
   aw roles set --bundle-file <adapted-roles.json>
   ```

5. Generate or copy harness adapters only after the human chooses that harness.
6. Record what was applied in a task/comment/mail handoff.

The pack may include helper scripts, but helpers must be dry-run friendly and
must not create identities, accept invites, delete `.aw` state, or create git
worktrees without an explicit command and confirmation.

## Validation checklist

A resource pack is valid when:

- `resource-pack.yaml` exists and declares `schema_version: 1`;
- every manifest path exists;
- no file under the pack contains `.aw/signing.key`, `.aw/team-certs`, private
  key material, API keys, invite tokens, final DIDs, final addresses, or final
  certificate IDs;
- no core resource is named or treated as canonical `CLAUDE.md`/Pi/Cursor
  runtime state;
- README explains which resources are included and how to apply them with
  explicit primitives;
- BYOT/controller operations, if mentioned, are labeled protocol/admin and are
  not part of the hosted happy path;
- old bootstrap-era commands are labeled obsolete/legacy compatibility if they
  are mentioned at all.

## Migration from bootstrap-era templates

Bootstrap-era `team.yaml` fields map to resource-pack resources as follows:

| Bootstrap-era field | Resource-pack replacement |
| --- | --- |
| `instructions.file` | `resources.instructions` |
| `roles.<name>.file` | `resources.roles.<name>` |
| `home/<responsibility>/AGENTS.md` | `resources/fragments/` or harness adapter examples |
| `agents.<responsibility>.role_name` | Suggested application note, not identity state |
| `agents.<responsibility>.identity_scope` | Remove from template; choose identity with setup primitives |
| `agents.<responsibility>.work` | Remove from template; use explicit git/filesystem steps |
| `naming.*` | Remove from template; choose aliases/addresses at invite/join/identity time |
| generated `agents/home/*/.aw` | Forbidden |
| generated `agents/worktrees/` | Forbidden |

Old template repos should either redirect to their replacement resource pack or
clearly mark themselves as obsolete/legacy compatibility.

## Relationship to skills

Skills are the orchestration layer. A resource pack gives the agent reusable
resources; skills tell the agent when and how to apply those resources using
safe primitives.

Use:

- `aweb-team-membership` for invite/join/team membership decisions;
- `aweb-identity` for key custody and global/local identity decisions;
- `aweb-coordination` for tasks, roles, instructions, locks, and handoffs;
- `aweb-bootstrap` only for legacy bootstrap-era layout recovery or migration.
