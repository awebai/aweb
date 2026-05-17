# aweb Agent Skills Decisions

Date: 2026-05-17

## Canonical location

Canonical customer-facing skill bodies live at the repository root:

```text
skills/<skill-name>/SKILL.md
```

Do not treat `cli/go/skills/` as canonical. Existing content there is legacy seed material and should be migrated or removed.

## V1 skill set

V1 ships three default skills:

- `aweb-coordination` — session/work-loop policy for coordinating with an aweb team.
- `aweb-messaging` — mail/chat/channel-awakening response policy.
- `aweb-team-membership` — joining teams, multi-team membership, workspace binding, hosted vs BYOT, custody, reachability, contacts.

Do not ship separate top-level v1 skills for awid, directory, or channel internals. Those topics appear as references/sections unless a future operator/developer audience needs a dedicated non-default skill such as `awid-operator`.

## Naming

Use the `aweb-` prefix in both directory names and SKILL.md `name` frontmatter so the skills remain unambiguous when copied into `~/.agents/skills/` beside non-aweb skills.

## Frontmatter

Each SKILL.md must include at least:

```yaml
---
name: aweb-...
description: ...
allowed-tools: "Bash(aw *)"
---
```

`allowed-tools` is advisory/experimental across harnesses. Pi does not enforce binary requirements for plain skills; the `@awebai/pi` package separately depends on `@awebai/aw` and performs readiness checks. Do not add custom `requires` metadata to the canonical v1 skills.

## Writing model

Skills teach decision policy and operational playbooks, not exhaustive command or MCP syntax. Agents can inspect `aw --help` or MCP schemas for surface details. Put non-obvious judgment in the skill body:

- when to use mail vs chat
- when to claim work or take a lock
- how to respond to channel awakenings
- how to reason about team membership, hosted/BYOT authority, custody, reachability, and contacts

Keep SKILL.md lean and move longer details to `references/`.
