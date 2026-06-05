# aweb Agent Skills Decisions

Date: 2026-05-17

## Canonical location

Canonical customer-facing skill bodies live at the repository root:

```text
skills/<skill-name>/SKILL.md
```

Do not treat `cli/go/skills/` as canonical. The old seed packs from that directory were migrated or removed when the root `skills/` tree became canonical.

## V1 skill set

V1 ships five default skills:

- `aweb-coordination`: session/work-loop policy for coordinating with an aweb team.
- `aweb-messaging`: mail/chat/channel-awakening response policy.
- `aweb-identity`: keypair, `did:key`/`did:aw`, AWID registry, local vs global identity, custodial vs self-custodial custody, what `aw init` does, addressability, inbound mode, contacts, key rotation, identity-level diagnostics.
- `aweb-team-membership`: team certificates, joining flows organized by team authority (hosted vs BYOT), the custody × authority matrix, accept-invite vs fetch-cert, multiple memberships, fresh BYOT setup. (Identity foundations split out into `aweb-identity` 2026-05-24.)
- `aweb-bootstrap`: creating a new aweb team from a template — template choice, hosted/BYOT/manual modes, project-local `agents/` layout, legacy work-directory/work-repo-url compatibility, optional worktree-bound agents, post-bootstrap validation, re-run safety.

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
- how to reason about team membership, hosted/BYOT authority, custody, addressability, inbound mode, and contacts

Keep SKILL.md lean and move longer details to `references/`.

## Awakening wording discipline

When an external awakening surface tells the agent to load a skill, mirror the awakening's trigger wording near the top of that skill body. This makes the injected event and the skill read like the same playbook.

For v1 aweb channel awakenings, keep the `aweb-messaging` opening aligned with this contract:

> This skill is the playbook for aweb channel awakenings. When you receive an injected aweb mail/chat event, inspect the metadata, respect verification warnings, and respond with aw CLI or the equivalent MCP tool surface for your harness.
