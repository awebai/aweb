# aweb skills for Claude.ai (web)

Per-skill ZIP bundles for the **Customize > Skills** upload UI at
[`claude.ai/settings/features/skills`](https://claude.ai/settings/features/skills)
(Pro / Max / Team / Enterprise plans).

This is a **separate distribution surface** from `@awebai/claude-skills`
(which is the Claude Code CLI plugin on npm). Same canonical skill
bodies, different packaging shape: Claude.ai's Skills system expects
one skill per ZIP with `SKILL.md` at the root, not an npm package.

## Build

```bash
./build-zips.sh
# → dist/aweb-coordination.zip
# → dist/aweb-messaging.zip
# → dist/aweb-team-membership.zip
```

Each ZIP contains:

```
SKILL.md                 # canonical body with YAML frontmatter
references/<name>.md     # supporting reference doc (when present)
```

Bodies are copied from canonical `aweb/skills/<name>/` — same source-of-truth
as the Codex plugin and the Claude Code npm package.

## Distribute

The `skills-release.yml` workflow (when extended) attaches these ZIPs to the
GitHub Release created on each `skills-v*` tag. End-user URLs follow the
pattern:

```
https://github.com/awebai/aweb/releases/download/skills-v<X.Y.Z>/aweb-<name>.zip
```

## Why one ZIP per skill

Anthropic's [Agent Skills overview](https://platform.claude.com/docs/en/agents-and-tools/agent-skills/overview)
documents one `SKILL.md` per upload. Multi-skill ZIPs are undocumented
behavior; we ship three discrete ZIPs to stay on the spec.

## Why this exists separately from `@awebai/claude-skills`

`@awebai/claude-skills` ships as an npm-published Claude Code plugin with a
`.claude-plugin/plugin.json` manifest. Claude.ai's web UI doesn't read that
manifest — it expects a bare ZIP of one skill. Two distribution shapes, same
bodies.

## Constraints to know about

- `name` field: max 64 chars, lowercase/numbers/hyphens, no "anthropic"/"claude".
- `description`: max 1024 chars. Current bodies: 266–353 chars (well under).
- Total upload size: under 30 MB per ZIP (we're at kilobyte scale).
- Plan gate: Pro / Max / Team / Enterprise only — Free plan can't upload Skills.
- No org-wide distribution — each Claude.ai user uploads individually.
