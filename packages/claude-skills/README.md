# `@awebai/claude-skills`

Content-only Claude Code plugin packaging the three canonical aweb skills:
`aweb-coordination`, `aweb-messaging`, `aweb-team-membership`.

Distinct from [`@awebai/claude-channel`](https://github.com/awebai/aweb/tree/main/channel),
which ships the real-time channel runtime and requires
`--dangerously-load-development-channels`. This package has **no runtime**, no
`bin`, no MCP server config — just the skill bodies. Users who only want
aweb's skill catalog install this one and skip the channel.

## Source of truth

Skill bodies live at [`aweb/skills/`](../../skills/) (canonical). This package
regenerates a local `skills/` directory at npm `prepack` time via the
`sync-skills` script. The local `skills/` is gitignored — it's a build
artifact, not source.

## Install (users)

```text
/plugin marketplace add awebai/claude-plugins
/plugin install aweb-skills@awebai-marketplace
```

No `--dangerously-load-development-channels` flag required — that's only for
the channel plugin.

After install, Claude Code namespaces the skills as `/aweb-skills:<name>` and
discovers them automatically.

## Publish (maintainers)

```bash
cd packages/claude-skills
npm publish --access public
```

`prepack` runs `sync-skills` first, so the published tarball contains current
canonical bodies. Verify with `npm pack --dry-run` before publishing.

After publish, bump the `version` in the marketplace entry at
[`awebai/claude-plugins`](https://github.com/awebai/claude-plugins) and commit
that change.

## Versioning

`@awebai/claude-skills` carries its own semver alongside aweb releases, the
same way [`@awebai/pi`](../pi-extension/) and
[`@awebai/claude-channel`](../../channel/) do. Bump on skill-body changes; not
locked to aweb-server versions.
