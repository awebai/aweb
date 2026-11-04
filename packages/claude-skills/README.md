# `@awebai/claude-skills`

Content-only skills package for Claude Code and Pi, shipping the canonical
aweb skills from [`skills/shipped.json`](../../skills/shipped.json): `aweb-coordination`, `aweb-tasks`, `aweb-messaging`,
`aweb-team-membership`, `aweb-bootstrap`, and `aweb-identity`.

`aweb-tasks` applies only when the team has aweb tasks or its instructions say
it uses them. Creating the first task is the opt-in; installing this package
does not choose the team's tracker.

Distinct from [`@awebai/claude-channel`](https://github.com/awebai/aweb/tree/main/channel),
which ships the real-time channel runtime and is started with
`--dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace`
in any permission mode. This package has **no runtime**, no
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

No channel launch flags required — those are only for the channel plugin.

After install, Claude Code namespaces the skills as `/aweb-skills:<name>` and
discovers them automatically.

## Install in Pi

```bash
pi install npm:@awebai/claude-skills@latest
```

Run `/reload` or restart Pi after installing. This installs guidance only; the
channel and CLI come from `pi install npm:@awebai/pi@latest`. An orchestrator
such as OATS may already supply the skills per home, in which case no global
skills install is needed. Neither package opts a team into aweb tasks.

## Publish (maintainers)

Use the tag-only process in [`docs/release.md`](../../docs/release.md). The
candidate gate proves that `package.json` and `.claude-plugin/plugin.json`
carry the same version, and the tag publisher publishes or adopts those exact
bytes. The marketplace intentionally has no duplicate version pin: after npm
marks the package public, a marketplace refresh resolves that published
version directly. There is no second repository bump to remember.

## Versioning

`@awebai/claude-skills` carries its own semver alongside aweb releases, the
same way [`@awebai/pi`](../pi-extension/) and
[`@awebai/claude-channel`](../../channel/) do. Bump on skill-body changes; not
locked to aweb-server versions.
