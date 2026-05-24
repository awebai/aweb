# aweb-skills for Codex

Codex plugin packaging for the canonical aweb skill bodies.

This directory is **not** the source of truth. The three skill bodies live at
[`aweb/skills/`](../../skills/), and the `skills/` subdirectory here is a
symlink to that canonical location.

## What this plugin ships

Three skills, auto-discovered from the symlinked `skills/` directory:

- **`aweb-coordination`** — session/work-loop policy.
- **`aweb-messaging`** — mail/chat policy + channel-awakening response.
- **`aweb-team-membership`** — joining, BYOT, custody, addressability,
  inbound mode, contacts.

## How it ships to users

Codex pulls this plugin via the marketplace at
[`awebai/codex-plugins`](https://github.com/awebai/codex-plugins), which
references this directory using a `git-subdir` source pointing at
`./packages/codex-plugin` on `awebai/aweb`.

User install:

```bash
npm install -g @awebai/aw                              # prerequisite CLI
codex plugin marketplace add awebai/codex-plugins      # add marketplace
# then install "aweb-skills" via Codex's plugin directory UI
```

## Why a symlink for `skills/`

Codex follows symlinks in skill scan paths. When Codex resolves this plugin via
the marketplace's `git-subdir` source it clones the full aweb repo, so
`skills/ → ../../skills/` resolves correctly.

If a future Codex version stops following symlinks inside `skills:`, the
fallback is a `sync-skills.sh` script that copies bodies into `skills/` at
build time. Try the symlink path first.

## Versioning

`plugin.json` `version` is independent of `aweb/cli/go` and the aweb server.
Track skill-body changes here, mirroring how `@awebai/pi` and
`@awebai/claude-channel` carry their own semver alongside aweb releases.
