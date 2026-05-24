# aweb-skills for Codex

Codex plugin packaging for the canonical aweb skill bodies.

This directory is **not** the source of truth. The four skill bodies live at
[`aweb/skills/`](../../skills/). The `skills/` subdirectory here holds
generated copies of those bodies, produced by [`sync-skills.sh`](./sync-skills.sh)
and committed to Git so the marketplace's `git-subdir` install delivers a
self-contained plugin.

## What this plugin ships

Four skills, auto-discovered from the bundled `skills/` directory:

- **`aweb-coordination`** — session/work-loop policy.
- **`aweb-messaging`** — mail/chat policy + channel-awakening response.
- **`aweb-team-membership`** — joining, BYOT, custody, addressability,
  inbound mode, contacts.
- **`aweb-bootstrap`** — creating a new aweb team from a template.

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

## Maintaining the bundled `skills/`

Before committing any change to either `aweb/skills/` (canonical) or this
directory, run:

```bash
./sync-skills.sh
```

The script copies the four canonical skill directories into
`packages/codex-plugin/skills/` and reports the count. The copies must be
checked in: Codex's plugin installer treats `skills:` paths as relative to the
plugin root and does not follow symlinks out of it, so a real directory of
files is the only working shape. Manifest paths must "stay inside the plugin
root" per the [Codex plugin docs](https://developers.openai.com/codex/plugins/build).

If `aweb/skills/` and `packages/codex-plugin/skills/` ever drift, the script is
idempotent — re-run it and commit the diff.

## Versioning

`plugin.json` `version` is independent of `aweb/cli/go` and the aweb server.
Track skill-body changes here, mirroring how `@awebai/pi` and
`@awebai/claude-channel` carry their own semver alongside aweb releases.
