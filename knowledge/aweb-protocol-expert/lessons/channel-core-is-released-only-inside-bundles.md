---
type: Lesson
title: channel-core is released only inside bundles
description: "@awebai/channel-core has never been published to npm; it reaches users only as esbuild bundles inside @awebai/claude-channel, @awebai/pi and aw wake, so a channel-core symbol that src/index.ts does not re-export and no in-repo package imports is not a released API and may be unexported. Recheck before relying on it: a channel-core release lane would end this."
tags: [lesson, compatibility, release, channel-core, npm]
timestamp: 2026-11-19
---

channel-core's `package.json` has no `exports` map and its `files` ships all of
`dist/`, so read from the source tree every dist module looks deep-importable,
and an unused-export cleanup looks as if it might narrow a released API. It
does not, because the package itself has never been released. This applies
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md):
that rule binds what was released, and this records what was.

# What establishes it

Checked on 2026-11-19; all three must still hold before relying on it.

- `npm view @awebai/channel-core` returns E404, while `@awebai/claude-channel`
  and `@awebai/pi` resolve publicly.
- The npm release lanes (`NPM_LANES` in `scripts/publish_release.py`) publish
  only `@awebai/claude-channel`, `@awebai/pi` and `@awebai/claude-skills`.
- No published version of claude-channel or pi lists channel-core as a
  dependency or bundled dependency; their tarballs (latest checked:
  claude-channel 1.8.3, pi 0.5.0) carry one esbuild bundle with no channel-core
  paths. aw wake embeds its own bundle,
  `cli/go/wake/channel_core_runner_bundle.mjs`.

# How to apply

- A channel-core symbol that `src/index.ts` does not re-export, and that
  nothing in `channel`, `pi-extension` or `scripts` imports, may be unexported.
  The released surfaces are the channel and pi entry points.
- The day a channel-core release lane appears, this stops being true; recheck
  the three points above first.
- Limit: an E404 cannot exclude a private publish under another account.
  Nothing in the repository's history or release tooling suggests one.

The coordinator accepted this evidence for the unexports made in the same
review (source-reported).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-19; notes/channel-core-ships-only-bundled.md. Verified by the harvester on 2026-11-19: npm returns E404 for @awebai/channel-core, and `NPM_LANES` on aweb main (ecb9d825a) names only the three packages above.
