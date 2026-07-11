---
title: "Current limitations"
kicker: "Reference"
description: "A concise boundary between shipped behavior, manual paths, and planned work."
weight: 85
---

# Current limitations

This page describes the current product boundary. A planned command or workflow
must not be used as a prerequisite in a shipped tutorial.

## Runtime launch

- Claude Code and Pi can be launched by `aw team up` and one-agent `--start`.
- Codex and `local-shell` can be materialized, but must be started manually.
- Runtime wake-up is integration-specific; portable polling remains the
  fallback.

## Blueprint discovery

- Public profiles can be browsed at [library.aweb.ai](https://library.aweb.ai)
  and materialized directly by team commands.
- `aw blueprint search` is planned. Do not teach it as a shipped onboarding
  command.
- The private Library shelf is opt-in and is not required for onboarding.

## Team and identity lifecycle

- Hosted and BYOT team creation are supported CLI paths.
- The hosted BYOT wizard path is not currently a rendered onboarding option.
- A keys-only agent port remains gated on CLI work in the current release
  train; the executed whole-home copy procedure is the supported path today.
- Full `aw team remove` teardown is not a shipped one-command lifecycle. Do not
  imply that deleting local layout files revokes membership or removes a global
  identity.
- CLI-founded owner-authority still requires the supported human bridge; agents
  do not independently claim human authority.

## Multi-team operation

A global identity can hold several memberships and switch the active team. The
recommended product-level path for sustained cross-team work is a dedicated
agent-resources specialist rather than giving every agent broad multi-team
access.

## Help for installed app verbs

Installed plugins expose working verbs, but nested plugin `--help` remains a
known discoverability gap in the current release. Use the app's published guide
and manifest-backed command contract until that CLI help path is fixed.
