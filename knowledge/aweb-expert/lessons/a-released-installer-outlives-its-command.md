---
type: Lesson
title: A released installer outlives the command it installs
description: When a released aw wrote a command line into the user's own configuration, server request counts cannot show that command unused, because installed hooks that never call the server still run it; measure the config writers, not the route, and keep a no-op command when hosts cannot be reached.
tags: [lesson, removal, compatibility, released-clients, hooks]
timestamp: 2026-11-27
---

`aw activity hook install --codex`, released in aw v1.36.41, writes the
constant command `aw activity hook` into the Codex hooks file for seven
events, whether publishing is on or not. The activity route had zero requests
in 14 days, which looked like proof that nobody used the feature. It was not:
an installed but disabled hook never calls the server, yet a newer aw without
the command would print `unknown command "activity"` and exit 1 on every one
of those hook events.

Whatever a released installer wrote outside our packages (shell hooks, a
runtime's hook file, cron, launchd) keeps calling the command after an
upgrade. Hooks shipped inside a plugin leave with the plugin; entries in the
user's own configuration do not.

# How to apply

- Before removing a command, search released code for installers that write
  its command line into user configuration.
- If there are any, the removal needs evidence that no host has the entries,
  or a no-op command: hidden, offline, identity-neutral, reading and
  discarding its input, writing nothing and exiting 0. Add a CHANGELOG
  instruction to delete the entries, and remove the stub in a later change.
- The stub is a compatibility bridge, so it needs Juan's approval. In E1 (b)
  the coordinator chose to keep the no-op (option B) on Juan's approval of
  cheap bridges for released clients, as relayed to the source on
  2026-11-27.

This refines
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
for removals: "measured that nobody sends it" has to cover callers the server
cannot see.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-e1-removals, 2026-11-27;
notes/released-hook-config-outlives-the-command.md. Checked by the harvester:
the installer constant and its seven hook entries in
`cli/go/cmd/aw/activity_install.go` and its test at aweb main 90519b0d2, and
commit 924b23e9e8 on the E1 removal branches (not yet on main), which records
the zero-request count, the unknown-command failure and the kept no-op. Juan's
approval is source-reported (relayed), not verified.
