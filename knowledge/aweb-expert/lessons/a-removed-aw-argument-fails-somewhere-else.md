---
type: Lesson
title: A removed aw argument fails its callers somewhere else
description: When aw drops a flag or positional, a green Go suite covers only Go callers; server tests that spawn the built aw with argv lists written one token per line, and aw's own printed next-step strings, still pass it, and the server test fails on an unrelated assertion because aw exits on the argument first; grep the command with the lines after it and the usage form, and run the server suite on the head before handover.
tags: [lesson, removal, cli, testing, review]
timestamp: 2026-11-27
---

The Go compile-and-test loop finds every Go caller of a removed argument, so
a green Go suite makes an aw removal look complete. Two kinds of caller sit
outside that loop.

- **Server tests that run the built binary.** They build argv lists for an
  asyncio subprocess, and a formatter writes them one token per line. A
  phrase grep (`add-worktree developer`) and a one-line token grep
  (`"add-worktree", "developer"`) both miss them.
- **aw's printed guidance.** Next-step and usage strings, such as init's next
  step `aw workspace add-worktree <role>`, are plain strings. The Go test for
  them asserts the stale text, so it stays green.

The server failure misleads. aw exits on the removed argument before it gets
to the behaviour the test checks, so the red test is named for, and asserts,
something unrelated. In the E1.7 roles removal `aw workspace add-worktree`
stopped taking a role positional, and the first server run at the commit
failed `test_global_inviter_without_registry_pins_uses_real_discovery`, whose
assertion is about registry discovery, because it still passed `developer`.

# How to apply

- For a removed flag or positional, grep the command name together with the
  lines after it: `git grep -nP -A2 '"<command>",'` across `server/`,
  `scripts/` and `e2e/`. Read the tokens that follow each hit.
- Grep the usage form too (`aw <command> <` and `aw <command> --<flag>`) to
  find printed guidance, docs and the tests that assert their text.
- Run the server suite on the head before handover, not only at the gate.
- When a server test that spawns aw fails after a CLI change, read aw's own
  stderr in the test output before investigating the behaviour its name
  points at.

The elimination route for the guidance strings is a Go test that parses every
printed next-step command against aw's command tree, so a stale suggestion
fails at compile-and-test time. Until that exists this is a search habit.

This extends
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
to callers of aw's own command surface written outside Go.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-e1-removals, 2026-11-27;
notes/cli-argument-removal-has-subprocess-callers.md. Checked by the
harvester: at aweb main fbfa65f22 the server test passes `"add-worktree",`
and `"developer",` on separate lines, and init's next step and its test carry
`aw workspace add-worktree <role>`; commit 1a7572a7e4 on the source's E1.7
branch (task aweb-adzb.10, not yet on main) fixes both. The failing server
run is source-reported.
