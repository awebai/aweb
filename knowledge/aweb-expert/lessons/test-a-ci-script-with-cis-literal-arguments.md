---
type: Lesson
title: Test a CI-run script with CI's literal arguments
description: Keep at least one test that calls a workflow-run script's main() with the workflow's literal arguments, relative paths included, from a fresh working directory and with the real runner; stubbed runners and absolute temporary directories hid a failure that would have made every CI run red.
tags: [lesson, testing, ci, release]
timestamp: 2026-11-26
---

naapp's `scripts/release_files.py` compared each wheel's `direct_url.json`
with `Path(wheel).as_uri()`. `as_uri()` raises on a relative path. The unit
tests stubbed the install runner, and the tests that ran it for real used
absolute temporary directories. CI calls the script with `--out
release-files`, a relative path, so the new required job would have failed on
every run, and merging it would have turned every CI run red. The split-review
seat's NACK of naapp PR #58 at d44bb4532 caught it before merge.

Fix 579376e4f resolves the output directory to an absolute path, and adds
`test_the_command_builds_into_a_relative_directory_as_ci_names_it`. That test
calls `main()` from a relative working directory, the way CI does.

# How to apply

- For a script that a workflow runs, keep at least one test that calls its
  `main()` with the workflow file's literal arguments, from a fresh working
  directory, with the real runner instead of a stub.
- When reviewing a new CI-run script, compare the arguments its tests pass
  with the ones in the workflow file. Relative paths, defaults and the working
  directory are where they usually differ.

Related: [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-26;
notes/test-the-command-as-ci-invokes-it.md. The harvester checked that commit
579376e4f ("Install-check release files by absolute path, as CI's relative
--out names them") changes `scripts/release_files.py` and
`scripts/test_release_files.py`, and that the test named above is on naapp
main.
