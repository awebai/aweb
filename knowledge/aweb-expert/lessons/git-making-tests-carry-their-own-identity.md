---
type: Lesson
title: Tests that make commits or tags carry their own git identity
description: The gate's runner has no git identity while a Mac infers one from the hostname, so a test that commits or tags in a fresh repository passes locally and fails only in the gate; give the fixture its own identity and reproduce under strict git config before trusting a local pass.
tags: [lesson, gate, testing, git, release]
timestamp: 2026-11-25
---

The aweb gate's runner has no git identity. On a developer's Mac, git still
infers one from the user and hostname. A test that makes a commit or an
annotated tag in a fresh repository therefore passes locally and fails only
in the gate, with "Committer identity unknown".

This happened to the release command's tests. The command makes an annotated
tag as whoever runs it. The tests passed on the Mac and failed in the
1.27.55 gate (four tests in the shipping checks), at the cost of a gate run of
about 36 minutes. Some tests in the repository already ran under a strict
configuration, but a new test file did not follow them, and nothing forced it
to.

# How to apply

- Every test fixture that creates commits or tags sets its own identity:
  `GIT_AUTHOR_*` and `GIT_COMMITTER_*`, or a repository-local `user.name` and
  `user.email`.
- Before trusting a local pass of such a test, reproduce the gate's
  condition. Run it with `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`
  and `user.useConfigOnly=true` passed through `GIT_CONFIG_COUNT`,
  `GIT_CONFIG_KEY_0` and `GIT_CONFIG_VALUE_0`. See it fail without the
  fixture identity first, then pass with it.

The elimination route is not built yet: a shared script-test harness that
runs every git-making test under the strict configuration on every machine.
Until it exists, this lesson is the guard.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-25;
notes/gate-runner-has-no-git-identity.md. Failed run vm-5a28b049; fixed in
aweb df2f356b45, with the strict-config reproduction seen red first. The
release run vm-e6ea6ce5 was green before aweb 1.27.55 was published. One
occurrence.
