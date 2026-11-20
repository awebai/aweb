---
type: Lesson
title: Staged credentials need private directories from the start
description: When a stage writes credentials into an externally prepared directory tree and fixes owners and modes only afterwards, validate that every directory that will receive them is private (no group or other access) before the first write, the run directory included; ownership and emptiness checks, a wrapper umask or a later chmod do not close the window.
tags: [lesson, security, secrets, deployment, permissions]
timestamp: 2026-11-13
---

Learned on 2026-11-13 while staging a team deployment into an
operator-provided secrets directory for the real-agent run.

Staging code commonly writes passwords and keys with the process umask (022,
so files land 0644) and only afterwards chowns and chmods each component to
its service's uid. The first version of the operator secrets-dir check
accepted pre-created component directories that were owned by the staging
user and empty, but did not look at their modes. With a 0755 component
directory, the database password sat world-readable at 0644 until the later
chmod. The independent reviewer reproduced it with the exact staging function
on disposable files and refused the change.

# How to apply

- When a stage validates an externally prepared tree that will receive
  credentials, check modes as well as owners: refuse any group or other
  access on every receiving directory.
- Run the check before anything is created. Creating the run directory is
  already a first write.
- Do not count on a wrapper's umask or on the chmod that follows the write;
  neither covers the window between them.
- A parent that must stay traversable (0755 for a root-run receiver) may do
  so; its children carry the privacy.
- Show the check failing on the layout it guards against (a 0755, 0750 or
  otherwise group- or other-reachable component directory) before trusting
  it, as in
  [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Elimination route

For the team deployment journey this is now code: `check_operator_secrets`
refuses any component directory with group or other access before the run
directory or any credential is written, with mode controls in its tests. The
lesson guards the next stage that validates an operator-provided layout.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13; notes/staged-credentials-need-private-directories.md.
