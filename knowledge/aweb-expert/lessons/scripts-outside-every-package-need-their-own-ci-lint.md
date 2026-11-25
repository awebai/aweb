---
type: Lesson
title: Scripts outside every package need their own CI lint
description: Repository-level scripts, release tooling included, sit outside every package's lint, and their unit tests rarely cover every path; a NameError in a release publisher passed its tests and would have surfaced only at the first real publication, so put a lint for those scripts in CI.
tags: [lesson, ci, lint, release, python, review]
timestamp: 2026-11-25
---

In the apps repository a change removed a name from
`scripts/publish_release.py` and left two uses behind, on the publisher's
routing path. `make test-scripts` passed because no test exercised that path,
and CI then ran the script tests but did not lint `scripts/`. The NameError
would have surfaced only at the first real image publication. `ruff`'s F821
(undefined name) caught it before that (defect naapp 9a261685c, fixed in
57fc99774).

The elimination route was taken: the apps repository's CI now lints the
scripts (14c136b43).

# How to apply

- When reviewing or creating a repository's CI, check that every Python file
  outside the packages, `scripts/` and release tooling above all, is covered by
  a lint job. Package lint configurations do not reach them.
- Until such a job exists, lint changed scripts before committing.
- A grep for a removed name is no proof by itself: in zsh an unmatched glob
  such as `--include=*.py` aborts the command with "no matches found", which
  can read as "no uses".

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-25;
notes/lint-scripts-before-commit.md. The CI lint commit is from the proposal;
the note predates it.
