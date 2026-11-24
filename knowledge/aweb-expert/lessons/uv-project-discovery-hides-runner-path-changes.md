---
type: Lesson
title: uv project discovery hides runner-path changes inside the repository
description: uv run --project walks up to the nearest pyproject.toml and, with none, falls back to the working directory's project and the active virtualenv, so a script's changed project path passes under pytest whether right or wrong; show it red with the working directory outside the repository, VIRTUAL_ENV removed and a project that is not the repository's.
tags: [lesson, testing, uv, python, deployment, harness]
timestamp: 2026-11-24
---

Found on 2026-11-24 while extracting deployment tooling into its own
repository. A shell script ran its Python helper with
`uv run --project "$REPO_ROOT/server"` (the old layout) and was changed to
`--project "$REPO_ROOT"`. The test suite passed with both. It went red only
with `--project` pointing at an empty directory, the working directory outside
the repository and no `VIRTUAL_ENV`, failing with a missing dependency.

# The mechanism

- `uv run --project <dir>` looks for the nearest `pyproject.toml` at or above
  `<dir>`. A project path that points at a subdirectory of the repository
  silently resolves to the repository's project.
- With no project at or above `<dir>`, uv still finds an environment: the
  project of the working directory, or the active virtualenv.
- pytest runs from the repository root inside the repository's environment,
  so every one of those fallbacks succeeds there.

The harvester reproduced this on uv 0.13.9: a project path pointing at a
subdirectory or at an empty directory outside the repository both ran with
the repository's environment when the working directory was the repository.
With the working directory outside and `VIRTUAL_ENV` set, the empty project
also ran. Only with the working directory outside and `VIRTUAL_ENV` unset did
it fail with `ModuleNotFoundError`.

# How to apply

- A green suite proves nothing about a script's runner path. Its operator runs
  it from elsewhere, without the repository's virtualenv.
- The regression test runs the script with the working directory outside the
  repository and `VIRTUAL_ENV` removed from its environment.
- Its red comes from a mutation that points `--project` at a directory that
  is not this repository's project, and the red's text must name the missing
  dependency, as [a harness must be shown to
  fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md) requires.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-repo, 2026-11-24;
notes/uv-project-discovery-hides-runner-changes.md. The deployment repository
commit with the test and its mutation control (4eebece) is source-reported;
the uv behaviour was reproduced by the harvester.
