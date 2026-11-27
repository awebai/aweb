---
type: Lesson
title: Check outside consumers before moving an aweb path
description: In-repo grep and green make targets prove a path move only inside aweb; before moving or deleting a path, check the consumers that pin it from outside the repository and say in the plan which pins move with it.
tags: [lesson, review, paths, consumers, publication]
timestamp: 2026-11-27
---

A search of the repository and a green `make test` show that a move or
deletion is consistent inside aweb. They do not show who outside the
repository pins the path. Those consumers break later and silently: at their
next repin, install or build, not in any aweb gate.

On 2026-11-27, the inventory for a tidy of the aweb root found these kinds of
outside consumers:

- **A hosted documentation publication pin.** It names each aweb doc it
  publishes by path at one pinned commit, and also some non-doc paths (the
  `aw` command source, a server and a package README, the CLI-reference
  regeneration script). A move breaks it only at the next repin.
- **A hosted build that reaches into a sibling aweb checkout** by relative
  path.
- **The Codex plugin marketplace** (awebai/codex-plugins) installs
  `packages/codex-plugin` from aweb by git subdirectory, so that path is
  published. The Claude marketplace (awebai/claude-plugins) installs from
  npm, so the Claude packages have no path pin.
- **The OATS workspace binding** uses aweb's `knowledge/` as the OKF base root
  and needs `oats-membership.yaml` at the aweb root.
- **Published READMEs and the awid.ai pages** link
  `github.com/awebai/aweb/tree/main/<path>`. READMEs already published to npm
  keep the old link permanently.
- **In-flight work about to depend on the path.** A planned gate step that
  builds `spec/trust-model` and an open PR rewriting it both decided when that
  move could land.

That list is point-in-time. The lesson is the check, not the list.

# How to apply

- Before you move or delete a path, search each known outside consumer for it,
  read-only: publication pins, sibling-path builds, plugin marketplace specs
  (`gh api repos/<owner>/<repo>/contents/...`), the OATS workspace binding,
  and published links.
- Ask the owner of any in-flight work on that path. Their schedule can set the
  order of the move.
- Say in the plan which outside pins move with the path, or why the path
  stays.
- Following [OSS and Cloud are separate teams](/aweb-expert/decisions/oss-and-cloud-are-separate-teams.md),
  give the hosted consumers' specifics to the coordinator, not to an aweb plan
  or doc.

This extends
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md),
which covers consumers inside the repository, to consumers it cannot reveal.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-root-tidy, 2026-11-27;
notes/moving-an-aweb-path-check-outside-consumers.md. The root inventory was
taken at aweb 271b2bd44a. The OSS coordinator approved the plan that took
these pins into account, and the OATS integration coordinator reported the
pending `spec/trust-model` gate step and rewrite PR. Both are
source-reported.
