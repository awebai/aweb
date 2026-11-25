---
type: Lesson
title: Playwright fetches the base commit on pull-request runs
description: Playwright's test runner collects git metadata by default in CI and, on a GitHub pull_request run whose checkout lacks the PR base commit, runs a git fetch to get it; a test egress guard denies that fetch and fails a green suite, so every Playwright config that runs behind the guard sets captureGitInfo off.
tags: [lesson, ci, playwright, test-egress, naapp]
timestamp: 2026-11-24
---

In naapp CI the page renderer's `npm test` passed all its Node and Playwright
tests, and the step still failed: the test egress guard reported a
`CONNECT github.com:443` from git, started under Playwright's node process.
Playwright's git-info plugin does this. When `GITHUB_ACTIONS` is set and the
event is a pull request, it checks whether the PR base commit is in the
checkout and, if not, fetches it from origin. A shallow CI checkout never has
that commit.

# How to apply

- Set `captureGitInfo: { commit: false, diff: false }` in every Playwright
  config that runs behind the egress guard, when the config is written, not
  after the first red. With it, the tests run no git command at all. naapp's
  page renderer config does this (582f8d21, landed with PR #5).
- A local run does not show the fetch, because it happens only under the CI
  pull-request environment. To reproduce, set `GITHUB_ACTIONS` and point
  `GITHUB_EVENT_PATH` at a pull_request event payload, then run with
  `GIT_TRACE=1` to see the git commands.
- Read a guard denial whose client is git under a test runner as the runner's
  own metadata collection before suspecting the code under test.

The durable fix would be a check that every Playwright config behind the guard
disables git capture. No such check exists, so this lesson covers new configs
until one does.

The proposal also said the guard cannot attribute or deny connections on
macOS. naapp's `scripts/test-egress/native.py` on main contradicts that: it
denies by proxy and falls back to `lsof` and `ps` to attribute the connection
when `/proc` is absent. That claim was not kept.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-24; notes/2026-11-25-playwright-git-capture-egress.md. naapp PR #5,
pull_request runs 45502679386 and 45506485403.
