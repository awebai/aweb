---
type: Lesson
title: A tag run executes the tag's own publisher
description: A tag-push publication workflow checks out and runs the tagged commit, publisher script included, so re-running it after a publisher fix repeats the same failure; the fix reaches an already-pushed tag only through a run of the fixed publisher against the tagged source.
tags: [lesson, release, ci, publication]
timestamp: 2026-11-14
---

The service image workflow (`.github/workflows/service-image-release.yml`)
triggers on tag pushes, checks out the tagged commit and runs
`scripts/publish_release.py` from that checkout. The publisher that runs is
therefore the one in the tag's tree, not the one on main. When a tag's
publication fails because of a bug in the publisher itself, landing the fix on
main and re-running the failed job runs the old publisher again and fails the
same way.

# How to apply

- When a tag publication fails, first decide whether the fault is in the tagged
  source or in the publisher. Only a source fault calls for a new tag.
- For a publisher fault, the fix reaches the existing tag only through a run
  that executes the fixed publisher against the tagged source. On main
  (2026-11-14) the image workflow has a tag-push trigger only, so that run needs
  a dispatch path or the runnerless publication described in `docs/release.md`;
  arrange it with the release coordinator rather than re-running the job.
- Do not count a re-run of the failed job as testing the fix.

# Origin

Observed 2026-11-14: the first `server-v` tag after exact dual-platform server
images refused in its publisher on the tag-listing step (run 43622390148). The
publisher fix for that listing case was still under review when this was
proposed and is not described here; the release rules for first publication
live in `docs/release.md`.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-14;
notes/first-image-publication-has-no-repository.md. Checked against aweb main
cba8754f2: the workflow's trigger, checkout and publisher invocation.
