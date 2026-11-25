---
type: Lesson
title: Pre-check an image source change by what runs, not by what the lock lists
description: Before deploying an app from a new repository (or any image change), diff the runtime dependency set rather than the lock, compute the served manifest bytes from each tree with that tree's own dependencies, read new settings upper bounds that refuse startup, and expect an old live build to turn the switch into a feature deploy.
tags: [lesson, naapp, deploy, dependencies, uv, verification]
timestamp: 2026-11-25
---

Learned while preparing Folio and Library to deploy from the naapp repository
instead of aweb (naapp PR #48, merge 5f5a7196). Both handoffs were confirmed
by read-only checks, and both apps' manifest digests matched production.

# How to apply

- **Diff the runtime set, not the lock.** A raw `uv.lock` diff overstates the
  change: a lock lists test-only packages that never enter the image. The
  image installs `uv sync --frozen --no-dev`, so export that set from both
  trees (`uv export --frozen --no-dev`) and diff the exports.
- **Prove manifest identity before deploying.** Run the app's own manifest
  builder from each tree, with identical inputs, and compare the bytes. Where
  the origin serves a committed manifest file verbatim, hashing that file is
  enough to match production's digest.
- **Give each tree its own dependencies.** Running both trees in one virtual
  environment hides any change in a shared dependency (here, awid). A
  comparison that shares an environment proves nothing about that dependency.
- **Read new settings upper bounds.** A field bound such as `le=` refuses
  startup when the running service sets a larger value. One such bound
  (a timestamp-skew limit) was missed by the source and found by a second
  reviewer.
- **Check how old the live build is.** If live is weeks behind, the switch
  carries feature changes too. List them and let the lane decide; it is a
  feature deploy, not a pure source switch.

# Elimination route

The first three checks are mechanical and could be a pre-deploy command in
the naapp deploy tool (runtime export diff, manifest digest per tree in its
own environment, settings bounds against the service's values). Until such a
command exists, they are this lesson.

See also [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
for the same principle applied to test runs, and
[naapp deploys move forward only](/aweb-expert/decisions/naapp-deploys-move-forward-only.md)
for the repository-move path such a switch takes.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/source-switch-precheck-method.md. The harvester read naapp
PR #48 (merged at 5f5a7196). The digest matches and the reviewers' findings
are source-reported. No deploy from the naapp repository had run when this
was recorded.
