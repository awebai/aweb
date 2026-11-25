---
type: Lesson
title: An image no CI job starts is untested, even when e2e is green
description: An app's release image that no CI job builds and starts was first started in production, because naapp's e2e stacks for Folio and Library ran the apps from the checkout; the test is a CI job that builds the image as the release does, starts it with minimal configuration and checks /live with the build commit, and it counts only once a planted broken image has turned it red.
tags: [lesson, ci, release, docker, testing, naapps]
timestamp: 2026-11-25
---

A green end-to-end suite proves the code in the checkout, not the image the
release ships. In naapp the Folio and Library e2e stacks ran the apps from the
checkout, so nothing ever started their service images before production. The
gap showed when Folio began reading its package metadata at import: nothing
proved the image contained that metadata, so an import-time failure could only
have been found after a deploy. Reproducing the image's install steps by hand
gave quick confidence; it was not proof.

# How to apply

- For every app image, ask which CI job starts it. If the answer is "the e2e
  suite", check that the suite really builds the image; a stack that runs the
  app from the checkout does not count.
- The check builds the image exactly as the release does: the same Dockerfile
  and the same build context. naapp's release builds with the repository root
  as context, so the check must too, or files the release excludes or includes
  differ.
- Start the image with the smallest configuration it accepts and require its
  liveness endpoint to answer with the app's id and the commit just built. The
  commit check proves the probe reached this image and not a stale container.
- Prove the job before trusting it: plant an image that lacks the project and
  require the job to fail with the import error, then revert
  ([a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md)).

At naapp main 1740e25 (2026-11-25) the Folio and Library images have this job.
The Secrets owner-acts journey builds the Secrets image in its e2e compose, and
can build Logs under a profile, so those images are started in CI by that
journey rather than by a dedicated check. Whoever adds an app, or changes how
an app's e2e starts it, keeps this true.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/2026-11-25-ci-never-started-the-release-image.md. Checked at
harvest: naapp PRs #34 (Folio) and #39 (Library) merged the image jobs and
`scripts/image-smoke.sh`; in planted run 45531354946 the Folio image job
failed with `ModuleNotFoundError: No module named 'folio'` (the run's other
failure, a Secrets journey assertion, is unrelated), and in planted run
45539437869 only the Library image job failed.
