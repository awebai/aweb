---
type: Lesson
title: GHCR packages from a public repository are public
description: A GHCR package first pushed by a public repository's workflow is linked to that repository and made public, the REST API cannot change package visibility and deleting a package needs delete:packages, so a "private dry run" from a public repository is impossible; plan for public content.
tags: [lesson, ghcr, github, release, images, publication]
timestamp: 2026-11-25
---

A throwaway image meant to stay private came out public. On 2026-11-25 a
release dry run in the apps repository (public, `awebai/naapp`) pushed
`ghcr.io/awebai/naapp-dryrun/logs` with the workflow's `GITHUB_TOKEN` (run
45562375967). GHCR linked the new package to the repository and gave it the
repository's visibility; an anonymous readback matched the receipt digest.

- There is no REST endpoint to change a package's visibility; only the web UI
  can.
- Deleting a package needs the `delete:packages` scope, which a default `gh`
  token lacks.

# How to apply

- Treat anything a public repository's workflow pushes to GHCR as published.
  A dry run from a public repository must contain only publishable content,
  or run from a private repository.
- Do not promise "keep it private" for an image from automation in a public
  repository.
- For real releases this is the wanted behaviour: servers and gate journeys
  pull the images anonymously.
- The apps publisher treats a `workflow_dispatch` run as a recovery, which
  publishes the immutable version without moving `latest`. A first
  publication made by dispatch therefore gets no `latest`; plan the first
  real publication accordingly.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-25;
notes/ghcr-packages-inherit-public-repo-visibility.md. GitHub behaviour as of
2026-11.
