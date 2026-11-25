---
type: Decision
title: PyPI uploads the gated files the release tag locks
description: aweb publishes to PyPI only the wheel and sdist that passed the release gate, locked by sha256 lines in the annotated tag's message and uploaded from a published GitHub release with the PYPI_TOKEN repository secret; a tag-push trigger, trusted publishing and app lanes in aweb were each rejected.
tags: [decision, release, pypi, publication]
timestamp: 2026-11-24
---

Decided on 2026-11-24 while the PyPI lane was reworked for the release
tool. The bytes the gate tested are the bytes PyPI serves.

# Decision

- aweb publishes to PyPI only from `server-v` tags (package `aweb`) and
  `awid-service-v` tags (package `awid-service`). It uploads only the wheel and
  sdist that passed the release gate. Nothing is rebuilt at publish time,
  because a rebuild from the same tree can produce different bytes.
- The annotated release tag's message locks the files as `sha256sum` lines
  (`<sha256>  <basename>`). The files are attached to a GitHub release.
- `.github/workflows/pypi-release.yml` runs on `release: published`. It
  downloads the release assets and refuses unless they are exactly the locked
  set, by name and by digest. Only then does it upload, with the `PYPI_TOKEN`
  GitHub repository secret.

How the lane works is documented in `docs/release.md` ("PyPI publication").
That document is canonical for the mechanism. This concept holds the rule and
the alternatives that were rejected.

# Rejected

- **A tag-push trigger.** The release tool pushes the tag before it creates the
  release, so a lane triggered by the tag push would race the release event.
  A bare tag push publishes nothing to PyPI.
- **PyPI trusted publishing.** The operator's requirement is only that no PyPI
  token lives on the operator's machine. The existing repository secret meets
  that, so no PyPI publisher configuration is needed. Trusted publishing was
  briefly implemented and then reverted on the operator's correction. Do not
  reintroduce it as "best practice" without the operator.
- **Publishing the naapp apps from aweb.** The apps (`aweb-naapp`, Secrets,
  Logs and the Secrets runner) release from their own repository,
  github.com/awebai/naapp. aweb's tag spelling refuses their tags before any
  gate runs, so two repositories never publish the same packages or images.

# Acceptance

- The secret instead of trusted publishing is the operator's decision, relayed
  by the OSS coordinator by mail on 2026-11-24. **Source-reported**: the
  harvester could not read the mail.
- That the apps release from awebai/naapp is the operator's decision, cited by
  the OSS coordinator in task aweb-advk on 2026-11-24. **Source-reported.**
- The tag-message contract (sha256sum lines, the release published directly)
  was agreed with the release-tool seat in task aweb-advq. That seat pointed out
  the tag-push race. It is an agent agreement, not human acceptance.

# Limits

As of 2026-11-24 the lane is not on aweb main. It is on the reviewed release
train branch (commits 78a10a95b and f23167138 for the PyPI lane, fdcfb1a2e5
for removing the app lanes), and the workflow has not yet run on a real GitHub
release. If the lane does not land in this shape, this decision is superseded.

Related: [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
states the same principle for test evidence.

Evidence: OKF proposal from aweb-expert/aweb-expert-oss-publish, 2026-11-24;
notes/pypi-publishes-locked-release-assets.md. The harvester checked the
workflow trigger, the asset check and the secret, the `docs/release.md`
section, and the refusal of app tags on the train branch at 3405279a1.
