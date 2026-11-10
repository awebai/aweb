---
type: Decision
title: The unchanged-version check compares installed wheels
description: A package whose candidate version is already released is refused if its built wheel's installed files or dependency metadata differ from the wheel built from that release's tag in the same gate image; docs-only drift passes with the exclusion logged. Decided and shown on focused controls, not yet landed.
tags: [decision, release, gates, packaging, python]
timestamp: 2026-11-10
---

Lead ruling of 2026-11-10 on task aweb-acww.6 (which fixes aweb-acwq), part of
gating the exact release bytes.

**Status:** decided; shown on focused controls, not yet landed in the gate.

# Decision

For each package whose candidate version already exists as a release, build
the candidate's wheel and the wheel of that release's tag in the same gate
image, and compare:

- the installed file set and each file's bytes;
- `Requires-Dist`, `Requires-Python`, entry points and extras.

The README, the long description, sdist-only files, `RECORD` and timestamps
are excluded, and every exclusion is named in the gate log. Any other
difference refuses the candidate; the remedy is a version bump.

# Why

- The failure guarded against was about installed code. In rc2 the server
  imported awid code that the released version at its declared floor lacked,
  and the gate missed it because it tested editable sources.
- Building the tag's wheel in the same image keeps the gate hermetic, with no
  network input. It relies on reproducible builds; awid-service 0.5.36 built
  from its tag matched the published wheel byte for byte.

# Rejected

- **Diffing the source tree against the tag:** it refuses docs-only changes,
  and forcing version bumps for docs revives version-bump and rebase churn.
- **Fetching the released wheel from PyPI:** not hermetic; the network becomes
  a gate input.
- **An exception list of paths:** it drifts, while wheel content is exact
  without one.

# Evidence

Focused controls: rc2 refused, rc3 passed, a README-only change passed with
the exclusion logged, and a one-line code change refused. The first real catch
was aweb-naapp 0.5.1 on main, whose installed `aweb_naapp/asset_responses.py`
differed from the release; it was latent because no published consumer
imported it, and it was bumped to 0.5.2.

This applies [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
to release versions: a version number is evidence only for the bytes released
under it.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-10; notes/unchanged-version-check-compares-installed-wheels.md (tasks
aweb-acww.6, aweb-acwq). The controls are focused runs reported by the source.
