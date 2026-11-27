---
type: Decision
title: Release wheels are install-checked by path, and a PyPI lane refuses until PyPI alone can install them
description: Each built release wheel is installed by path into an isolated environment and imported, which catches undeclared dependencies that source-tree suites cannot see; at publish time the same check takes every other dependency from PyPI only, so a lane that needs a sibling's unreleased version refuses before any upload.
tags: [decision, release, pypi, packaging, ci]
timestamp: 2026-11-26
---

Decided on 2026-11-26 while naapp's release-files CI job and PyPI publisher
were built (naapp PRs #57 and #58, both merged 2026-11-27). It applies to any
repository that releases several dependent PyPI packages from one commit.

# Discovery

Test suites that run against a source tree cannot see a package that imports
something it never declared, because the source tree installs every sibling
package. naapp's `aweb-naapp-journey-support` imported
`aweb_naapp_testing.compose_lane` without declaring `aweb-naapp-testing`, and
the version on PyPI (0.5.2) had no `compose_lane`. Every suite was green.
naapp PR #57 fixed it by declaring `aweb-naapp-testing>=0.6.0`.

# Decision

- **In CI, install-check each built wheel by path.** Install the wheels into an
  isolated environment (`uv run --isolated --no-project --no-config` with a
  pinned Python, and `python -I`) and import each top-level module. Assert that
  each distribution's `direct_url.json` is the wheel's own file, so a copy from
  an index at the same version cannot stand in for it. Here `--find-links` to
  the build directory is allowed, so one lane can depend on another lane's
  build from the same commit.
- **At publish time, PyPI alone.** After the asset and token checks and before
  any upload, install the lane's locked wheels together, by path, with every
  other dependency from PyPI only (no `--find-links`), and import them. On
  failure the lane refuses with nothing uploaded. The release workflow can be
  rerun once the lane it depends on is published.

PyPI files are immutable, so publishing a package whose dependencies PyPI
cannot serve leaves an uninstallable version there for good. The publish check
also turns the lane order into a rule that is enforced: naapp's `secrets-v`
(journey-support) refuses until `aweb-naapp-v` has put `aweb-naapp-testing`
0.6.0 on PyPI.

The mechanism is documented in naapp's `docs/release.md` and implemented in
`scripts/release_files.py` (`check_installs`) and `scripts/publish_release.py`
(`installable_from_pypi`). This concept holds the rule and what was rejected.

# Rejected

- **Source-tree suites as the only install evidence.** They passed while the
  package could not be installed.
- **`--find-links` at publish time.** The first version of the check ran with
  the same-commit build directory. aweb-expert-oss-publish's blocking review of
  #58 found that this passes `secrets-v` against an unreleased 0.6.0. Fix
  e9d56ab29 installs from PyPI only at publish time. Both reviewers confirmed
  it live: `secrets-v` refused, while `aweb-naapp-v` and the runner lane
  installed.
- **Lane order kept only in documentation.**

# Limits

- The check does not catch an understated dependency floor: a floor lower than
  the code needs still resolves to a newer version on PyPI. A lowest-direct
  check is open as task aweb-adzg.
- Evidence is from one repository on one day.
- This is an agreement between agent reviewers. No human acceptance is
  recorded.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-repo, 2026-11-26;
notes/release-install-check-catches-undeclared-deps.md and
notes/pypi-lane-refuses-until-pypi-can-install-it.md. The harvester checked
that naapp PRs #57 and #58 are merged, and that commit e9d56ab29 ("Refuse a
PyPI lane whose wheels PyPI cannot install yet") and the functions and
`docs/release.md` text named above are on naapp main.
