---
type: Lesson
title: "No caller in aweb" does not make a packaged server or awid name unused
description: The hosted product's backend tests import aweb server internals, so a name with no aweb product caller can still be released consumer surface; before deleting a name from the aweb server package or awid, search the consumer repositories read-only at a recorded commit, and when they use it, keep it and move only aweb's own tests onto the live function.
tags: [lesson, removal, consumers, compatibility, testing]
timestamp: 2026-11-27
---

# The discovery

A test-honesty sweep classified `has_exact_active_identity_contact` as a
test-only compatibility wrapper, because nothing in aweb's product code calls
it. A read-only search of the hosted product's checkout found its backend
tests importing it. Deleting the wrapper would have broken another team's
suite at their next aweb dependency bump, in no aweb gate.

The aweb server package and awid are installed and imported by the hosted
product, tests included, so a name that looks internal to aweb's server can
still be consumer surface.

# How to apply

- Before deleting a name from the aweb server package or awid, search the
  consumer repositories that are available locally, read-only and without
  fetching, and record the commit you searched.
- If any consumer uses the name, keep it. Move aweb's own tests onto the live
  function (here `identity_contact_match`) and leave enough coverage of the
  kept name.
- Following [OSS and Cloud are separate teams](/aweb-expert/decisions/oss-and-cloud-are-separate-teams.md),
  do not cite the private repository's paths in OSS commits; "Cloud's tests
  import it" is enough.

The same day, protocol coordination ruled (D4) that released AWID Python and
Go exports stay until a release and consumer review (source-reported). "Test
only in this repository" is not a removal criterion for published surface.

This extends
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
to Python package names used from outside the repository, and sharpens the
"confirm nothing calls it" step of
[tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md).

# Limits

One consumer repository was checked, at one head.

Evidence: OKF proposal from aweb-expert/aweb-expert-contracts, 2026-11-27; notes/test-only-in-aweb-is-not-unused.md. Task aweb-adzj.1 (E8.1 H1, row P10).
