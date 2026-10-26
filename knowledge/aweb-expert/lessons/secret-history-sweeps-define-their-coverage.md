---
type: Lesson
title: Secret history sweeps define their coverage
description: A history sweep covers only the refs it enumerates, a detector is evidence only on the credential forms it was shown to catch, and an "in-memory" scan can still spill to disk; name the ref universe, validate detectors on the actual forms, and check every persistence boundary.
tags: [lesson, security, secrets, git, scanning]
timestamp: 2026-10-24
---

Learned during a read-only credential sweep of repository history.

- **Ref universe.** A branch-and-tag traversal missed advertised pull-request
  refs, which added 1,960 reachable commits and 3,653 blobs across sixteen
  repositories. Fetching the objects did not mean the traversal had selected
  them.
- **Detector forms.** Default generic-key rules produced about two thousand
  matches and still did not flag credential-bearing database and cache URLs
  used as positive controls. A large match count is not breadth.
- **Persistence.** A library's in-memory repository ingested packs through a
  spooled temporary file, so large packs could reach disk in a scan whose
  constraint was never to persist values.

# How to apply

- State which refs a "full history" claim covers before calling it complete. Run
  a differential pass over refs beyond branches and tags, visit commit trees so
  merge content is included, and name what remains uncovered: deleted or
  unadvertised refs, forks, external submodules, LFS objects.
- Show each detector positive on the actual credential form before trusting a
  negative; add checks for URL userinfo and sensitive environment assignments,
  including low-entropy local defaults that entropy rules miss.
- Triage the actual match, not a nearby word or a file name. A test path or an
  example filename is context, not proof a value is inert; leave validity
  untested unless an authorised operator checks it.
- Treat temporary files, decoder buffers, scanner output and exception paths as
  separate persistence boundaries, and recheck library behaviour when versions
  change.

The detector rule is a case of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-audit` (notes
`history-scans-need-an-explicit-ref-universe.md`,
`secret-scan-controls-must-cover-the-actual-credential-form.md`,
`in-memory-repository-objects-can-still-spill-to-disk.md`). No credential
values, repositories or incident details are recorded here.
