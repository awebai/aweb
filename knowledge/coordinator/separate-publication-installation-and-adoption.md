---
type: Lesson
title: Separate publication, installation and live adoption
description: A successful publisher is not proof that every platform can install the artifact or that a running consumer uses it.
timestamp: 2026-10-01
---

Record source identity, tag identity, publisher outcome, registry bytes,
installation and observed running version separately. Multi-package npm
publication can finish before a platform package becomes visible. Keep that
platform pending until its exact metadata and tarball are retrievable; verify
integrity and the embedded version/source rather than republishing on a transient
404. A GitHub artifact can support an isolated test without proving npm readiness.

A newly public CLI does not update another repository's pinned test image or an
already running daemon. Read the exact consumer candidate's pin and any supported
source override. For services, distinguish published package/image from the
intended and observed live version, and hand immutable provenance to the
responsible operator. A failed upgrade must name the version still serving.

Documentation copies have provenance too: matching raw and rendered bytes may
still leave an outdated manifest digest or source pin. Prefer direct live/source
evidence over a stale checkout or search cache. A ready health endpoint also does
not prove every startup consistency check passed; compare enforcement behavior
and deployment history before attributing an existing alert to a new release.
These distinctions were observed across September 2026 release handoffs.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `npm-platform-publication-propagation.md`, `awid-release-and-deployment-receipts.md`, `cloud-gate-cli-pin-and-published-source.md`, `cloud-docs-copy-requires-provenance-update.md`, `site-publication-check-current-source.md`, `production-readiness-and-consistency-alerts.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
