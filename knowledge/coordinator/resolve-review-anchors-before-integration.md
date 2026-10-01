---
type: Lesson
title: Resolve full review anchors before integration
description: Resolve the complete commit object and compare the reviewed diff and ancestry; a matching short prefix is insufficient.
timestamp: 2026-10-01
---

Treat a supplied full SHA as an object to resolve, not text whose first few
characters look familiar. Compare the remote ref, local object, parent set and
review receipt before integrating. Ask the reviewer to correct an invalid anchor;
do not silently substitute the object that a short prefix happens to resolve.

A September 28, 2026 handoff quoted a nonexistent full SHA beginning with the
same eight characters as the real commit. The reviewer had read the real object
through that prefix and explicitly corrected the anchor. The archived verdict
remained changes-required; this was not a demonstrated hash collision.

A correct SHA does not replace accounting for every incoming commit, comparing
the actual three-dot diff with the reviewed change, and checking that main has
no commits absent from the candidate. Resolve multi-ref fetch results explicitly:
FETCH_HEAD can name the first fetched ref. Use a literal or correctly braced push
refspec rather than allowing shell interpretation to alter it. Verify the remote
result after pushing.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `full-sha-review-anchor.md`, `integration-clone-gotchas.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
