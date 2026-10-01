---
type: Lesson
title: Preserve acceptance artifact provenance
description: Keep the tested executable, source, build context and harness together so a source claim can be traced to the accepted bytes.
timestamp: 2026-10-01
---

A source SHA alone does not identify an executable. Archive builds can omit
VCS metadata, and build paths or context can change the output. Preserve the
source archive or tree digest, exact build command and context, tested binary
hash, harness and run log. Do not overwrite another owner's named test artifact
without recording what replaced it.

During paired acceptance on September 25, 2026, the test owner rebuilt the
reviewed client from an archive into a path previously holding a worktree build.
The resulting hashes differed. The reviewer verified the preserved archive and
harness, then reproduced the binary from the original build context into a
separate output path. That resolved provenance without repeating the successful
endpoint test. The exact paired ACK is preserved in the archived session.

Investigate a mismatch before inferring a code change or demanding a broad
retest. Conversely, do not waive an unexplained mismatch because the source label
matches. Exclude checksum manifests from their own checksum input.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `paired-acceptance-binary-provenance.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
