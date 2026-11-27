---
type: Lesson
title: One producer-written fixture for a format that crosses two tools
description: When one tool writes a record another tool reads, commit one fixture written by the producer's real code with only the machine faked, keep it equal to the producer's output with a form test that asserts exact forms, and have the consumer load that file as its stand-in; each side testing against its own idea of the other's format cost three real runs in two days.
tags: [lesson, testing, release, gate, receipts, fixtures, cross-repository]
timestamp: 2026-11-26
---

The VM gate launcher in aweb writes a release receipt that Cloud's release
command reads. Three mismatches between the two sides each surfaced only in a
real run, within two days: a digest prefix, the index digest where the member
digest was required, and a full image reference where a bare digest was
required (Cloud 0.8.87). Each side had tested against its own idea of the
other's format. Running the producer's real code in one side's tests did not
stop the other side's stand-in from drifting.

# How to apply

- Commit one fixture in the producer's repository, written by the producer's
  real code with only the machine faked.
- Add a form test in the producer that keeps the fixture equal to the
  producer's output: the same keys, and the exact form of every value
  (digests as `sha256:<hex>`, commits as 40 hex characters, fixed values as
  literals). A test that only checks that a field "contains a digest" lets a
  full reference pass where a bare digest is required.
- The consumer loads that file as its stand-in, rather than writing its own
  copy of the format. A format change on either side then fails a test, not a
  run.
- The fixture must have a real consumer, as
  [frozen vectors need a real consumer](/aweb-protocol-expert/lessons/frozen-vectors-need-a-real-consumer.md)
  requires; here it is Cloud's release test.

The elimination route is this pair of tests. aweb added the fixture and its
form test (`tests/fixtures/ac-release-receipt.json`), and Cloud 0.8.88 started
with its copy byte-identical to the launcher's.

This applies to any producer and consumer pair across repositories: receipts,
evidence records, manifests. It extends the point of
[shared vectors prove only what they pin](/aweb-protocol-expert/lessons/shared-vectors-prove-only-what-they-pin.md)
from protocol corpora to tool records.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-26;
notes/one-producer-fixture-for-cross-tool-formats.md. Cloud 0.8.87 runs
(vm-415c4884 red on index against member; then the full reference against a
bare digest, cd4c28d3). Fixed in aweb f96ea6c8fc and
2295ab8eb7 (the fixture and its form test).
