---
type: Lesson
title: A number carried as a string in a hashed identity needs one spelling
description: Canonical JSON fixes key order and string escaping but not how a number carried as a string is spelled, so a hashed identity with such a field must fix one spelling (for an installation generation, ASCII [1-9][0-9]*) and publish refused neighbours such as "0", "03" and "+3" as negative vectors; otherwise two implementations hash the same value differently.
tags: [lesson, canonical-json, hashing, vectors, human-role-holders]
timestamp: 2026-11-10
---

Canonical JSON makes the encoding of a given JSON value unique. It cannot
decide which string a producer writes for a number. If a hashed or signed
identity carries an integer as a string, "3", "03" and "+3" are three
different values with three different hashes, and nothing in the encoding
says which is the integer 3.

In the human-role holding identity, `generation` is the installation's
integer generation rendered as ASCII `[1-9][0-9]*`, with no sign and no
leading zero. A string generation with no fixed spelling was proposed first
and refused in review.

# How to apply

- Whenever an identity, receipt or delivery body carries a number as a
  string, name its exact spelling as a grammar.
- Publish the refused neighbours as negative vectors: zero or another value
  outside the range, a leading zero, a sign. The holding vectors
  (`docs/vectors/human-role-holding-v1.json` at de9434ce1) include
  `generation_zero`, `generation_leading_zero` and `generation_signed`.
- Each consumer then refuses, rather than normalizes, a non-canonical
  spelling. Normalizing would let two parties sign different bytes for what
  they treat as the same identity. See
  [shared vectors prove only what they pin](/aweb-protocol-expert/lessons/shared-vectors-prove-only-what-they-pin.md).

**Status (verified 2026-11-10):** the grammar and the negative vectors are at
de9434ce1 on a review branch, not on aweb main.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-10; notes/human-role-audit-identifiers.md.
