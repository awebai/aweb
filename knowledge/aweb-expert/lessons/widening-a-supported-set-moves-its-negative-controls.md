---
type: Lesson
title: Widening a supported set moves its negative controls
description: When a change widens a supported set (protocol or manifest versions, modes, error codes), every negative control that pins the old boundary as refused is an existing consumer; before review, search the whole repository for the old boundary's refusal text and fixture names, across shared vectors, server tests and Go-only conformance vectors.
tags: [lesson, review, testing, contracts, vectors]
timestamp: 2026-11-09
---

A Go change raised the supported app manifest version from 2 to 3. Three
controls used version 3 as their "unsupported" case: the shared v2 vector, a
server registration test, and a Go-only conformance vector
(`cli/go/internal/conformance/vectors/app-manifest-interpretation-v1.json`).
The author moved only the first. The focused runs passed, and the train's full
gate failed in the Go conformance package, because the widened set now
interpreted the case the vector expected to be refused. The fix moved that
case to version 4; it was shown red, then green, and landed.

A passing focused suite does not show that a control elsewhere still pins the
old edge. Widening a set turns every "N is unsupported" case into a test that
expects the wrong answer, wherever it lives.

# How to apply

- Before review, `git grep` the whole repository for the old boundary: its
  refusal text, its error code and the fixture or case names that carry it.
  Cover shared vectors, server tests and Go-only conformance vectors, not only
  the package the change touches.
- Move each control to a value outside the new set, and show it red against
  the widened code before calling it moved.
- A reviewer asks for that search, not only for the moved control the author
  names.

A control that derived its unsupported value from the supported set, rather
than a literal, would not need moving; until controls are written that way,
this is a search habit. The full Go suite that caught this is not in the
candidate checks stage (see
[focused proof includes the contract guards](/aweb-expert/lessons/focused-proof-includes-the-contract-guards.md)).
This refines
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md):
negative controls are consumers too.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-09;
notes/checks-stage-does-not-run-go-tests.md (aweb-acgh.16.40 at aa2704d96,
train 33 gate; fixed in d3e8af4e3, landed with main 0b67bf256). The fix commit
and the vector file were confirmed on main at 0b67bf256. Observed in one train
on one repository.
