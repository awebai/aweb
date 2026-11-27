---
type: Lesson
title: Go's test cache ignores repository files outside the module
description: go test rechecks the files a test opened only inside the module root, so a cli/go test that reads ../../docs or test-vectors reports a stale cached pass after those files change; evidence runs use -count=1.
tags: [lesson, testing, go, cache, verification]
timestamp: 2026-11-27
---

Go keys a cached test result on the files the test opened, but it rechecks
only files inside the module root and GOROOT. Tests in `cli/go` that read
repository files above the module (`../../docs`, `test-vectors`) can report
`(cached)`, a pass for the old contents, after those files change. During the
E1 (b) removal, `go test ./internal/identityinventory` reported cached after
`docs/identity-tree-coverage.json` was edited.

# How to apply

- Run `go test -count=1` for any evidence run of a change that touches docs,
  vectors or other files outside `cli/go` that Go tests read. The repository's
  full Makefile runs already pass `-count=1`; a hand-run focused test does
  not unless you add it.
- Treat `(cached)` in a quoted result as evidence for the cached inputs, not
  for the tree.

This is another case of
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-e1-removals, 2026-11-27;
notes/go-test-cache-ignores-files-outside-module.md. The observed cached run
is source-reported. The harvester checked that the Makefile's whole-module
runs use `-count=1` at aweb main 90519b0d2.
