---
type: Lesson
title: A timed-out go test run hides the tests it never ran
description: When a package run passes Go's default 10-minute go test timeout it ends with "panic: test timed out after 10m0s" and the tests after that point never run, yet a tally of --- FAIL lines still reads as "only the known failures"; run long packages such as cli/go ./cmd/aw with an explicit -timeout and check for "test timed out" before claiming everything else passed.
tags: [lesson, testing, go, cli, timeouts, verification]
timestamp: 2026-11-13
---

On 2026-11-13 two full runs of `go test ./cmd/aw` in `cli/go` ended in
`panic: test timed out after 10m0s`. Each time, counting the `--- FAIL` lines
showed only the failures already known, so the run looked complete. It was
not: Go's default `-timeout` is 10 minutes per package binary, the panic ends
the binary, and every test after that point never ran. "Every other test
passes" was reported twice from such runs, once to a security reviewer, and had
to be corrected.

The run was slow for an environmental reason: 27 real-AWID tests each spent
about 15 s failing. A rerun with `-timeout 45m` finished in 670 s with only the
real-AWID failures. Once those were fixed the whole `cmd/aw` package passed in
about 5.5 minutes, so the trap returns whenever a package nears 10 minutes.

# How to apply

- Run long packages, `./cmd/aw` among them, with an explicit `-timeout` well
  above their expected time.
- Before claiming that the remaining tests passed, search the output for
  `test timed out`. A package that timed out has an unknown result for every
  test it did not reach.

# Real fix

The repository's broad Go test targets carry an explicit timeout
(`-timeout 20m` in the root `Makefile`), but the `cli/go/Makefile` `test`
target runs `go test ./...` with Go's default. Giving that target an explicit
timeout would remove the trap for anyone using it; ad hoc package runs still
need the check above.

The lesson is about Go's default timeout and this repository's long `cmd/aw`
package; it claims nothing about other packages.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/go-test-timeout-masks-unrun-tests.md. Verified by the harvester on 2026-11-19: the root `Makefile` passes `-timeout 20m` and `cli/go/Makefile` `test` passes none.
