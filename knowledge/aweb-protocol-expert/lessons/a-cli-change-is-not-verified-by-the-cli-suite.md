---
type: Lesson
title: A CLI change is not verified by the CLI suite
description: Server tests drive the built aw binary and pin CLI exit codes and messages, and some released CLI contracts are pinned only there, so a cmd/aw change is handed back only after the server tests for that behaviour, or the full test-server, have run; a newer design sentence that meets an older pin needs a ruling.
tags: [lesson, testing, aw-cli, review, contracts]
timestamp: 2026-11-28
---

A change to `aw` reads was handed back with a green `make test-cli`. The gate's
server suite then failed five cases of
`test_a_chat_read_whose_encryption_key_cannot_load_says_so`. That test is the
only pin for a released CLI contract: reads fail when local encryption key
state exists but cannot load. `make test-cli` does not run server tests. Many
of the files under `server/tests` take `AW_TEST_CLI_BINARY` or build `aw`, and
then assert its exit codes and output.

# How to apply

- Before handing back a `cmd/aw` change, grep `server/tests` for the behaviour
  you touched (exit codes, error text, command names) and run those tests, or
  the full `make test-server`.
- When a protocol owner's design sentence conflicts with an older pinned
  behaviour, find the pin (`git log -S` on the test) and get a ruling. The
  newer sentence does not silently override released behaviour; see
  [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md).
- The elimination route is in the gate: a target that runs the server tests
  driving the built binary whenever `cmd/aw` changes. Until one exists, this
  is a handback habit.

This is the counterpart of
[identity and routing review needs the real client](/aweb-expert/lessons/identity-and-routing-review-needs-the-real-client.md),
which says a server change needs the real client.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-e2ee-rotation, 2026-11-28; notes/cli-changes-need-the-server-suite.md.
The red gate receipt for d1f7b2ce9 and the green one for b639fb191 are
source-reported. The test, the Makefile targets and the binary-driven server
tests were checked by the harvester at aweb main fbfa65f22.
