---
type: Lesson
title: Sweep every package, harness and process after a shared change
description: After a behaviour change to a shared Go package such as awid, or to what the aw binary refuses, test every package in the module and every harness and process that runs the changed code (shell e2e and its compose services, daemon containers, Python server and naapp tests, TypeScript tests) before handoff, not only what was touched; check that negative tests still fail for their own reason; and when a gate failure looks like a product gap, read the contract the change already shipped and take a contract question to its owner instead of fixing it inside the gate.
tags: [lesson, testing, handoff, awid, aw-cli, e2e, contracts]
timestamp: 2026-11-13
---

One change (registry pinning in awid, task aweb-aczi, 2026-11-13) broke
consumers four times after its touched packages were green.

- **Untouched Go packages.** `awid` and `cmd/aw` passed, but
  `cmd/aweb-a2a-gw` and `internal/conformance` also build registry resolvers
  and failed on the new refusal. Only a `go list ./...` sweep found them.
- **Harnesses outside Go.** The new refusal broke the e2e shell journeys
  (8779621fb) and, one gate later, a Python server test that spawns `aw`
  with its `AW*` environment stripped (4f2acd0e4).
- **A process, not a script.** RC2 gate #10's A2A docker e2e gave
  `AWID_REGISTRY_URL` to its `aw` containers but not to the gateway
  container the same script starts (harness fix 2dd65c797).
- **A negative test passing on the wrong refusal.**
  `TestTeamReplaceKeyReportsOldCertificateRevocationFailureState` passed on
  the pinning error instead of the server's 400 it was written for.

A further trap at gate #10: the failure looked like a product gap, and the
first instinct was to make the gateway trust its configured registry. The
contract the change had already shipped classed that as pinned, so the
"fix" would have silently widened a reviewed decision. It was dropped
unpushed, and the question went to the owner, who ruled the
[refinement](/aweb-protocol-expert/decisions/registry-trust-is-the-operators-choice.md).

# How to apply

- For a behaviour change in a package imported across commands (awid, or
  anything the `aw` binary refuses), run `go test $(go list ./...)` before
  handoff. Keep `cmd/aw` on its own long timeout (`-timeout 45m`) and grep
  the output for `test timed out`.
- List every harness that runs the binary and run each one, or record how
  it sets the variable involved: Go packages; `scripts/*.sh` and the compose
  services that run the CLI; `server/tests` using the `source_cli_binary`
  fixtures; `naapp*/tests` and their e2e compose files; channel and pi
  TypeScript tests. "Every Go package passes" says nothing about these.
- Within each script, sweep every process it starts (daemon containers
  beside the CLI containers), not just the script.
- When a change adds a refusal, check that each negative test in its reach
  still fails for its own reason, not the new one.
- When a gate failure looks like a product gap, read the contract the change
  shipped first. A contract change goes to its owner as a question, never
  inside a gate fix ([accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)).
- To find which test reaches real DNS, run `go test -v` with
  `GODEBUG=netdns=go+2`: the resolver prints a `confVal` line on first use
  and `hostLookupOrder(<host>)` before each host lookup (TXT lookups print no
  line of their own), and the `=== RUN` line above each one names the test.
  A package that prints no `confVal` did no DNS at all, TXT included.

The elimination route is CI that runs the whole module and every listed
harness on each change; until a gate does that for authors, this sweep is the
author's handoff duty. It extends
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
(old-contract tests and callers) from review to the author's handoff, and
from changed packages to every consumer.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-local-log-encryption, 2026-11-13; notes/sweep-whole-module-after-shared-library-change.md. Commits 8779621fb, 4f2acd0e4 and 2dd65c797 are source-reported.
