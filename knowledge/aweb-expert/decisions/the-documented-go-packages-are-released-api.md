---
type: Decision
title: The documented Go packages are released API
description: cli/go is a documented Go library, so the exported API of its documented packages (aw, awid, awconfig, chat, run) is a permanent constraint; a dead-code tool's "unused" for those packages means unused inside our repositories, never dead, and removing one needs a deprecation path or a major version and a decision.
tags: [decision, compatibility, go, cleanup, release]
timestamp: 2026-11-26
---

# Decision

- `cli/go` is a Go library as well as the `aw` binary. Its README section "Go
  Library" names the public packages: `aw` (the module root), `awid`,
  `awconfig`, `chat` and `run`.
- Released exported API in those packages is a permanent constraint. Removing
  or changing an exported symbol needs a deprecation path or a major version,
  and an explicit decision.
- A dead-code tool's report for those packages means "unused inside the
  repositories we can search", never "dead". Outside Go importers cannot be
  searched.
- Undocumented packages belong under `cli/go/internal/`, where Go itself
  enforces the boundary. On 2026-11-26 the eight undocumented packages (`wake`
  with `wake/session`, `hookevent`, `a2a`, `a2agw`, `strictjson`,
  `canonicaljson`, `logschain`, `signaturewire`) moved there (cbac81752c, with
  a CHANGELOG entry), without changing the documented packages' exported API.

# Why

During the 2026-11-24 dead-code removal, a candidate report said the `cli/go`
README documented only `go install`. That was wrong, and an earlier team
decision that "the Go module is not a library" was taken on that report. The
decision was withdrawn once the README section was found (source-reported).
Before then a head had already removed released entry points: f03d894f77
restored the released `chat` and `awid` entry points, and
`cli/go/chat/released_api_test.go` pins them.

An inventory of the organisation's `go.mod` files on 2026-11-26 found that the
Go importers outside aweb (approval-service, bdh and claw) import only the
documented five (source-reported). That is why moving the undocumented
packages under `internal/` was safe, and why the documented five cannot be
treated the same way.

# How to apply

- Before calling an exported symbol dead, read the package's documented
  status (README sections, CHANGELOG retention notes) and look for released-API
  pins such as `released_api_test.go`.
- Report "unused internally" and "dead" as separate findings for public
  packages, as for configuration in
  [verify business facts; consolidate before cutting](/aweb-expert/lessons/verify-business-facts-and-consolidate-before-cutting.md).
- A package outside `internal/` is not thereby documented: at main 5c2ee7bad,
  `cli/go/approval` is outside `internal/` and is not in the README table.
  Read the README rather than inferring the public surface from the tree.

This is the Go-library counterpart of the wire-level rule in
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-cleanup-oss, 2026-11-26;
notes/go-module-is-a-documented-library.md. Checked by the harvester on aweb
main 5c2ee7bad: the README "Go Library" table, `chat/released_api_test.go`,
f03d894f77 and cbac81752c on main, and the CHANGELOG entry. The withdrawn
decision and the `go.mod` inventory are source-reported.
