---
type: Lesson
title: A command removal keeps the Go library's API while the server routes stay
description: Removing an aw command removes only the CLI caller; the exported wrappers, types and request/response fields of the published Go module (the root package and awid) stay while the server serves the matching routes, unless a ruling approves the Go API removal, and a downstream compile through a replace directive is the check.
tags: [lesson, removal, compatibility, go, review]
timestamp: 2026-11-28
---

`cli/go` is the `aw` binary and also the published Go module
`github.com/awebai/aw`. Its root package and `awid` have callers outside our
repositories. When an aw command goes, the wrappers it called can lose their
last caller inside the repository. That makes them look like orphans of the
removal. They are not: they are library API for programs that call the same
server.

# What happened

The E1.7 roles removal (November 2026) deleted `cli/go/team_roles.go` and the
`RoleName`/`Role` fields of `PatchCurrentWorkspaceRequest` and
`PatchCurrentWorkspaceResponse` together with `aw roles`. Released
`aw-v1.36.59` exports all of them. The server's roles routes and the workspace
role fields stayed under the removal's own ruling (D5), so downstream programs
still had a working server to call and broke for no server-side reason. No
ruling had approved the Go API change. The dead-code diff gave no signal on
these symbols either way (source-reported). The reviewer found the break by
compiling an independent downstream module against the head. The API was
restored unchanged in e53fa2a4e6.

# How to apply

- In an aw surface removal, list changes to the root package (`cli/go/*.go`)
  and to `cli/go/awid` separately from `cmd/aw`, and review them as library
  API changes.
- Keep the exported types, methods and fields by default. They go only when
  a ruling removes the matching server capability or explicitly approves the
  Go API removal.
- Do not count dead-code output as evidence for these packages. For public
  packages it can only mean "unused inside the repositories we can search".
  Deleting orphans after a removal applies to unexported code and to
  packages under `internal/`.
- Prove the API is intact with a throwaway module that imports
  `github.com/awebai/aw` through a `replace` directive pointing at the head,
  calls the affected methods, sets the affected fields and compiles.

This applies the wire-level rule in
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
to a consumer that an aw removal easily misses: the published Go library. It
is also a contract guard in the sense of
[focused proof includes the contract guards](/aweb-expert/lessons/focused-proof-includes-the-contract-guards.md).

# Elimination route

`cli/go/awid` and `cli/go/chat` already carry `released_api_test.go` pins; at
main fbfa65f22 the root package has none. A root-package pin that calls each
released wrapper and sets each released field would make a removal like this
fail in our own suite. Until it exists, the downstream compile is the check.

Evidence: OKF proposal from aweb-expert/aweb-expert-e1-removals, 2026-11-27;
notes/cli-removal-keeps-the-published-go-api.md. Checked by the harvester:
`aw-v1.36.59` contains `cli/go/team_roles.go` and the `RoleName`/`Role`
fields in `cli/go/workspaces.go`; e53fa2a4e6 restores `team_roles.go` and
the field pairs and records a passing downstream compile. It is on the E1.7
roles branch and on `one-organisation`, not yet on main at fbfa65f22. The
review that found the break is source-reported.
