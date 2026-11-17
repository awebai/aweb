---
type: Decision
title: Released exported Go names stay
description: An exported name, signature or field of the aw Go packages that shipped in a release tag is public API even when nothing in the repository reaches it; check it with apidiff against the latest release tag, give changed behaviour a new name that the released name delegates to, and keep the released signature but not its old weak semantics.
tags: [decision, compatibility, release, go, api]
timestamp: 2026-11-17
---

The aw Go packages under `cli/go` (`aw`, `awid`, `awconfig`, `chat`, `run`
and the others) are a documented Go library: `cli/go/README.md` says so and
invites importers. This is the Go-library side of
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

# Decision

- An exported function, type, method or field that is in the latest aw
  release tag stays, with its signature, even when no binary or test in this
  repository reaches it. "Neither a binary nor a test reaches it" is not
  evidence that a library name is unused: its callers are importers outside
  the repository. The rule that code left unused by a change is deleted
  ([tests exercise the real authority](/aweb-protocol-expert/decisions/tests-exercise-the-real-authority.md))
  does not apply to released exported names.
- Check with a real API diff against the tag, not by reading the diff or
  grepping: `golang.org/x/exp/cmd/apidiff`, writing the tag's export data
  with `-m -w`, then `-m -incompatible` against the head. Run it for each
  package a change touches, before removing or changing an exported name.
  Additions are fine.
- When a released signature must change, the released form stays. The new
  behaviour gets a new name, and the released name delegates to it (for
  example `chat.Open` next to `chat.OpenConfirmed`, `ListRegistrations` next
  to `ListRegistrationsWithFaults`).
- A released name keeps its signature, not its old weak semantics.
  `awid.VerifyTeamCertificate` was restored with its released signature but
  runs today's strict check: restoring its signature-only body would have
  published a verifier that accepts what aw refuses.
- A struct that gains a non-comparable field (a map or slice) is still an
  incompatible change, because `==` on it stops compiling. The reviewer
  accepted announcing two such changes in the release notes rather than
  reverting them (source-reported).

# Why

On 2026-11-17 `chat.ExtendWait` was removed as a leftover wrapper because
only one test called it. It had shipped in aw-v1.36.58, and review caught the
removal. The apidiff run that followed found eight `awid` names deleted
earlier by a cleanup titled "Delete Go code that neither a binary nor a test
reaches", plus further removed names and changed signatures in `chat`,
`wake`, `awid`, `a2a` and `awconfig`. Reading the diffs by eye had missed
them. All were restored on main (82353bd31d, 2880a740cf), each removed name
byte for byte from the tag.

# Elimination route

This rule should be a gate: an apidiff run against the last aw release tag in
the release checks. As of 2026-11-17 no such gate exists, so the check is
manual.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/released-exported-names-stay.md. Restore commits 82353bd31d and 2880a740cf and tag aw-v1.36.58 verified on aweb main.
