---
type: Lesson
title: Membership evidence rides with the binding act
description: The holder's team certificate travels in the body of the act that binds the holding and is retained only after verification; keeping it as state against a credential not yet bound recreates the pending rows the human-role-holders design removed and puts a time limit on two-person designation.
tags: [lesson, naapp, human-role-holders, owner-acts, evidence, design-review]
timestamp: 2026-11-09
---

The decided human-role-holders design (`docs/design/human-role-holders.md`,
section "No prepare, no pending rows, no role tokens", ruled by the operator)
removed prepare together with its pending rows and their lifetimes. The act
names the credential itself, and a member takes no part in designation.

A later draft retained the holder's team certificate at the `credential`
handoff "until an act binds it". That recreated a pending row by another name.
It also broke two-person designation: when the owner is not the holder, the
two clients compare a fingerprint before the owner signs, and that comparison
can outlast the handoff's lifetime, so the parked evidence expired before the
act arrived. A second reviewer caught it after the first review passed.

The fix: the team certificate rides in the owner-act delivery body next to
`credential`, and stage 3 checks it when the act binds the holding. A team
certificate is a public statement signed by the team key, so it needs no
proof of who carried it, and anyone may deliver it with the act.

# How to apply

- Evidence goes in the request that consumes it. It is kept only after that
  request has verified it.
- Keep no state for a credential, holder or session that is not yet bound.
  If a design needs such a row, check it against the design's accepted
  "no pending rows" rule first; changing that rule needs a ruling (see
  [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)).
- Evidence that is a public signed statement (a team certificate) can travel
  with any carrier. Evidence that proves possession cannot, and needs its
  own binding.

# Status

The "no pending rows" section is on aweb main at 9a54c7392. The delivery
body carrying the team certificate (stage 3 of human-role-holders.md, and the
membership-evidence section of human-confirmation-from-aw.md) is at
8e7ca8565, on a review branch and not on main. The source reports it ACKed by
two reviewers and fit for use by two implementers. The proposal attributes
the removal of pending rows to the operator's H4 ruling; the design on main
records that the operator ruled H1 to H4.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/two-origin-handoff-and-carried-certificate.md.
