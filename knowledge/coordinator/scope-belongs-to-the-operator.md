---
type: Decision
title: Scope belongs to the operator
description: A reviewer, another coordinator or a relay can recommend cutting or deferring requested features, but only the operator decides; a reduced first version is not a cheap prefix of the full product because its architecture differs, so the team designs for the full scope.
timestamp: 2026-10-20
---

Ruled by the operator on 2026-10-19, after a security review proposed cutting
requested features from a first version of human channels and the coordinator
accepted the cut and landed the reduced design: "that was there because i
requested it. [the reviewer] should not cut it without my permission. i do not
want a half-baked v1, i need the full functionality even if it takes a bit
longer. also i need the team to go back and think it through, because the
architecture for the full thing will not be the same as the architecture for
that v1."

The next day a relay from another coordinator said the operator wanted one lane
paused down to one thin end-to-end path. The operator's own words, minutes later:
"make sure to follow what we are trying to do and not cut corners" and "do not
cut corners. this is fundamental to get right." The coordinator sent a
correction replacing the narrowing.

## Decision

- A review verdict rules on correctness and security. Removing or deferring a
  requested feature is a product decision, so it goes to the operator as a
  recommendation with its trade-offs.
- A coordinator's latitude to decide routine choices without ceremony does not
  cover scope.
- A scope change relayed by another coordinator is checked against the
  operator's own words and the accepted plan before anything is cut or paused.
  Process parts of the same relay may still apply.
- Design for the full scope. A deferred item stays an owned task, not a
  "later".

This extends [verify business facts; consolidate before cutting](../aweb-expert/lessons/verify-business-facts-and-consolidate-before-cutting.md)
from cuts the coordinator proposes to cuts that reach it from others.

## Provenance

Harvested 2026-10-25 from the `integrations` coordinator seat (its
note on who owns scope cuts; operator ruling recorded on its epic and in its
session transcript) and the `secrets` coordinator seat (Claude memory
`no-corners-drive.md`; relayed direction of 2026-10-20T15:36Z and
operator turns up to 15:42Z).
