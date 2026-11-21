---
type: Decision
title: Signed team reads share one verifier, not one access policy
description: Every private-team read resolves the reader's did:key in one verifier, a covering-v2 read_team envelope or else the counted path signature, and each route keeps its own key rule over that key for both forms; a present covering header never falls back, a failing proof is refused rather than read as anonymous, and a third signed format and one policy for all routes were rejected. Ruled; on a review branch, not on main.
tags: [decision, awid, teams, signed-reads, controller-auth, compatibility]
timestamp: 2026-11-17
---

# Decision

- **One verifier.** A private-team read resolves the reader's `did:key` in one
  place in the registry (`_signed_reader` in the team routes):
  - when `X-AWEB-Signed-Payload` is present, a covering-v2 envelope with
    operation `read_team`, whose claims are `domain` and, for a read under one
    team, `name`; the envelope binds the registry audience, the method and
    the path with its query;
  - otherwise the path signature in `Authorization`, which binds the path
    only; it is accepted and counted until it is measured unused;
  - otherwise the read is anonymous.
- **Each route keeps its own key rule**, the same for both forms:
  - team key or an unrevoked member: team metadata, the team list, members,
    the certificate list and revocations;
  - only the certificate's own member: the certificate blob fetch;
  - only the team key: signed records.
- **No fallback, no silent downgrade.** A present covering header is verified
  only as covering; it never falls back to the path signature. A supplied
  proof that does not verify is refused, never treated as anonymous. An empty
  `Authorization` header stays anonymous.
- **The team list signs no name.** With no team in the path its claims are
  `domain` and `operation` only: `name` is absent, not null.
- **`read_team` sits among the controller operations** only because the
  controller request verifier is the covering verifier. It proves which key
  signed; what that key may read is the route's decision.

# Rejected

- **A third signed format** (the path signature extended with the query). It
  would still bind no audience, so a read signed for one registry would
  authenticate at another.
- **One access policy for every route.** "One rule" was required as one
  verifier, not one policy. Widening the blob fetch or signed records to every
  member would leak certificate blobs and custodian records to all members.

# Status and constraints

- Ruled on 2026-11-17 under the identity-path delegation Juan gave on
  2026-11-16; the ruling required the same access-rule code for both forms
  and every gated read in one change. **Acceptance: source-reported** (team
  mail relayed by the coordinator, which the harvester could not read).
- Built on the review branch `agents/aweb-protocol-expert-team-key-trust`
  (commit 29db28565, `awid/tests/test_team_read_requests.py`); not on main,
  not released, and no client signs covering reads yet, as of 2026-11-17.
- The path signature stays because
  [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md);
  when it may go is read from the registry's metrics as
  [reading the signed-form metrics before a removal](/aweb-protocol-expert/lessons/reading-signed-form-metrics-before-a-removal.md)
  describes.
- Extending either form, removing the path signature or adding a gated route
  keeps this split: resolve the key in the one verifier, decide access in the
  route. Changing a route's key rule is a new ruling, as
  [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
  requires.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/signed-team-read-design.md.
