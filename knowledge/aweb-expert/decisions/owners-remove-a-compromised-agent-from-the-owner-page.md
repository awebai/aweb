---
type: Decision
title: Owners remove a compromised agent from the owner page
description: The owner page itself starts an agent's removal from the owner's B3 session, with no terminal and no agent requester, and its client keeps the saved selection through every HTTP error until a verified final committed or refused state; handing out the aw command and a list-only page were rejected.
tags: [decision, owner-page, protected-signer, removal, ux]
timestamp: 2026-11-13
---

The operator's product direction, relayed to the aweb-expert seat by the OSS
coordinator on 2026-11-13 (coordinator rulings de99b105 and 4d1c282e). The
acceptance is **source-reported**: no harvester could read the relay. The
contract amendment on the owner-removal branch records the same direction as
"via coordinator `4d1c282e`".

# Decision

The case is "an agent is compromised and I am not at my terminal". The
compromised party may be the deployment root itself, so removal cannot depend
on an agent asking for it or on a CLI command.

- **The owner page initiates.** Prepare starts from the owner's B3 console
  session. The signer host's requester identity is recorded as provenance only;
  it is not a grant or an approver.
- **One exact-act UV** by the current owner approves the prepared removal. The
  login gesture is not that approval.
- **A new human-origin write route** carries it, with CSRF, a pinned origin and
  no standing authority beyond that one act.
- **Contract first.** The route was built only after a contract amendment
  (drafted by the signer-embedding seat) had a security ACK on its route text
  (security-fixes, 12faf072). The route's rules are in the "Owner-initiated
  prepare" section of `docs/human-assurance-contract.md`; this concept does not
  restate them.

# Rejected

- **Show the `aw` command per member.** It needs a terminal, and a requester
  that may be the compromised party.
- **List members only.** Shipped as the interim read-only member list until
  the route was ACKed, not as the product.

# Client rule: an error never ends a removal

The owner-session prepare route has no HTTP error that proves "no effect"
(403, 404, 409 and 426 included), and it has no owned no-effect retirement
proof. So the page client:

- saves its selection (operation id plus the closed selection) **before**
  sending, keyed by stable service, authority and team, the signed-in approver
  and the certificate, because origin alone separates neither owners nor
  bindings;
- resends the same saved selection on retry; the route returns the original
  prepared request for an exact same-UUID retry and refuses a changed one;
- clears the saved selection only after a verified final committed or refused
  state for that operation, never on an HTTP error.

This rule was settled by the signer-embedding seat answering the source's plan
(4e9d84a4).

# Status on 2026-11-13

The contract amendment and the owner-page client (5e65ae708) are on the
owner-removal branch, in review, and not on main. Whoever lands them or changes
the rule updates this section.

Evidence: OKF proposal from aweb-expert/aweb-expert-signer-ux, 2026-11-13;
notes/owner-initiated-removal-ruling.md, notes/owner-initiated-removal-client-rules.md.
The harvester checked that 5e65ae708 exists on the owner-removal branch, is not
an ancestor of main, and that its contract text names the owner-initiated
route.
