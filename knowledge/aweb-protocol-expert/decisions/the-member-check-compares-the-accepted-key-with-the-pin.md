---
type: Decision
title: The member check compares the accepted team key with the pin
description: Each server member row records the team key its certificate was accepted under, and a member is a member only while that key equals the team's admitted pin; a row with a certificate but no recorded key fails closed, and the check ships enforcing with a one-time fill. A raw registry comparison was rejected because a substituted registry key would satisfy it. Accepted; on a review branch, not on main.
tags: [decision, teams, keys, membership, certificates, security]
timestamp: 2026-11-15
---

The operator approved the "Membership and key changes" section of the
architecture "Human approval and key custody" on 2026-11-15, and ruled the same
day that the member check ships enforcing together with its one-time fill; a
counting-only release was withdrawn. A team ruling that the pinned-key rule
(V1) stays and that the member check compares against the admitted pin was
relayed by the aweb coordinator. All of this is source-reported, from mail not
readable here.

# Decision

- Each member row on the server records the team key under which this server
  last accepted the member's certificate. A one-time migration fills it from
  the pin.
- Wherever a member is looked up, it is a member only while that recorded key
  equals the team's pin: the team key the server admitted, which moves only on
  the namespace controller's act (V1).
- The comparison is part of the query that already loads the member row. It
  adds no registry or database call.
- A row that has a certificate but no recorded key is refused, so a writer that
  forgets the column fails closed.

When a team key changes, every member accepted under the old key stops being a
member until the server accepts its certificate under the new key.

# Rejected

- **Comparing with the registry's current key:** a key substituted in the
  registry would satisfy a check that the pin refuses.
- **A counting-only first release:** withdrawn by the operator in favour of
  shipping enforcement with the fill.

# How to apply

- Every writer of member rows, hosted writers included, sets the accepted key
  from the key it verified the certificate under.
- A new membership site uses the shared member-key check, never its own
  comparison.
- A test that edits member rows or replaces the team key directly in SQL also
  records the accepted key, or the member reads as superseded.

# Status

Implemented on the review branch `agents/aweb-protocol-expert-team-key-trust-adcl3`
(checked at 56687aa6e), under correctness review and not on main at harvest
time (main at 3bb8fefab).

Related: [a team key change carries the members' new certificates](/aweb-protocol-expert/decisions/a-team-key-change-carries-the-members-new-certificates.md),
which restores membership in the same act that changes the key, and
[key authority history spans every path to the key](/aweb-protocol-expert/decisions/key-authority-history-spans-every-path.md),
the same every-path discipline.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-15; notes/member-check-compares-accepted-key-to-pin.md. Checked against the branch at 56687aa6e.
