---
type: Decision
title: Tenant-chosen URLs go through egress, with an operator exact-origin allowlist
description: An app fetches a URL its tenant chooses (such as a team's signed team-server record) only through the shared egress guard; dev and e2e stacks reach their own loopback server through an operator list of exact origins that is empty in production, never by lifting the egress loopback floor.
tags: [decision, naapps, egress, ssrf, team-server, security]
timestamp: 2026-11-18
---

Decided on 2026-11-18 in task aweb-adje.16.2. The design was approved by the
naapps coordinator, and the security reviewer ruled on the allowlist with six
conditions and ACKed the implementation. The rule is written in
`docs/design/app-team-server-api.md` §1 step 4 on the task branch; the
rejected alternatives and the safety argument are recorded only here.

# Decision

- A URL the tenant chooses is fetched only through the shared egress guard
  (`aweb_naapp.egress`). The case that forced the decision is the team's
  signed `aweb.team-server/1` record: the team controller picks `server_url`,
  and the app's grant and hook-resolver reads go to it.
- Development and e2e stacks need plain http on loopback, which the egress
  floor refuses for every destination. They reach their own server through an
  operator-configured list of exact origins:
  - entries are https origins, or http only on `127.0.0.1`, `[::1]` or
    `localhost`;
  - the list is canonicalized and checked at startup;
  - a request origin matches only by equality;
  - a non-empty list is logged once at WARNING;
  - it applies only to the team-server reads, nothing else;
  - an injected test transport is honoured only for listed origins.
- The list is empty in production.

# Rejected

- **An operator switch that lifts the egress loopback floor.** The floor is
  shared, so lifting it would also widen hook delivery and the credential
  broker, not just the one read that needed it.
- **Moving dev stacks to https off loopback.** Large churn across the stacks,
  and at least one app's e2e runs the app on the host, where loopback is the
  natural address.

# Why the list is safe

A team cannot add to the list; only the operator configures it. With it empty,
behaviour is exactly the egress path. Registry policy is not a substitute: the
registry accepts any https name whatever it resolves to (see
[trace every check on the write route before sizing a finding](/aweb-expert/lessons/trace-every-check-on-the-write-route-before-sizing-a-finding.md)),
so the client must guard its own reads.

# Status

As of 2026-11-18 the implementation is on the task branch and not yet on
`main`; the full gate at the branch head was still owed. Check `main` before
relying on the allowlist existing.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-egress, 2026-11-18; notes/team-server-allowlist-not-floor-lift.md.
