---
type: Decision
title: Credential lifetime is optional team policy
description: Certificate and grant expiry is a per-team setting with no expiry by default and live revocation as the primary control; a renewal that replaces a certificate does not end the grants it issued, and no renewal or policy change ever extends a deadline. Ruled, not yet shipped.
tags: [decision, awid, certificates, grants, revocation, lifetime]
timestamp: 2026-10-20
---

Ruled by the operator on 2026-10-20, rejecting a design with fixed maximum
lifetimes that the security reviewer had already accepted: "key expiry has to
be a team policy for each team. for many small teams expiry is just useless
friction." The OSS coordinator confirmed on 2026-10-25 that the ruling stands.

**Status:** accepted direction, not shipped. The reviewed implementation is
parked unlanded. Until it lands, `docs/awid-sot.md` correctly says a
certificate is valid until revoked, which remains true for every team that sets
no lifetime.

# Decision

- Per-team, nullable lifetimes for member certificates, ephemeral certificates,
  identity grants and hosted MCP grants; unset by default.
- A certificate may carry an optional signed `expires_at`; verifiers refuse an
  expired one. Verifier support ships before any team can enable expiry, and a
  certificate without expiry is the valid default, not a legacy form.
- No global cutoff. A team's grant cap is checked on every verify, so existing
  over-cap grants stop at once when a team sets one. Renewal applies only to
  teams that set a lifetime.
- Enabling a lifetime makes certificates without expiry due for renewal;
  disabling one never extends a deadline already signed. On a standalone
  server, the existing admin or controller authority sets policy, never a member
  or a grant.

# Renewal does not end grants

Ruled by the security reviewer on 2026-10-20, superseding an earlier design in
which renewal invalidated grants: when the issuing certificate was revoked as
replaced, follow the replacement chain (bounded, refusing cycles) to an active
certificate with the same member key and team. A disciplinary revocation, with
no replacement, still ends every grant it issued at once. A grant's own
deadline, clamped at mint, still binds; renewal never extends it, and removing
a policy never ends a grant or extends a deadline. Ending grants on rollover
had no security value and would break long-running agent sessions every
renewal cycle.

# Rejected

Fixed maximum lifetimes with a global cutoff for certificates without expiry
and forced re-consent for MCP grants: friction for small teams with no
proportional gain while live revocation exists.

Related: [team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-chat-session-fix`
(coordinator relay fc7e04ef, security reviewer fc6d401f, c11beaf8 and 57912983;
the seat's reply 145a45c9 confirms no superseding ruling in its records).
Confirmed by the OSS coordinator in f8d89364, which attributes the renewal rule
to the security reviewer, not the operator.
