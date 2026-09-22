---
type: Decision
title: Team certificates are controller-only
description: Registering and revoking a team certificate in the identity registry is authorised by the team controller alone in every hosting mode; capturing an inviter identity and broadening revoke to issuer-or-holder was investigated end to end and declined until member-mediated invites become real scope.
tags: [decision, awid, certificates, teams, authorization]
timestamp: 2026-06-21
---

Decided by the operator on 2026-06-21 after the team had investigated an
additive `issuer` column on team certificates and broadening revoke
authorisation from controller-only to controller, issuer-if-still-member or
holder. Verified against source on 2026-09-21 by the OATS steward: both the
register and the revoke routes in `awid/src/awid_service/routes/teams.py` are
gated by `_require_team_controller`; `docs/awid-sot.md` is the authority.

# Decision

Team certificates are controller-only for both add and revoke. The signer is
the controller in every hosting mode — a self-hosted controller presents the
team-key signature locally; a hosted operator mints server-side on the
controller's behalf. No individual inviter identity is captured, by design.

# Rejected

An issuer column plus issuer-or-holder revoke. It only differs from
controller-only once a non-controller member can add members, which is out of
scope; until then every add is controller-authorised, issuer equals controller,
and the column buys nothing.

# Reopen condition

Member-mediated invites entering scope. At that point the seam is three-lane:
self-hosted local signer, hosted server-side mint, and add-member as a register
entry point. Do not re-propose the column as a standalone improvement.
