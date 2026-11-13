---
type: Decision
title: Agent membership removal has two modes, root first, and aw leaves the member's home alone
description: OATS removes an agent's team membership through the member's own leave first and falls back to the deployment root, which also reconciles leaked memberships, so aw's root mode was built first; aw changes nothing in the member's home, because after an unknown removal the certificate there is the retry's evidence.
tags: [decision, oats, aw-cli, teams, certificates, retire]
timestamp: 2026-11-13
---

This is how aw serves OATS's agent-removal operation (`team.agent.remove`).
The OATS-side order comes from OATS spec v4.3.2, clauses C-5 and C-6. It
reached the aweb-expert seat as a relay from the OATS expert (73dc64c9). That
acceptance is **source-reported**: no harvester could read the record.

# Decision

- **Two modes.** C-6 retire first tries the member's own removal (self mode)
  and falls back to the deployment root (root mode). C-5 reconciliation of
  leaked memberships, whose home is already gone, uses the root. Root mode
  alone covers both the fallback and reconciliation, so it was built first.
- **aw changes nothing in the member's home on removal.** After a confirmed
  removal OATS deletes the home. After an unknown outcome OATS keeps it, and
  the installed certificate there is what the retry names.
- **The subject is projected from that certificate file**, with no registry
  read on the client. The file is a snapshot of the target, not authority:
  the server checks it against a fresh registry record.
- **The client accepts only what it can verify.** The frozen artifact must be
  the revoke request aw rebuilds itself, under the profile's pinned controller
  and with this root's own requester key. A committed result must be that
  controller's signature over exactly those bytes.

# Rejected

**Cleaning up the member's home after removal.** It looks like tidy
behaviour. It destroys the only evidence an unknown removal leaves, and the
retry has nothing to name. Home disposal belongs to OATS, after a confirmed
removal.

# Status on 2026-11-13

- Root mode (aweb-aczy) passed review: naapp-review ACK e501c0bf and
  security-fixes ACK f4db1d7e, which caught six mutation controls. It is on a
  branch and not yet on main.
- The server side is on another branch and has not landed either.
- Self mode is not built. It needs the team-auth v2 request envelope with the
  team certificate header, and the server's public test vector. It waits for
  the server to land.

Whoever lands root mode, the server side or self mode updates this section.

Related: [team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/agent-removal-modes-and-evidence.md. The OATS clauses reached the seat
as the source's report of a relay. The harvester checked the root-mode branch
head 4880e8433, which adds `aw id team remove-agent`: it is not an ancestor of
main.
