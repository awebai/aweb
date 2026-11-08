---
type: Decision
title: Human treatment requires the subject's own verified kind
description: A member is treated as human only on its own currently verified human subject kind, never on a raw team label; legacy labels stay only to name the predecessor in owner-checked history recovery and to exclude unverifiable members from agent displays, and neither use grants human authority. Ruled; on a review branch, not on main or released.
tags: [decision, identity, human-channels, recipient-kind, migration]
timestamp: 2026-11-08
---

Ruled by the operator on 2026-11-08 (task aweb-acwb). The acceptance is
**source-reported**: the coordinator relayed the ruling, and the coordinator's
approvals of the design, of the historical scope and of the display exception
were also reported by the source. No independently readable acceptance record
exists.

**Status (2026-11-08):** implemented on the source's review branch at
`4ee3ddfca`, pending review; not on main, not released, not deployed.

This supersedes one premise of
[humans use mail; recipient kind is authoritative](/aweb-protocol-expert/decisions/humans-use-mail.md)
(D8): that a team row typed `human` is authoritative human evidence. The rest
of D8 stands unchanged: humans are reached by mail, unknown kind is not human,
an agent with a responsible human is still an agent, and clients render the
backend's decision.

# Decision

- Current human treatment (refusing chat, human-only behaviour, any human
  capability) requires the subject's **own** verified kind: a valid identity
  whose verified kind is human. A raw `human` team label, a human ancestor, a
  team certificate, account ownership, custody or a client-claimed runtime
  type does not supply it.
- Legacy human labels are kept, not relabelled, for two separate uses that
  grant no current authority:
  - **Predecessor recovery.** In owner-checked retired-mail succession,
    contact transfer and pre-cutover alias retirement, a legacy label may
    identify the old predecessor. The new or live destination must itself
    satisfy the verified-kind rule, and the independent ownership checks still
    apply.
  - **Display exclusion.** Agent rosters and dashboards may keep excluding
    raw-labelled members, so an unverifiable old human is not shown as an
    agent. Its effective kind is unknown; no capability may use the label.
- Revalidation of existing labelled members measures and explicitly disposes
  of the unresolved ones. It never claims they were verified and never
  silently removes their former treatment.

# Why

A label recorded on a team row cannot prove what kind of identity holds the
row now. But labels are also the only record of which old owner a piece of
history belonged to, so erasing them would block rightful recovery, and
demanding fresh proof from a retired predecessor would make that recovery
impossible for legitimate historical owners. Requiring verified kind only of
the live destination keeps the authority boundary while leaving history
recoverable.

# Rejected

- Keeping the raw team label as human evidence: a future change must not
  restore that gate.
- Blanket relabelling of old human rows: it destroys the provenance that
  owner-checked recovery depends on.
- Requiring verified human kind of the historical predecessor as well as the
  destination: it blocks legitimate recovery.
- Displaying unverifiable old human-labelled members as agents: it invents an
  agent identity from missing human evidence.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-human-kind,
2026-11-08; notes/human-kind-history-boundary.md. The public contract is
`docs/id-certificates.md`, "Team-row human classification", at branch commit
`4ee3ddfca`; that commit is implementation evidence, not acceptance evidence,
and not evidence of release. Coordinator message identifiers are omitted.
