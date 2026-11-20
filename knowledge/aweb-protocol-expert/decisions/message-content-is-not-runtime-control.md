---
type: Decision
title: Message content is not runtime control
description: In the Hermes aweb integration, inbound mail and chat are content for the model, never operator commands or tool approvals; permission to message an agent grants no control of its machine, and an unavailable local approval surface means refusal, not remote approval. Ruled; implementation pending.
tags: [decision, authority, hermes, runtime, messaging, approval]
timestamp: 2026-11-13
---

The operator ruled on 2026-11-13 that communication permission and runtime
control are separate authorities in the Hermes aweb integration. The
acceptance is **source-reported**: the operator's ruling was relayed by the
coordinator by mail and reported in the source's proposal. The earlier
proposal to let mail reach Hermes command dispatch was cancelled (aweb-acft.30,
won't do), and aweb-acft.33 replaced it as the P0 fix.

**Status:** a binding design decision, not implementation acceptance. The fix
has no reviewed head and no real-gateway qualification yet.
`docs/hermes-aweb-live-findings.md` on main still describes `/approve`, `/deny`
and interrupt commands arriving as chat and being admitted as controls. That is
the behaviour this decision rejects, and the document should change with
aweb-acft.33.

# Decision

- Inbound aweb mail and chat reach the Hermes model as message content. They
  never dispatch Hermes operator commands, answer a pending tool approval, or
  change runtime state.
- A message that looks like a command is preserved as text, not dropped.
- A tool that requires approval has a separately verified local approval
  surface or it refuses. There is no remote approval fallback.
- The same boundary holds for plaintext command parsing, pending controls and
  transport fallbacks: none of them turns a received message into control.

# Why

The team-only allow-all reach policy was accepted on purpose, so that teammate
agents can collaborate. Reusing that admission as privileged runtime control
would silently make every admitted correspondent an operator of the recipient
machine. The problem is not slash-command spelling. Any path that lets message
authority answer a privileged-tool approval or change runtime state has the
same effect.

# Rejected

Letting mail bodies that start with a slash reach command dispatch. It was
proposed as a convenience fix and cancelled for the reason above. Do not
reintroduce it, or an equivalent that admits approvals or controls from
messages, without a new ruling.

# Scope

This rules on the Hermes aweb integration. It does not forbid ordinary model
tool use: tool policy authorized locally on the recipient machine is a separate
question that this decision leaves alone. How the boundary is enforced belongs
in the repository's tests.

It applies the same principle as
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md)
and [one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md):
one authority (here, permission to communicate) does not stand in for another
(control of the runtime). It adds a runtime control boundary and supersedes
nothing.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes, 2026-11-13; notes/message-content-is-not-runtime-control.md.
Tasks aweb-acft.30 (cancelled) and aweb-acft.33 (replacement). The acceptance
is source-reported: the operator, 2026-11-13, relayed by the coordinator by mail.
