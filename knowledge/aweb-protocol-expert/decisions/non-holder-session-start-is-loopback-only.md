---
type: Decision
title: A session start by someone other than the holder is loopback only
description: When an agent whose direct parent is human H starts H's app session, the typed user_code fallback is refused with 400 handoff_invalid and only the loopback can collect the result; H's own same-signer start keeps the conditional fallback, which is live where the app emits session.handoff_completed and otherwise 409 fallback_unavailable. Frozen in a contract on a review branch, not yet on main.
tags: [decision, security, handoff, sessions, cli, human-assurance]
timestamp: 2026-11-11
---

**Status (verified 2026-11-11):** frozen in `docs/human-assurance-contract.md`
(the direct-child session section, and section 10) at 584d76c9c on a review
branch, not on aweb main. The contract records the operator's approval of the
architecture on 2026-11-11; this specific choice was ruled by the coordinator
and the security reviewer.

# Decision

- An agent Q whose direct parent is human H may start H's app session. That
  start is **loopback only**: `return: user_code` refuses with HTTP 400
  `handoff_invalid` before any handoff is created.
- Only aw's in-memory ephemeral key, verifier preimage and single-use loopback
  code can collect the result. The session is H's, with H's holding and
  membership checks unchanged.
- H's own same-signer start keeps the typed-code fallback, under its usual
  condition (below).

# Why

The one-gesture direct-child design is safe only because the result reaches
the loopback on the machine of the human who completed the ceremony; a
requester elsewhere collects nothing. The typed-code fallback exists to remove
exactly that machine binding, so a human can finish a ceremony for an aw on
another machine. With Q as requester, the fallback would hand H's session to
an agent's aw elsewhere after H types a code: the device-code phishing pattern
with an agent as receiver. The completion event also names H's login, not the
agent that asked.

# Rejected

- **Allow the fallback for Q plus a requester field on
  `session.handoff_completed`.** The page display becomes the only consent
  signal on the riskier path, and the event catalog has to change. H on
  another machine can still use H's own fallback.

# The fallback is live and conditional

The typed-code fallback for a `session` handoff is not removed. It is allowed
only where the app emits the owner-visible `session.handoff_completed`
governance event; otherwise the start refuses with `409 fallback_unavailable`
(`docs/design/handoff-wire.md`). The bullet in
`docs/design/human-confirmation-from-aw.md` saying a `session` handoff
"returns its result only to the loopback" describes the default path, and its
"Fallback: no local browser" section qualifies it. Reading the bullet alone
led to a confident wrong ruling that sessions are loopback only, which had to
be retracted.

# How to apply

- Before answering an SSH or no-browser question, read the Fallback section,
  not only the summary bullets.
- Any new path where someone prepares a session for the holder inherits
  loopback only unless a ruling adds requester-visible audit.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-11; notes/non-holder-session-start-loopback-only.md; notes/browser-to-cli-handoff-lessons.md.
The loopback-only rule and its refusal were checked in
`docs/human-assurance-contract.md` at 584d76c9c; `409 fallback_unavailable`
in `docs/design/handoff-wire.md` at 27169df70; the default-path bullet and the
Fallback section in `docs/design/human-confirmation-from-aw.md` on main at
7f4be32fa. The rejected alternative and the retracted reading come from the
source notes.
