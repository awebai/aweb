---
type: Decision
title: Hosted init refusals use a fixed vocabulary
description: aw init shows a hosted refusal's code only when it is in aw's own public vocabulary, always with aw's own remedy; unknown or disagreeing codes stay "unknown" and server messages are never shown, which keeps Juan's approved diagnostic contract. Extending the vocabulary is how a refusal becomes actionable. Decided; on a review branch, not yet on main.
tags: [decision, aw-cli, init, hosted, diagnostics, privacy]
timestamp: 2026-11-17
---

**Status (checked 2026-11-17):** the diagnostic contract is on main (4e477ad74d,
first released in aw-v1.36.24). The per-code remedies are on the review branch
`agents/aweb-protocol-expert-team-key-trust` at c9f8f8738e, not yet on main.

# Decision

- When hosted `aw init` refuses, aw prints a refusal code only if the code is
  in its own public vocabulary of known refusals, and always with aw's own
  remedy for that code.
- An unknown code, or codes that disagree within one response body, are shown
  as `unknown`.
- The server's own messages and arbitrary response bodies are never shown.
- To make a new refusal actionable, add it to the vocabulary with an aw remedy
  that aw itself can carry out (see
  [context-changing init remedies go to a new directory](/aweb-protocol-expert/decisions/context-changing-init-remedies-go-to-a-new-directory.md)).

# Why

This is the diagnostic contract Juan approved for task aweb-aboa on
2026-10-05: hosted bootstrap diagnostics carry a bounded category, status,
known code and unambiguous request ID, and omit arbitrary bodies. Operators
forward this output, so it must not carry arbitrary server text or codes aw
does not understand. The coordinator ruled on 2026-11-17 that this approval
still stands for the per-code remedies work.

# Rejected alternatives

- **Printing any code that passes a syntax check.** It would supersede Juan's
  approved contract, which no agent ruling can do.
- **Repeating the server's remedy text.** The server's text can describe a
  path that the init route cannot take. For example, the hosted message for
  `custodial_reinit_forbidden` points to a path that needs a person session,
  which `aw init` does not have, so repeating it would mislead the user.

# How to apply

A bug report that says "the parser drops the error code" may be describing
this allowlist, not a parsing bug. Check whether the code is simply missing
from the vocabulary before you change the parser. In the case that produced
this decision, the parser read the code correctly and the allowlist suppressed
it on purpose.

Acceptance: the contract is Juan's, verified at commit 4e477ad74d on aweb main.
The 2026-11-17 coordinator ruling is source-reported (coordinator mail
08bb057a).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/hosted-init-refusal-display.md. Checked by the harvester against c9f8f8738e (workspaceInitRefusalRemedies and the summary that falls back to `unknown`, in cli/go/cmd/aw/init_apikey_diagnostic.go) and docs/hosted-global-bootstrap.md at that commit.
