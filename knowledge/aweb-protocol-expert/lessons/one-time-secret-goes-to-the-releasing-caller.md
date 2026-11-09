---
type: Lesson
title: A one-time secret goes to the client that makes the releasing call
description: A secret released only in a mutation's response reaches whichever client makes that call, so to keep it out of the browser the protected client makes the call while the human gestures in the browser; the entitled caller is the decider plus the client kind, not one session, and only the authenticated drafting route sets the mark that selects this journey.
tags: [lesson, security, secrets, cli, browser, review]
timestamp: 2026-11-08
---

Review of the secrets naapp's runner-registration contract in November 2026
found that the registration code would reach the browser although the
contract said it was for the terminal, and then that the fix could strand
some confirms.

- **The response decides who sees the secret.** The runner registration code
  exists only in the change-set confirm response and is never stored. If the
  browser makes the confirm call, the browser sees the code, whatever the
  contract says about the terminal.
- **Fix: the protected client makes the call.** The human still approves in
  the browser; the CLI then calls confirm itself and receives the code.
- **Sessions expire before slow approvals finish.** Tying confirm to the
  drafting session would strand an approval that outlives it. The entitled
  caller is any key-bound session of the same decider, identified by decider
  plus client kind.
- **Only the authenticated drafting route sets the journey mark.** The mark
  that says "confirm in the CLI" is set only by a draft made through the
  key-bound drafting route, never by an agent (team-auth) draft or a browser
  draft. Otherwise an owner who uses only the browser is stranded with a
  change they cannot confirm.

# How to apply

- For any secret that is released once and not stored, name the client that
  must receive it and make that client the caller of the releasing mutation.
- Authorize that call by who decided and which kind of client calls, not by a
  single session.
- Set the journey-selecting mark only on the route that proves the protected
  client is present, and check that every other drafting route still has a
  way to confirm.

# Status

Specified in the reviewed contract, which reached final acknowledgement on
2026-11-08 with landing requested; not implemented. On aweb main at
06e61e395 confirm requires the decider's scope and subject
(`naapp/secrets/src/aweb_secrets/console_changes.py`), and the results module
says codes go only to the deciding owner's console session and are not
persisted (`naapp/secrets/src/aweb_secrets/console_results.py`). The code does
not say that, because nothing is stored, the confirm response alone decides
which client sees the code.

Related: [a browser-to-CLI handoff returns its result to loopback](/aweb-protocol-expert/lessons/browser-to-cli-handoff-returns-to-loopback.md),
from the same review; [gate before the point of no return](/aweb-protocol-expert/lessons/gate-before-the-point-of-no-return.md),
also about the secrets naapp's confirm boundary.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/browser-to-cli-handoff-lessons.md.
