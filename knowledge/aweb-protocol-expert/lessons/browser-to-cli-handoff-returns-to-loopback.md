---
type: Lesson
title: A browser-to-CLI handoff returns its result to loopback
description: A device-style handoff with a typed user code is phishable, and binding the result to an ephemeral key does not help; the default is a verifier-bound redirect to a stored literal 127.0.0.1 or [::1] URI (RFC 8252), and a typed code is only a no-browser fallback with a warning and an owner-visible governance event.
tags: [lesson, security, sign-in, cli, browser, review]
timestamp: 2026-11-08
---

Review of a CLI sign-in and approval contract in November 2026 found this
twice in an otherwise acknowledged design: first the device-code flow, then
the fix's unrestricted redirect URI, which reopened the same hole.

- **A typed user code binds nothing to the client that started the flow.**
  An attacker starts a handoff with its own key and sends a victim the real
  page and the real code. The victim signs in and the attacker's client
  collects the result. Binding the result to an ephemeral client key does not
  help, because the attacker holds that key.
- **The result must return to the machine that started the flow.** The
  default is a loopback redirect bound to a verifier, as RFC 8252 describes.
- **The redirect URI is part of the defence.** If the app accepts any
  redirect URI, the attacker registers its own callback and the phishing
  path is back. The app accepts only a literal `127.0.0.1` or `[::1]`
  redirect URI, refuses `localhost` and every other URI, and redirects only
  to the URI stored when the flow started.

# How to apply

- When specifying any CLI sign-in, approval or secret-release flow that goes
  through a browser, make the loopback redirect the default result path.
- Validate the redirect URI at registration against the literal loopback
  addresses, and redirect only to the stored value, never to one supplied
  later.
- Keep a typed code only as a no-browser fallback. It shows a warning page
  and emits an owner-visible governance event, so a phished use can be seen.

# Status

Specified in the reviewed contract, which reached final acknowledgement on
2026-11-08 with landing requested; not implemented. On aweb main at
06e61e395 the device flow was only planned, so the code does not show this.

Related: [a one-time secret goes to the client that makes the releasing call](/aweb-protocol-expert/lessons/one-time-secret-goes-to-the-releasing-caller.md),
from the same review.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/browser-to-cli-handoff-lessons.md.
