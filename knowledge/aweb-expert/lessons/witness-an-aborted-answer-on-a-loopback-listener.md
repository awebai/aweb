---
type: Lesson
title: Witness an answer the front aborts on a loopback listener
description: A Caddy 2.10 front that aborts a response logs status 0 and drops log_append fields, so it cannot record the app's real answer; routing only the watched method and path through a second loopback site with its own filtered access log records the app's status before the abort, without changing the app's logging.
tags: [lesson, testing, caddy, evidence, logging, e2e]
timestamp: 2026-11-13
---

Observed on 2026-11-13 with a checksum-verified Caddy 2.10.2 release binary
in front of a stub app, over HTTP. A test needed to drop the app's answer to
one request before it reached the client, and still prove what the app had
answered. The Secrets image serves with no access log on purpose, so the app's
own log could not be the witness, and changing that policy for a test was
not acceptable.

# What does not work

- In a site that proxies and runs `handle_response` with `abort`, the client
  gets an empty reply and the access log records `"status":0`.
- `log_append` inside `handle_response` adds nothing to an aborted request. At
  site level, `{http.reverse_proxy.status_code}` is evaluated too early and
  logs null. A `<` prefix on the field name is not supported in 2.10.2; it
  becomes a literal key.

# What works

- Route only the watched method and path to a second site inside the same
  front, `http://:<port>` with `bind 127.0.0.1`, which proxies to the app.
- Give that site its own access log with a `format filter` that deletes
  request headers, TLS details, the client address and response headers. Its
  log then carries the app's status, the method, the original Host and the
  URI. A test Authorization header did not appear in it.
- Aim the drop at that inner listener. The witness logs the app's status (200
  on the dropped request, 409 on the next one) before the outer site aborts.
- Address the inner site by port only. `http://127.0.0.1:<port>` matches only
  requests whose Host is `127.0.0.1`, so proxied requests carrying the
  original Host miss it.

The witness lives only in the test's front configuration; the app's
production logging is untouched. The team-deployment journey's protected
round trip uses it (on aweb main from dfce11678).

# Limits

Not yet observed over TLS in a native run.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/caddy-abort-hides-the-upstream-status.md. The harvester checked that
dfce11678 is on aweb main and that its front configuration binds the witness
site to 127.0.0.1. The Caddy observations are source-reported.
