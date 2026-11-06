---
type: Lesson
title: Stream bodies leave the request connection scope
description: The request connection scope closes at http.response.start, and only BaseHTTPMiddleware's late forwarding of that message let a streaming body's first statement borrow the request connection; with pure ASGI middleware each stream open costs one more checkout, the new count is the contract rather than a regression, and the way to cut it is a connection_scope() around the stream's opening reads.
tags: [lesson, database, connections, streaming, middleware, budgets, measurement]
timestamp: 2026-11-06
---

`ConnectionScopeMiddleware` closes the request's connection scope when the
response sends `http.response.start`, and its contract says statements in a
streaming body take pool connections. For a while they did not, by accident.

# What happened

`BaseHTTPMiddleware` forwards `http.response.start` to the outer send only after
`call_next` returns, while the streaming body generator already runs in an inner
task. So the body's first statement ran before the scope closed and borrowed the
request connection. When the request-body cache layer became pure ASGI
(da22d0974), that delay disappeared: the scope now closes first, and the stream's
opening read checks out its own connection.

Cloud's 0.8.76 release-candidate gate caught it as a hot-path budget for opening
an event stream going from 19 to 20 checkouts. Wheels from aweb 131713729 gave
19; da22d0974 and later gave 20. The asyncpg reset count went from 9 to 10, and a
per-call-site checkout trace put the extra checkout at the stream's opening
viewer read in `routes/events.py`. The ceiling was raised to 20.

# How to apply

- Removing a `BaseHTTPMiddleware` layer can raise budgets by one checkout per
  stream open. When a per-call-site trace attributes the increase to a stream's
  opening statement, the new count is the contract: raise the ceiling and record
  why. This differs from a count that flaps by one with timing (a connection
  parked during a pause), where raising the ceiling hides real growth; the trace
  is what tells the two apart.
- To reduce stream-open checkouts, give the stream's opening reads their own
  `connection_scope()`. Do not move the request scope's close past
  `http.response.start`.

# Measuring gotcha

To run a test suite against a specific package version, use
`uv run --with pkg==X python -m pytest`. `uv run --with pkg==X pytest` runs the
project's own version: the `pytest` script's shebang bypasses the overlay.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-db-access, 2026-11-05; notes/stream-body-statements-leave-request-scope.md. The harvester checked the middleware, the commits and the stream-open read against aweb main at 07f1c8f0c; the Cloud gate counts are the source's report.
