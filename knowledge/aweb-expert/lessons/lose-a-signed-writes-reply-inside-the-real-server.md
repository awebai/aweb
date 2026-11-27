---
type: Lesson
title: Lose a signed write's reply inside the real server, not with a proxy
description: To test a committed signed write whose reply is lost, inject the loss as middleware on the real fixture app; a reverse proxy on another origin is refused, because the server admits signed requests only for its own public origin, and reads through the proxy pass and hide the cause. Then disable the recovery under test and show the test fails.
tags: [lesson, testing, fault-injection, team-auth, signed-requests]
timestamp: 2026-11-27
---

A test needed the server to commit a grant revoke and the client to lose the
reply. A reverse proxy in front of the real aweb server, forwarding the revoke
and then dropping the client connection, never reached the commit: the server
answered 401 "signed request payload audience is not allowed". `aw` signs a
mutating request for the URL it sends it to, and the server admits exactly one
audience, its configured public origin (`request_auth_audiences` in
`server/src/aweb/team_registry.py`). Unsigned reads passed through the proxy,
so the first failure looked like a Host header problem and cost a round.

# What worked

`scripts/test-egress/aweb_fixture.py` already loses a committed write's reply
as HTTP middleware on the real app (the certificate registration loss). The
same pattern, armed once for the first grant revoke, lets the real route
commit and then fails the response body. The request is signed for the
server's own origin, so the real authority decides it.

# How to apply

- Inject a lost reply of a signed write inside the real server process, as
  fixture middleware that lets the route commit first. Do not put a proxy on
  another origin in front of it.
- A proxy is still fine for a request that must never reach the server
  (dropped before forwarding); it cannot model a write that committed.
- Then prove the test decides: disable the recovery under test (here the
  read-back after the lost reply) and the lost-reply test must fail. Otherwise
  a client-side retry could be what passes it. This is the removal control of
  [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

Seen once, in this repository.

Evidence: OKF proposal from aweb-expert/aweb-expert-aw-contract, 2026-11-27; notes/lost-reply-of-a-signed-write.md. The single-audience check and the existing middleware were checked by the harvester on aweb main 39b3f0911; the grant revoke fixture is source-reported, on a branch not yet on main.
