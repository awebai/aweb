---
type: Lesson
title: Team-auth steps run on the app origin
description: A naapp's human origin refuses every team-auth header before any route, so in a human-confirmation design each step that carries team-auth goes on the installation's app origin and the human-origin steps use the console headers with aud set to the human origin; name each step's origin, path, authentication and aud together before placing it.
tags: [lesson, naapp, origins, team-auth, human-confirmation, design-review]
timestamp: 2026-11-09
---

A naapp installation has two pinned origins: the app (agent) origin, where
member-signed tools are served, and the human origin, where the browser and
the console run. `split_origins` in
`naapp-lib/src/aweb_naapp/runtime/origins.py` refuses any request to the
human origin that carries `Authorization` or an `X-AWEB-*` / `X-AWID-*`
header, with `403 team_auth_refused`, before any route is reached.

A signed step placed on the human origin is therefore unreachable, however
correct its signature. In the human-confirmation-from-`aw` design a first
draft put the team-auth-signed handoff start on the human origin. It passed
first review, and implementers caught it before any code was written.

# How to apply

- Every step that must carry team-auth (for example, one that presents the
  holder's team certificate as team-auth) runs on the app origin.
- Steps on the human origin (the browser page, the result pickup, session
  requests) authenticate with the console headers, with `aud` set to the
  human origin, or with the browser's own ceremony.
- Before placing any signed request in a design, write its origin, path,
  authentication and `aud` together, as one table row, and check that
  origin's admission rules.
- A host with a single origin for both roles, such as a team server, applies
  the same refusal per path instead of per origin. The rule still holds:
  name the path's admission before placing a signed step on it.

# Status

Verified on aweb main at 9a54c7392: `split_origins` and `_carries_team_auth`
refuse team-auth on the human origin. The handoff table that applies this
rule (start on the app origin; page, result, session requests and owner-act
delivery on the human origin) is in `docs/design/human-confirmation-from-aw.md`
at 8e7ca8565, on a review branch and not on main. The source reports it ACKed
by two reviewers and fit for use by two implementers.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/two-origin-handoff-and-carried-certificate.md.
