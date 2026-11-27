---
type: Lesson
title: Reducing a naapp installation's scopes bites within the grant answer age
description: A running naapp process judges each request's scopes against the grant answer it last read, which it may reuse for up to aweb's app grant max age (1 to 60 s, default 60), and the installation fence row holds no scopes; a rollback that revokes write must wait that long, or start a fresh process, before relying on writes being refused.
tags: [lesson, naapp, grants, scopes, revocation, rollback, cache]
timestamp: 2026-11-27
---

# The discovery

A naapp request is admitted when the tool's scopes are a subset of the grant's
scopes (`tool.scopes <= grant.scopes` in naapp-lib's runtime authorization).
The grant is the answer the process last read from aweb, and the process may
reuse that answer for up to aweb's app grant max age:
`AWEB_APP_GRANT_MAX_AGE_SECONDS`, which aweb refuses outside 1 to 60 and
defaults to 60.

The installation fence row holds no scopes, so nothing local to the app
narrows a cached grant. After an installation is re-granted read-only, a
running process can keep admitting writes from its cached grant for up to a
minute. A fresh process reads the new grant and refuses with `scope_denied`.

# How to apply

- A rollback that revokes write authority waits at least the grant max age,
  or restarts the app process, before treating writes as refused or checking
  that none was committed.
- A fence-expiry step does not shorten the window: the fence carries no
  scopes.
- A test of revocation either runs in a fresh process or waits out the age;
  acting immediately after the re-grant in the same process will see writes
  admitted.

The bound holds while aweb's ceiling for the grant max age is 60 s. The aweb
server's own cache of team-certificate revocation is a separate window with
its own TTLs.

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-move, 2026-11-27;
notes/scope-revocation-bites-within-the-grant-answer-age.md.
Checked by the harvester: `get_app_grant_max_age_seconds` in
`server/src/aweb/config.py` on aweb main 90519b0d2 (default and ceiling 60,
values outside 1 to 60 refused); naapp commit 2cab30f8 adds the test that a
rolled-back installation refuses every write once its service resumes. The
naapp-lib authorization line, the fence-row migrations and the scratch run in
which the same process admitted the write are source-reported. The naapp team
accepted this window as the basis for the rollback order (source-reported).
