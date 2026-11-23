---
type: Lesson
title: An expected refusal is a hypothesis until it runs
description: An exact refusal code written into a test from reading one layer's code is a hypothesis; run every exact-code assertion before sending a head, because an earlier layer may refuse first, as naapp-lib admission refuses an uninstalled app's member routes with 403 scope_denied before the app's own installation fence.
tags: [lesson, testing, review, naapp, refusals]
timestamp: 2026-11-20
---

On 2026-11-20 a Folio end-to-end test expected a member route of an
uninstalled naapp to be refused by the app's installation fence with
`installation_inactive`. The expectation was written from reading the app's
code, and it reached an ACKed head without being run. It was wrong.

# The layering that was missed

After an uninstall, naapp-lib's `team_grants.grant_for` returns no grant
because the installation is not active, and `authorize_request` turns that into
403 `scope_denied` ("The team has not granted this app any scopes"). Admission
runs before any app fence, so a member route never reports
`installation_inactive` after an uninstall. Capability paths (present links,
edit sessions) read the installation status themselves and do see
`installation_inactive`; Folio maps it to 404. Observed in
`naapp-lib/src/aweb_naapp/runtime/` at main d8d0bfa1e; the test was fixed in
f6686d45d0 and passed 28/28.

# How to apply

- An exact status or code in a test is a claim about every layer the request
  crosses, not only the layer you read. Treat it as a hypothesis, as the
  [evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md)
  treats any source reading, until it has run.
- Run every exact-code assertion before sending a head for review. An ACK on an
  unrun assertion verifies nothing about it.
- For naapp refusal tests, start from the library's admission order: member
  routes meet naapp-lib's grant check first; only capability paths reach the
  app's installation fence.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links, 2026-11-20; notes/2026-11-20-member-uninstall-refusal.md.
