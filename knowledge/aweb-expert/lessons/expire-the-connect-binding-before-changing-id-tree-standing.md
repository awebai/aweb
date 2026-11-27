---
type: Lesson
title: Expire the connect's binding observation before changing ID-tree standing
description: A server test that admits a member through /v1/connect and then enrolls, revokes or root-replaces its did:aw sees connect's cached binding, "not enrolled" included, for 60 s on every lane; clear the binding cache after the connect to stand for the TTL elapsing, and keep a claimed-path control that must track the change.
tags: [lesson, testing, identity, revocation, cache]
timestamp: 2026-11-27
---

Two rules combine in a way neither states.

- **Tests use the product path.** The gate's product-table-writes check
  refuses unmarked writes to product tables, so server tests build member
  state through product routes such as `/v1/connect`.
- **Connect warms the binding cache.** Connect observes the did:aw binding and
  caches the observation for the binding TTL (60 s), including an ID-tree
  status of "not enrolled". Inside that window an enrollment, revocation or
  root replacement of the same ID is invisible to every lane, the claimed
  lane included. That is the accepted freshness bound, not a defect.

Followed naively, the first rule makes ID-tree and revocation tests test
nothing, or fail in ways that look like the bug under test. In task
aweb-advl.2, the connect-based setup without expiry failed 6 of 9 cases,
including the claimed-did:aw controls. With the cache cleared after the
connect, all 9 passed, and against the unfixed source exactly the 4 omission
cases were red. The protocol reviewer and the finder both accepted that setup,
and it landed through a green full gate.

# How to apply

- To test behaviour that depends on a standing change after admission, clear
  `identity_binding_cache(env.app.state)` after the connect. The clear stands
  for the TTL elapsing. The repository precedent is
  `server/tests/test_certificate_preferred_identity_http.py`
  ("Expire positive proof from connect").
- Do not go back to an unmarked write to skip connect. The gate refuses it,
  and it would bypass the product path the test must exercise.
- Keep a claimed-path control in the same test. The claimed lane checks ID-tree
  standing directly, so it must follow the change. If the control does not
  follow it (for example it passes when it should refuse), the cache is
  masking the change and the test proves nothing.
- The clear stands for elapsed time, not for immediate effect. When the
  freshness window itself is the property under test (does revocation end
  authority, and when), do not clear the cache. Test the window as a timing
  case instead, as in
  [elapsed time is a test input](/aweb-expert/lessons/elapsed-time-is-a-test-input.md).
- Elimination route: a shared server-test helper that admits through connect
  and then expires the binding observation would make this setup the default.
  Until such a helper exists, this lesson is the guard.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-sec-r1, 2026-11-27;
notes/connect-warms-binding-cache.md. Task aweb-advl.2; setup commits
8f338d3aff (no expiry) and ad17a99bef (expiry), landed on aweb main as
39b3f091. Reviewer and finder acceptance is source-reported.
