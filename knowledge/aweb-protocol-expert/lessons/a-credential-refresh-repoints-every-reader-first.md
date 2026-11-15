---
type: Lesson
title: A credential refresh repoints every reader before it makes a request
description: A refusal-triggered credential refresh can be re-entered by its own install when an install side effect authenticates through a record that still names the stale credential; aw's team-certificate refresh deadlocked this way on its own install lock. Point every record clients read the credential from at the new one before the install makes any authenticated request, make the refresh non-reentrant as a backstop, and test it end to end with the real binary.
tags: [lesson, aw, certificates, credentials, refresh, testing]
timestamp: 2026-11-15
---

Learned while building aw's automatic team-certificate refresh for team key
changes ([a team key change carries the members' new certificates](/aweb-protocol-expert/decisions/a-team-key-change-carries-the-members-new-certificates.md)).

- The refresh installs the new certificate through `install-cert`, and that
  install also publishes the identity's encryption key.
- The publish built its client from the workspace record, which still named the
  old certificate. The server refused it with `team_key_not_current`, which
  started a second refresh inside the first.
- The second refresh waited forever on the install lock the first one held.

Publishing an encryption key looks unrelated to certificates, so the shared
install path hid the loop. Only an end-to-end run of the real aw binary against
a real server and registry found it: a hand-built refusal would not have been
re-entered.

# How to apply

- Any "on refusal, refresh the credential and retry" hook: before the refresh's
  install makes an authenticated request, update every record clients read the
  credential from (for aw's team certificate, the workspace binding as well as
  the team list).
- Make the refresh non-reentrant within the process, as a backstop, not as the
  fix.
- Test a refresh end to end with the real binary.

The fix is in code on the review branch (recording the certificate in the
binding first, and a reentrance guard), with an end-to-end test; this lesson
covers refresh paths that code does not reach.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-15; notes/install-side-effects-must-not-use-the-replaced-credential.md. Fix on branch `agents/aweb-protocol-expert-team-key-trust-adcl3` at 225c31d29, not on main at harvest time.
