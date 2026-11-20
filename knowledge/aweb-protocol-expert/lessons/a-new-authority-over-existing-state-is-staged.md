---
type: Lesson
title: A new authority over existing state is staged
description: Before a new rule makes existing rows authoritative, ask which rows already violate it and stage enforcement when that set cannot be measured from OSS; on the server auth path, read any new app.state attribute with a safe default, because an embedding host runs aweb's certificate check with an app state create_app did not build; and change every copy of the check, since the library naapp carries its own team auth.
tags: [lesson, security, rollout, embedding, teams]
timestamp: 2026-11-12
---

Learned while making team keys pinned
([team keys are pinned](/aweb-protocol-expert/decisions/team-keys-are-pinned.md)).
None of the three failures below shows in the repository's own tests.

- **Existing rows can already violate the new rule.** Pinning made the local
  team key authoritative. Any team whose stored key already differed from the
  registry (rotated before rotation acts were kept) would fail closed on
  deploy, and how many such teams exist in hosted deployments cannot be
  measured from OSS.
- **An embedding host runs the auth path with its own app state.** A hosting
  deployment wraps aweb's certificate check, so `app.state` there is not what
  `create_app` built. A new `app.state` attribute read on the auth path made
  every certificate check fail with 500 in that host until it was read with a
  default.
- **Team auth has more than one copy.** The library naapp carries its own copy
  (`library/auth.py`), separate from naapp-lib's runtime team auth, so a fix in
  naapp-lib does not reach it. Moving library onto naapp-lib is not small (about
  80 tests are built on the copy's internals), so the pin change wired the copy
  to the shared SDK pin logic instead. Retiring the copy is the real fix and a
  separate task.

# How to apply

- For any new authority over pre-existing state, answer "which existing rows
  already violate it?" before enforcing. When the answer cannot be measured
  from OSS, ship enforcement behind a default-off flag with one greppable log
  line for each violation, and turn it on after the violations are counted and
  repaired.
- On the server auth path, read every new `app.state` attribute with a safe
  default, and test under an embedding host as well as `create_app`.
- When changing naapp-lib team auth, change `naapp/library` too, until the copy
  is retired.

Related: [a mounted app gets no lifespan](/aweb-protocol-expert/lessons/a-mounted-app-gets-no-lifespan.md),
the same embedding-host blind spot for process services.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-12; notes/team-key-pin-rollout-and-embedding.md, notes/library-has-its-own-team-auth-copy.md.
