---
type: Decision
title: Key authority history spans every path to the key
description: Revocation and key-identity history are keyed by key identity and consulted by every insert and lookup that can reach the key, across table versions, tenants, origins, uninstall and reinstall; revocation is one-way and rotation uses a new key id.
tags: [decision, app-registry, revocation, keys, security]
timestamp: 2026-10-21
---

Ruled by the security reviewer on 2026-10-21 after a cross-tenant gap in app
emit keys. Rated P1 rather than P0 because it "breaks a stated invariant... a
revoked credential acting again", and the server release was held until the
fix landed. Scope ruling the same evening: history spans origins, "including
uninstall and reinstall at a new origin".

The gap: registry rows keyed by app, origin and manifest digest were written
from member-supplied install fields, upserted with revocation cleared, and
looked up without a team filter. A fallback lookup also reached keys through a
second, older table that the revocation check did not consult. The independent
review had ACKed "revocation carried across digests" and missed the two-table
path. The fix shipped in server 1.27.31.

# Decision

- One history per key identity (team, app, key id, did). Every insert and
  every lookup consults it, whichever table or representation it goes through.
- Revocation is one-way: the earliest revocation wins and re-registration never
  clears it.
- A key id's mapping to its did is immutable across origins, uninstall and
  reinstall; rotation uses a new key id.

# Why

If history resets when an app moves origin, a revoked key returns simply by
re-hosting the app. The cost of the rule is small: a new operator or a re-host
uses new key ids, which was already the documented rotation rule.

# Lesson for review

An invariant checked inside one table, tenant row or origin does not protect a
lookup that reaches the same key another way. Registry rows keyed by content
but written from caller-supplied fields are shared mutable state across
tenants: check whose authority writes them, and enumerate every path a lookup
can take, fallbacks included.

`docs/app-registry.md` states the current rule; this records why it spans
origins and the review miss that made it explicit.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-app-team-api` (note
`emit-key-cross-team-gap.md`; security reviewer a6cf3036 and b7c5a879).
