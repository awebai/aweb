---
title: "aw hooks: named extension points"
kicker: "Pointer"
description: "The aw hooks contract and the naapp SOTs now live in the private awebai/naapp-specs repo."
weight: 27
---

# aw hooks — moved to naapp-specs

The aw hooks contract (the named-hook mechanism aw-core implements) and the
self-contained naapp SOTs now live in their shared home:

> **`awebai/naapp-specs`** (private) — `aw-hooks-sot.md`, `secrets-aw-do-sot.md`,
> `audit-logs-app-sot.md`, `linear-naapp-sot.md`.

**aw-core implementers:** build the hook mechanism per `aw-hooks-sot.md` in that
repo. This pointer stays in `aweb/docs` because the hook is an aw-core contract you
build from; the naapp product specs do not.
