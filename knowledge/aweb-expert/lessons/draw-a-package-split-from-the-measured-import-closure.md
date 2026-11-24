---
type: Lesson
title: Draw a package split from the measured import closure
description: Before deciding which modules of a shared library become a published contract, measure the transitive import closure of each consumer's production entry points, parent-package __init__ files included, confirm it with sys.modules after a cold import, and cut single-helper edges by moving the helper; extras comments and doc claims about consumers are hypotheses to grep.
tags: [lesson, architecture, packaging, boundaries, investigation]
timestamp: 2026-11-24
---

A split, an extraction, or a "publish the shared part" decision is usually
drawn from the stated intent: the module list, the packaging extras and their
comments, and what the docs say consumes what. In November 2026 the planning
work for moving the native agentic apps out of aweb measured the server's real
import closure into the naapp library instead. Three things the stated intent
did not show turned up (aweb at d8ee9ed31):

- **Extras comments named consumers that do not exist.** The library's
  pyproject says its outbox and signing-key extras exist so the core server
  can use them. No server production code imports either module.
- **One helper edge pulled in a whole runtime.** The server imports
  `runtime.task_requests` for request validation. That module imports a
  single signer helper from the app credentials module, and that one edge
  brought about 2.5k lines of app runtime into the server's closure, by the
  source's count: settings, team auth with its web and database dependencies,
  the outbox and the signing key.
- **The root `__init__` runs on every submodule import.** `aweb_naapp/__init__.py`
  imports the docs surface (chrome, CSS, llms, reference), so every
  `import aweb_naapp.X` in the server loaded it too. A per-file count of
  importers cannot see this, and the source's own first pass missed it. It
  also meant the contract could not keep the `aweb_naapp` import name: it
  needs a package whose root imports nothing it does not own.

The measured contract came to about 13% of the library. That figure, not the
extras list, decided between a separate package and a single package.

# How to apply

- Walk the closure statically from each consumer's production entry points:
  follow every `from X import` and add each parent package's `__init__`.
- Confirm the static result against `sys.modules` after a cold
  `import <consumer>` in a fresh subprocess. Here an independent cold-import
  listing matched the static closure exactly.
- Treat every "shared with" or "used by" comment, and every claim in the docs
  that a component consumes something, as a hypothesis. Grep for the import
  before it moves a module across the line.
- When one helper drags in a large subtree, move the helper to the contract
  side. Do not widen the contract to take the subtree, or the coupling comes
  back after the move.
- Check the root `__init__` of any package that is to keep its import name.
  If it imports beyond the contract, the contract needs its own name.

Once the boundary is drawn, the route that removes this lesson is a test: a
cold-import guard that fails when a consumer's `sys.modules` gains a module
outside the contract.

This lesson draws a boundary before any change.
[Review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md)
covers the callers of a change once it is made.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-apps-boundary, 2026-11-24;
notes/package-split-from-measured-closure.md. The harvester confirmed the
pyproject comments, the absent server imports, the single helper import in
`runtime.task_requests` and the root `__init__` imports at aweb d8ee9ed31. The
line counts and the 13% share are the source's measurements.
