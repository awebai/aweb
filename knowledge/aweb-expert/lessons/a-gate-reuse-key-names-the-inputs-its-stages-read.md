---
type: Lesson
title: A gate reuse key names exactly the inputs its stages read
description: The candidate gate's reuse key carries every input a stage reads and only those; a proxy component (synchronized main's SHA standing in for main's product-table ceilings) is replaced by the input's own content identity, reported by the check that reads it, and no component leaves the key until every reader of its source has been listed.
tags: [lesson, testing, candidate-gate, caching, ratchets]
timestamp: 2026-11-24
---

A reuse key can fail in two directions, and each costs something different.

- **A proxy in the key causes runs nobody needs.** The candidate ledger keyed
  stage results on synchronized main's SHA. No stage reads main as a whole,
  so every move of main re-ran an unchanged tree's entire gate.
- **A component removed on an incomplete list of readers skips a real
  refusal.** The task that set out to remove main's SHA assumed its only
  reader was the lint ratchet. A second main-relative ratchet was still live:
  the product-table writes check reads main's ceilings file. Dropping the
  component outright would have reused a pass after main lowered a ceiling
  the tree exceeds.

On 2026-11-24 the coordinator, with the reviewer's agreement, replaced main's
SHA in the key with the sha256 of main's product-table ceilings file, or
"absent" when there is none. The product-table check itself reports that
identity, so the stage that reads the input is also the one that names it.
The ledger's Docker integration test and the user-paths gate test both fail
with the old key and pass with the new one. When this was harvested the
change was under review and not yet on main.

# How to apply

- When asked to make the gate "reuse more" or to "drop X from the key", first
  list every reader of X's source: each stage and check, including ratchets
  that compare against main. Do not take the task's premise about readers on
  trust.
- Key on the content those readers actually read (a file's hash, or an
  explicit "absent"), not on a commit or ref that contains it.
- Have the check that reads an input report that input's identity, so the key
  and the read cannot drift apart.

This complements
[a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md):
that lesson binds a result to the bytes that executed; this one decides which
inputs must match before a result may be reused. It applies to aweb's
candidate gate ledger; the hosted ledger was not examined.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-24;
notes/gate-reuse-keys-on-real-inputs.md (commit 6254485d06 on the source's
review branch). The harvester confirmed on aweb main at 1378733f0 that the
ledger requires the same reviewed main for same-tree reuse and that the
product-table writes check reads origin/main's ceilings file.
