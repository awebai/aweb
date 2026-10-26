---
type: Decision
title: Codex live delivery is the OATS wake
description: Nothing aweb ships recommends `aw run codex`; Codex gets live mail and chat delivery through the OATS host wake broker, and standalone Codex reads when asked. A command proven to work is not thereby the supported journey.
tags: [decision, codex, runtime, wake, docs]
timestamp: 2026-10-16
---

Ruled by the operator on 2026-10-16 (UTC), correcting guidance the coordinator
had derived from `aw run`'s help text after a live journey showed a Codex runner
answering mail within seconds: "we do not use nor recommend aw run codex we use
the oats wake instead".

# Decision

- No dashboard, `aw init` output, team-join flow or doc recommends
  `aw run codex`.
- Codex under OATS gets live delivery from the host wake broker: install the
  wake once per host, then spawn Codex seats through OATS. Codex without OATS
  has no live delivery and reads mail and chat when asked.
- The compatible runtime code stays; only the recommendation changes.

# Lesson

Tests establish that a command works; the product owner decides what users are
directed through. When writing CLI output or docs, separate capability evidence
from recommendation authority, and keep compatibility while aligning
recommendations with the decision.

`docs/add-ai-tool.md` shows the outcome; this records the ruling and why the
working runner is not recommended.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-awid-service-bypass`
(note `working-command-is-not-supported-journey.md`; coordinator 407a0932 and
caa373ac).
