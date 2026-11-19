---
type: Decision
title: Codex live delivery is the OATS wake
description: Nothing aweb ships recommends `aw run codex`; Codex gets live mail and chat delivery through the OATS host wake broker, and standalone Codex reads when asked. A command proven to work is not thereby the supported journey. `aw run` is headed for obsolescence, so it gets no further investment beyond keeping existing release evidence working; its released command and compatibility code stay.
tags: [decision, codex, runtime, wake, docs, aw-run]
timestamp: 2026-11-19
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

# No further investment in `aw run`

The operator extended this ruling on 2026-11-19 (UTC): `aw run` is to be
obsoleted, for every runtime and not only Codex, because the OATS kernel and
wake broker own the agent seat lifecycle and the launcher does not.

- Do not spend work on the launcher: no quality or UX work, no new runner
  tests, no refusal-text improvements, and no new support such as
  grant-backed seats.
- Existing runner fixtures that release evidence depends on may be repaired so
  that evidence stays valid, using a path the launcher already supports,
  without adding tests, support or refusal text.
- Defects in `aw run` that cross a team or authentication boundary are still
  reported.
- This does not authorize removing the released command or its compatibility
  code; that needs its own ruling under
  [released clients are a permanent constraint](released-clients-are-a-permanent-constraint.md).

An earlier request to improve the launcher's refusal wording was withdrawn by
this direction. Why it matters: a security or release repair in `aw run` is
an easy entry to further ownership of a launcher the product is leaving; keep
such a repair to the minimum that restores the existing evidence.

Acceptance: source-reported. The operator's direction was relayed to the
source seat by coordinator mail f43e3e8c (2026-11-19 UTC); the harvester could
not read that record.

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

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-untrusted-input, 2026-11-19; notes/aw-run-obsolescence-direction.md.
