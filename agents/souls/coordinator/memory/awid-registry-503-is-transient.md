---
name: awid-registry-503-is-transient
description: An AWID registry 503 or alias-lookup failure is usually a transient blip — retry and keep driving; escalate the pattern, never the occurrence.
metadata:
  type: feedback
---

When an `aw` coordination call (mail / chat / directory) fails with an **AWID
registry unavailable** 503, treat it as transient until proven otherwise.

**Why:** the registry has failed intermittently since at least 2026-06 — health
returns 200, retries succeed. These failures degrade coordination without being
a sustained outage, so both available mistakes are real: stopping work over a
blip, and reporting a blip as an outage.

**How to apply:** retry, and **keep driving** — do not stop the work for it, and
do not over-escalate a transient blip as an outage; verify against
`api.awid.ai/health` (or `aw doctor registry`) before calling it one. The
per-occurrence response is **retry and continue**. Surface the *pattern* to the
human or to operations, with a recommendation, only if it persists.

Distinguish it from operator error before escalating at all: a genuine `503`
from the correct instance home is a registry problem, while `agent not found` is
usually the wrong working directory, since `aw` derives identity from `.aw/` in
the cwd. That discriminator lives in [[run-aw-only-from-instance-home]].

**Provenance:** this restores the still-true half of a memory deleted by
`aweb-aazb.7.4` on 2026-08-16. That entry also carried a mandate to append every
occurrence to `docs/awid-registry-unavailable-log.md`; that document was deleted
in the same programme, so the mandate is genuinely false now and is not restored.
The response policy above was lost with it and is not recorded anywhere else —
`aazb-dev` self-reported the loss, and a claim that it survived in
[[lead-drive-to-completion]] was checked and does not hold: that entry is about
not deferring coordination to the human and says nothing about registry failures.
