---
name: log-awid-registry-unavailable
description: Log every AWID-registry-unavailable / alias-lookup failure to docs/awid-registry-unavailable-log.md — but never stop driving; retry and continue.
metadata:
  type: feedback
---

Whenever an `aw` coordination call (mail / chat / directory) fails with an **AWID
registry unavailable** 503 or an `agent not found` alias-lookup failure, **append
an entry to `docs/awid-registry-unavailable-log.md`**: UTC (`date -u`), **the cwd
you ran `aw` from** (it derives identity/context from `.aw/` in the working dir),
the exact command/context, the exact error, the retry outcome, and registry
health if checked (`api.awid.ai/health`, `aw doctor registry`).

**Why:** Juan asked for this (2026-06-17) — the registry has been intermittently
failing (503s, alias lookups) and he wants hard data for operations / coord-awid
to act on. The failures are intermittent (health returns 200, retries succeed),
so they degrade coordination but are not a sustained outage.

**How to apply:** log it, **retry, and keep driving** — do not stop the work for
it, and do not over-escalate a transient blip as an outage (verify with
`api.awid.ai/health` first). Surface the *pattern* to the human/operations with a
recommendation if it persists, but the per-occurrence response is: record + retry
+ continue. See [[lead-drive-to-completion]].
