---
name: run-aw-only-from-instance-home
description: Run `aw` ONLY from this instance's home dir; never batch git (repo root) + aw in one shell — the repo root is a different identity (grace), so aw there sends as the wrong agent and "agent not found" looks like a registry outage but isn't.
metadata:
  type: feedback
---

**Always run `aw` from this coordinator's instance home**
(`agents/instances/<name>/`), never from the repo root or any other workspace.
`aw` derives identity from `.aw/` in the cwd. Verified 2026-06-17:

- instance home → `aweb-coordinator` / `default:atext.aweb.ai` (correct).
- repo root `/Users/juanre/prj/awebai/aweb` → **`grace` / `aweb:juan.aweb.ai`**
  (a *different* identity/team).

**The trap I fell into:** batching `git` (which needs the repo root) and `aw`
(which needs the instance home) in **one shell**. After `cd <repo-root>` for git,
the `aw` call ran from the repo root **as grace**, which can't resolve this team's
aliases → repeated `agent not found`. I mis-logged those as "AWID registry
unavailable"; they were operator error and an identity-safety violation (the
AGENTS.md #1 rule: never run `aw` from another workspace — it sends as the wrong
agent / claims work under the wrong identity).

**How to apply:**
- Put `git` (repo root) and `aw` (instance home) in **separate** Bash calls, or
  always `cd` back to the instance home before any `aw`.
- The Bash tool resets cwd to the instance home between calls — rely on that for
  `aw`; only `cd` to the repo root inside a git-only call.
- Before trusting an `agent not found` / failure as a registry issue, check the
  cwd and `aw whoami` first. Genuine registry-unavailable is a `503` from the
  *correct* home base; an `agent not found` from the wrong cwd is neither.
