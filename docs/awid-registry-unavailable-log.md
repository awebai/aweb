# AWID registry-unavailable log

Running record of every observed **AWID registry unavailable** event — 503s and
alias-lookup failures (`agent not found`) on the `aw` coordination path (mail /
chat / directory), which route through the aweb server's AWID dependency. Kept at
Juan's request (2026-06-17) as hard data for operations / coord-awid on the
registry's intermittent-reliability problem.

Pattern so far: **intermittent, not a sustained outage** — `api.awid.ai/health`
returns 200 (db+redis ok) during the failures, and **retries succeed**. It
degrades coordination but does not block the work; we log and retry, we do not
stop.

Per-entry format: `UTC | cwd (dir aw ran from) | command/context | exact error | retry outcome | registry health if checked`.
Append a new entry on **every** occurrence (use `date -u`). The cwd matters: `aw`
derives identity/context from `.aw/` in the working directory.

**CRITICAL distinction (verified 2026-06-17):** an `agent not found` alias
failure is usually **NOT a registry outage** — it's `aw` being run from the
**wrong directory**. From the repo root `/Users/juanre/prj/awebai/aweb`, `aw`
resolves identity **`grace` (aweb:juan.aweb.ai)**; only from this coordinator's
instance home does it resolve **`aweb-coordinator` (default:atext.aweb.ai)**.
Running `aw` from the repo root (e.g. by batching `git` + `aw` in one shell) sends
**as the wrong identity**, which cannot resolve this team's aliases → `agent not
found`. That is operator error / an identity-safety violation, **not** the
registry being down. Genuine registry-unavailable = a `503 AWID registry
unavailable` (or health failing) **while running from the correct instance
home**. Always log the cwd so the two are distinguishable.

## Entries — genuine AWID registry-unavailable (503 from correct home base)

- ~2026-06-17 | cwd `~/prj/awebai/aweb/agents/instances/aweb-coordinator` (correct) | `aw chat send-and-wait coordinator` (folio status pull, bg task be6n78smj) | `aweb: http 503: {"detail":"AWID registry unavailable"}` — message did not send | re-sent later, succeeded | `api.awid.ai/health` 200, `app.aweb.ai/health` 200, `aw workspace status` OK — confirmed intermittent, not sustained
- 2026-06-17T~10:45Z | cwd `~/prj/awebai/aweb/agents/instances/aweb-coordinator` (correct; `aw whoami` → `aweb-coordinator` confirmed in the same batch) | `aw task comment add default-aaaj.2` (recording the emit-wire lock) | `aweb: http 503: {"detail":"AWID registry unavailable"}` — failed twice (the immediate in-shell retry also 503'd) | re-ran ~10:46:50Z, succeeded (`✓ Added comment`) | health not checked at the moment. **Strong intermittence signal:** in the *same* batch (same identity, same cwd, same second) the preceding `aw chat send-and-leave aw-coordinator` SUCCEEDED while this `aw task comment` 503'd — so the blip is per-request/transient, not a sustained outage and not a wrong-cwd identity issue.

## Entries — NOT the registry: wrong-cwd / wrong-identity (operator error, reclassified)

These three were initially mis-logged as registry events. Root cause (per Juan +
verified): `aw` ran from the **repo root as `grace`** because I batched `git`
(repo root) + `aw` in one shell. Fix: run `aw` only from the instance home.

- ~2026-06-17 | cwd `/Users/juanre/prj/awebai/aweb` (REPO ROOT = grace, wrong) | `aw mail send --to aw-coordinator` and `--to coordinator` (batched after `git`) | `agent not found` | retried from instance home, sent | not the registry
- ~2026-06-17 | cwd `/Users/juanre/prj/awebai/aweb` (REPO ROOT = grace, wrong) | `aw mail send --to ac-coordinator` (m8 sign-off, batched after `git`) | `agent not found: ac-coordinator` | retried from instance home, sent | not the registry
- ~2026-06-17 | cwd `/Users/juanre/prj/awebai/aweb` (REPO ROOT = grace, wrong) | `aw mail send --to ac-coordinator` (applied-table confirm, batched after `git`) | `agent not found: ac-coordinator` | retried from instance home, sent | not the registry

Evidence (2026-06-17): `aw whoami` from the instance home → `aweb-coordinator` /
`default:atext.aweb.ai` (DID `z6MkvE1j…`); from the repo root → `grace` /
`aweb:juan.aweb.ai` (DID `z6MkncRg…`). Different identity → wrong-team alias
resolution → `agent not found`.

Log started: 2026-06-17T08:46:30Z. New occurrences appended below with precise UTC + cwd.
