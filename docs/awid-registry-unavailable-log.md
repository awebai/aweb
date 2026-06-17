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

**All entries below ran `aw` from `~/prj/awebai/aweb/agents/instances/aweb-coordinator`**
(this coordinator's instance home) unless a later entry notes otherwise.

## Entries

Backfill — earlier in the 2026-06-17 session, times approximate (precise stamping
begins below this block):

- ~2026-06-17 (early) | `aw mail send --to aw-coordinator` and `--to coordinator` (folio prod directive + reply) | `agent not found: aw-coordinator` / `agent not found: coordinator` (alias lookup failed) | retried after diagnosis, both sent | `aw doctor registry` clean; `api.awid.ai/health` 200 shortly after
- ~2026-06-17 | `aw chat send-and-wait coordinator` (folio status pull, bg task be6n78smj) | `aweb: http 503: {"detail":"AWID registry unavailable"}` — message did not send | re-sent later as mail, succeeded | `api.awid.ai/health` 200, `app.aweb.ai/health` 200, `aw workspace status` OK — confirmed up
- ~2026-06-17 | `aw mail send --to ac-coordinator` (m8 sign-off) | `agent not found: ac-coordinator` | retry succeeded | (not separately checked; up per prior check)
- ~2026-06-17 | `aw mail send --to ac-coordinator` (applied-table confirm) | `agent not found: ac-coordinator` | retry succeeded | (not separately checked)

Log started: 2026-06-17T08:46:30Z. New occurrences appended below with precise UTC.
