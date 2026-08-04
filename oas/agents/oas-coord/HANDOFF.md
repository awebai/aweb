# oas-coord state — 2026-08-04

Everything here is durable; nothing depends on tmux or model context.

**The OAS team from this epic is GONE.** `oas-seam-dev/rev`, `oas-runtime-dev/rev`,
`oas-journey-dev`, `oas-contract-rev`, `oas-exec-dev/rev`, `oas-admission-rev`,
`oas-retire-rev` — no windows, no presence. `atext.aweb.ai/developer-frontend`
did the v0.20 port through 2026-07-31, but the current occupant of that alias is
a different agent who correctly says the OAS work is not theirs. **Do not send
work to those aliases; verify a recipient is reachable before routing anything.**

**Staff through `aw team add … --start`, not `oas spawn`.** That is the proven
path on this machine and it provisions identity through the Library, sidestepping
the hosted-minting gap in `.66`. Current pair: `e2ee-dev`, `e2ee-rev`.

## Resume

From `oas/agents/oas-coord/instances/alice` (never `cd` elsewhere before `aw`):

```
aw workspace status          # confirm Team=aweb-oas:aweb.ai Name=alice
aw task show aweb-oas-aaaa   # the epic
aw task list --status open | grep aaaa
```

Read `oas/docs/oas-aweb-seam.md` first — it is the design of record, and its
newest section ("Cleanup authority belongs to the spawner, never to the worker")
is today's main decision.

## Repository state

- **aweb**: `main`. Other teams push here too; `git fetch` before assuming.
  **My local main has UNPUSHED commits and origin has commits I lack** — check
  `git rev-list --left-right --count origin/main...main` before branching anyone
  off it. A developer branched off my unpushed main and their branch then carried
  five of my unreviewed commits; see `.63`.
- **upstream OAS clone**: `~/prj/awebai/oas`. Branch `working` is HISTORY, not
  current — it was 8 commits on a pre-v0.20 base and its rebuild is abandoned.
  Current is `aweb/v020-integration`: released v0.20 upstream main plus the three
  seams open upstream as PRs 37, 48 and 69.
- **The local `oas` binary is OURS, not upstream.** `@oas-framework/oas`
  **0.20.0-aweb.1**, built from `aweb/v020-integration`. Released upstream 0.20.0
  does NOT carry the three seams, which is why the version is not a bare 0.20.0.
  Rollback: `npm i -g /private/tmp/oas-rollback-0.18.0/pkg`.
- **The test pin resolves the same commit the binary runs**, through an
  aweb-controlled mirror `github.com/awebai/oas` rather than upstream. Upstream
  branch retention is not ours to promise: the previous pin's ancestor lived on
  an upstream branch that was DELETED, which invalidated the pin and forced a
  full rebuild.
- **Push to the upstream clone is deliberately blocked**:
  `remote.origin.pushurl = BLOCKED-open-a-PR-for-Pepe-instead-see-aweb-oas-aaaa`.
  Leave it blocked. The `mirror` remote is ours and is where our branches go.

## Upstream PRs (three OPEN, awaiting Pepe — who has NOT been told what they are for)

- **PR 37** `fix/delimit-task-prompt-after-variadic-flags` — rebased onto current
  main and **reduced to the pi half only**; Pepe's `5a79622` already delimits
  claude. Fixes a defect *we introduced*: adding `--` made every pi spawn die
  with `Unknown option: --`. pi has no end-of-options marker. Fix = task
  positional ahead of contributed options.
- **PR 48** `upstream/launch-environment-contract` — 6 commits, rebased, one
  conflict resolved (Pepe added error handling around the lock write; our
  disclosure now precedes it) plus a fixture fix for his new `lib/packages.mjs`.

## What works

`.60` shipped the customer path **for a BYOT team**, and that qualifier is
load-bearing: every one of its tests drives a fake `aw` that answers
`import-request`, which is the BYOT flow. Our own deployment team
`aweb-oas:aweb.ai` is HOSTED, and the capability only mints under a local BYOT
controller, so the shipped path has never run against the only kind of team we
have. The claim is true about the object it tested and false about the object we
run. See `.66`.

Also merged: `.57` (adapter signals broken bindings as subprocess failure),
`.56` (OAS_TEST_ROOT coupling fails legibly), `.28` (ordinary worker journey,
bounded, residuals stated), `.30`'s harness (preserved on main even though the
proof is incomplete — it is what found the pi defect).

## Blockers, in priority order

1. **`.63` — IMPLEMENTED AND ACKed, NOT LANDED.** Branch `e2ee-dev`, reviewed
   tip `64833dac`, task commit `2a25f085`. The root cause was NOT the resolver
   I traced: `aw mail show` was refused outright by the `.11` default-deny
   allowlist, which is why it diverged from `inbox`. Blocked only by my own five
   unreviewed commits sitting under it. **Residual: no resident Pi/channel
   journey was rerun — cross-runtime local channel decryption is UNPROVED and
   must not be reported as proved.**
2. **`.47`** — ours to build, unblocked, blocks `.44`. AC already exposes the
   endpoints (`POST /{team_id}/agents/remove-member` and `add-member` in
   `aweb_cloud/routers/teams.py`); what is missing is aweb calling revoke from
   the SPAWNER's context, with OAS receiving no owner credential. Needs its own
   human clearance: it IS cleanup/revocation authority.
3. **`.66`** — spawned agents could not coordinate. Two halves fixed
   (`cdab8f59` wrong-cause diagnosis, `a4659c60` soul scope). One open: a failed
   spawn hook only WARNS. The kernel can now enforce `required` — deliberately
   not switched on, because on this hosted deployment the hook fails every time,
   so requiring it would mean no agents at all. `.47` first, then required.
4. **`.59`** — tmux fd exhaustion. Root cause NOT found. See below.

## Design decision of the day

**Cleanup authority belongs to the spawner, never to the worker.** Membership is
a *team certificate*; removing a member means *revoking* it, which needs the team
controller key. A worker must never hold that — hook and model share a UID. We
spent weeks asking "how does a disposable worker delete itself?"; that question
has no safe answer. Cleanup is the spawner's operation, using authority it
already holds. Hosted differs at exactly one step: the credential used to revoke.

## Operational knowledge that must not be lost

- **`tmux list-sessions` is NOT sufficient verification.** It only reaches the
  server your inherited `TMUX` names. There are **two live servers** here:
  `/tmp/tmux-501/default` (pid varies; the 7-session fleet) and
  `~/.aweb/tmux/cli/tmux-501/default` (the `cli` session, ~11 agent windows).
  Enumerate sockets and probe each with `env -u TMUX tmux -S <socket>
  list-sessions`. I verified a destructive action with `list-sessions` and it
  structurally could not have detected the failure I was checking for.
- The fd exhaustion is real: one server held 238 `/dev/ptmx` handles against 40
  panes and **did not release** on pane death. tmux itself releases correctly —
  verified in eight experiments including at exhaustion, with HUP-ignoring
  children and with the `run-shell -b` self-retire pattern. Closest documented
  match is tmux/tmux#14 plus PR #4256 (closed unmerged). **Do not raise the fd
  limit**; a restart clears it, and the restart is now happening anyway.
- After the restart, take a baseline immediately and sample
  `lsof -p <server> | grep -c ptmx` against pane count over a day. A fresh server
  is the one chance to catch which operation leaks.

## Standing constraints

- Never `cd` before an `aw` command; run from the instance home.
- No backticks in `aw mail`/`chat` bodies — zsh expands them and corrupts the
  message.
- Never `tmux kill-server`; other teams' live agents share this machine.
- Execute the affected feature against **every supported runtime** before
  proposing anything upstream. PR 37 passed 80+ green tests and seven review
  passes because nothing ever ran the command.


## DIRECTION CHANGE — package convergence (accepted 2026-07-27, Juan-confirmed)

We converge on Pepe's OAS package train and one canonical `oas.aweb`
capability. `aweb.identity-attach` stops growing into a competing messaging
surface and becomes a **migration source**, marked experimental, not deleted.
Full deliverable — task graph, Pepe concept-review note, mine/retire list — is a
comment on epic `aweb-oas-aaaa`.

**Base train:** `origin/agents/cli-dev-strict-curriculum-spike` (verified: exists,
54 commits ahead of `origin/main`). Do NOT treat the 8-commit `working` branch as
a second base; replay its two useful changes onto the train instead.

**Three verified findings that bear on sequencing:**

1. **The train does NOT carry the pi task-order fix** (`lib/core.mjs:4046` still
   puts contributed options before the task positional). PR 37 is the only place
   that fix exists. Replay is required or the bug ships on the new train.
2. **The train has NO launch-environment contract** — zero hook-env references in
   core, no `environment` in the manifest schema. PR 48's content must be
   replayed; convergence does not supply `.29`.
3. **The train largely answers `.2`**: `oas.aweb` v1.8.0 declares
   `spawn: { required: true }` and the kernel has `manifestRequiredHooks` /
   `requiredHooks` machinery. **I verified the machinery EXISTS; I did NOT verify
   it prevents a launch.** Execute a failing required hook and observe no model
   process before closing `.2`.

**DONE, and stated precisely because the first version of this sentence
overclaimed.** The seam document is *consolidated*, not prefaced: the customer
config selects canonical `oas.aweb`; the "deliberately distinct from
destructive upstream" rationale is withdrawn on both halves; the metadata key,
tasks-layer and interim-surface sections are reclassified as migration-source
evidence; and the ordered plan is rewritten around train replay, required-spawn
enforcement proof, blocking normal retirement, canonical package regeneration,
`.44`, `.63`, `.45`.

**Board state, exactly:** task **descriptions** were rewritten for `.10`,
`.35`, `.36`, `.60`, `.61` — each now opens with a MIGRATION SOURCE header
saying the behaviour is mined, not discarded. `.2` was **retitled and rescoped**
by comment and title, and stays open. The epic carries a governing convergence
comment. An earlier revision of this file said "descriptions are restructured"
when only comments had been added; that was an overclaim about board state and
is corrected here.

**`.47` is OURS to build, not anyone else's to decide.** Its own description is
authoritative and says so: AC already exposes the revocation path, and what was
missing was us performing revocation from the owner's context rather than
expecting the worker to clean up after itself. One step: owner-initiated retire
on a hosted team revokes the certificate through an authenticated owner/admin
call, executed by the SPAWNER, with OAS receiving no owner credential. It blocks
`.44`.

An earlier version of this line said `atext.aweb.ai/ac-coordinator` owns it. That
routing is withdrawn: it contradicted the task, no such alias was ever confirmed
reachable, and treating it as routed is how this task sat parked once already.
`.47` covers REVOKE. It does not by itself make hosted MINTING work, which is the
separate reason a spawned worker currently cannot join the team (`.66`).

**`.63` is unaffected by convergence** and remains the single blocker on a
demonstrable resident.


## `.64` retirement half — reviewed, proposal drafted, upstream UNPUSHED

**Property:** normal retirement must not delete an instance home whose cleanup did
not finish. It deliberately does **not** ask for required retire hooks — upstream's
rejection at `lib/core.mjs:671` is correct, since `required` means *fatal to a
spawn* and retire runs outside a spawn transaction.

**Where the code is:** branch `upstream/retire-blocks-on-incomplete-cleanup` in a
local worktree, base `6ac3386949b2b97787522e679a4369bca936d1ef`, tip
`7b4fe6471fe875d1ac9c3339f582791061ff91f3`. **On no remote.** Not to be pushed
upstream pending Juan and Pepe.

**The proposal is durable in this repo** at
`oas/docs/proposals/upstream-retire-blocks-on-incomplete-cleanup.md`,
SHA-256 `9959cd1bde989c2ee39881836017c2d5e45b70931005290abd817d948bae643d` — the
exact text reviewed and ACKed. It was drafted in scratchpad, which does not
survive; this copy is byte-identical and is the one to send.

**Review:** two rounds by an independent agent. Round one on `5c8b724` returned
*amendments required* and caught a real defect — the blocking path reached
self-retire, which I had claimed it did not. They established it with a
fixed-vs-control regression, not by reading the diff; my own mirror case could
never have caught it, because I wrote it around the ordinary path only. Round two
on `7b4fe64`: **ACK, no blocking issues, no non-blocking suggestions.**

**Evidence attribution matters here:** the full fixed-vs-control suite comparison
(437/436/0 vs 436/434/1) was run at **`5c8b724`** and was *not* repeated at the
tip. `7b4fe64` carries the reviewer's two regressions (2/2) and a scoped suite of
460/459/0/1. The control-only failure is a pre-existing upstream load-sensitive
flake — 5/5 passes in isolation — and is not attributed to this change.
