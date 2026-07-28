# oas-coord recovery state — 2026-07-27

Written before a machine restart. Everything here is durable; nothing depends on
tmux or model context.

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

- **aweb**: `main`, pushed. Other teams push here too; `git fetch` before
  assuming. My last verified-green run was the OAS suite 83/83.
- **upstream OAS clone**: `~/prj/awebai/oas`, branch `working` — current
  upstream `main` (Pepe's 192 commits) **plus** our 8 commits: the pi launch fix
  and the 6-commit environment contract. `OAS_TEST_ROOT` resolves here by
  construction (`Makefile:24`), so our suite tests against this tree.
- **Push to that clone is deliberately blocked**:
  `remote.origin.pushurl = BLOCKED-open-a-PR-for-Pepe-instead-see-aweb-oas-aaaa`.
  Leave it blocked. Push feature branches by explicit URL only.

## Upstream PRs (both OPEN, awaiting Pepe)

- **PR 37** `fix/delimit-task-prompt-after-variadic-flags` — rebased onto current
  main and **reduced to the pi half only**; Pepe's `5a79622` already delimits
  claude. Fixes a defect *we introduced*: adding `--` made every pi spawn die
  with `Unknown option: --`. pi has no end-of-options marker. Fix = task
  positional ahead of contributed options.
- **PR 48** `upstream/launch-environment-contract` — 6 commits, rebased, one
  conflict resolved (Pepe added error handling around the lock write; our
  disclosure now precedes it) plus a fixture fix for his new `lib/packages.mjs`.

## What works

`.60` shipped the customer path: a config naming a team and selecting the aweb
capability gives READY or exactly one action; ordinary `oas spawn` provisions a
disposable worker; `status` shows member name and DID; `retire` cleans up with
the durable controller byte-unchanged. **No identity vocabulary anywhere.**

Also merged: `.57` (adapter signals broken bindings as subprocess failure),
`.56` (OAS_TEST_ROOT coupling fails legibly), `.28` (ordinary worker journey,
bounded, residuals stated), `.30`'s harness (preserved on main even though the
proof is incomplete — it is what found the pi defect).

## Blockers, in priority order

1. **`.63`** — an attached principal can send but **cannot read** its own mail.
   `configureClientE2EE` returns **silently** when key material is not found on a
   read path, so this presents as `encrypted=true, decrypted=false` with no
   error. Fix in two parts: (a) make missing key material observable — say it
   could not decrypt and which path was consulted; (b) ensure every mail path
   carries the resolved external identity home into the selection. Test with an
   attached principal whose home **differs** from the ambient one.
   **This is the only thing between us and a demonstrable resident.**
2. **`.47`** — design resolved, one step to build: hosted retire must revoke the
   team certificate under the **owner's** authority. Local path already does this
   correctly. Self-retire cannot revoke on either path; it leaves a recorded
   incomplete operation for the cleanup owner.
3. **`.59`** — tmux fd exhaustion; new agents cannot be started. Root cause NOT
   found. See below.

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

**Deliberately not done tonight:** rewriting the normative seam document into the
convergence shape. Rushing the design of record into a third direction hours
before a restart is worse than doing it carefully first thing after. That is task
one on resume.

**`.47` now has a real recipient:** `atext.aweb.ai/ac-coordinator` owns the hosted
cleanup contract. It stops being a parked task on our board.

**`.63` is unaffected by convergence** and remains the single blocker on a
demonstrable resident.
