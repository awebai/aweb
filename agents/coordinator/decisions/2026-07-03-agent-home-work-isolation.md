# Agent instantiation: home/work isolation (2026-07-03)

Decided with Juan after studying `~/prj/awebai/a2am` (its agents-architecture,
aweb-setup-feedback, and spawn-instance skill). Fixes the aaeq.19 bug where a
library-materialized developer agent (aw-docs) did git work in its home — a
subdir of the main repo — and hijacked the main checkout's branch.

## The split (from a2am, refined by Juan)

Per instance, home = `agents/instances/<name>/`, created in the **spawn cwd
which we do not control** (tends to be the project repo/main, or another dir).
So the home is never assumed git-safe.

- **home/** — identity (`.aw`) + body (AGENTS.md/CLAUDE.md → profile).
  Gitignored. `aw` runs here (resolves identity from `home/.aw`). **Never** run
  git in the home.
- **home/worktree/** — a git worktree of the project repo on branch `<name>`.
  **Every** agent gets it; the default, safe place for `git`/build. Accidental
  commits land on the agent's branch, never main.
- **home/work-main/** — symlink to the main checkout. **Only** for
  `tracks_main` agents (coordinator, maintainer, reviewer). Deliberate, named
  main access.

Rule: **`aw` from the home, `git`/build from `worktree/`, main ops deliberately
from `work-main/`.**

## Two refinements Juan added over the a2am model

1. **Name the work dir by mode** — `worktree/` vs `work-main/`, not a uniform
   `work/`. The word *main* in the path signals caution; the cwd/prompt tells
   the agent which mode it's in. Cheap, prevents the accident class.
2. **Every agent gets a `worktree/`** (a2am gave code agents a worktree but
   coordination agents *only* a main symlink, so their default cwd was main).
   Main-touchers *also* get `work-main/`. Default cwd is always the safe
   worktree; main is reached only via the explicitly-named handle.

## Soul-growth: option (a)

Coordination agents commit soul-growth (docs/decisions/memory, which live in
main) **directly to main via `work-main/`** — because the home is in main
anyway and the coordinator is the merge authority. Accidents still land in
`worktree/`. (If a standalone maintainer is ever split out, tighten to routing
soul-growth through a branch.)

## Implementation

- Blueprint profile schema gains **`tracks_main: true|false`** (coordinator
  owns this). Code profiles → false; coordination → true. A worktree is implied
  for all.
- `aw team add` sets up `home/worktree/` (always) + `home/work-main/` (if
  tracks_main) when the home is in a git repo; skips if not. Do it in `add`
  itself so the two-step add-then-up flow is isolated, not just `--start`.
- `aw team add --start` adds the launch from the home.
- Retirement (aaeq.15): `git worktree remove`, unlink work-main, `aw workspace
  delete`, rm home.
- **Hard constraint:** never move/rename a home after `aw init` — aweb registers
  the identity at its path and reaps it if the path disappears.
- Applies to **newly instantiated** agents only; existing running instances
  keep their setup until re-minted.

See [[2026-07-02-agent-runtime-launch-written-once]] (the launch primitive this
composes with) and task default-aaeq.19 / default-aaeq.14.
