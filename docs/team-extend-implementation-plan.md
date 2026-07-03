# `aw team extend` — implementation plan

Status: plan (task default-aaeq.26). Companion to the reviewed command SOT,
[`team-extend-sot.md`](team-extend-sot.md) (ACKed at 9e03487a). This plan
does not change `team_human.go`; implementation starts only after
default-aaeq.23 lands there. Line anchors below are at main `c0305cee`
unless a branch is named.

## Code seams to reuse

### Roster population (the shared path)

- `runTeamHumanCreateRosterAdd` — `cli/go/cmd/aw/team_human.go:592`. The
  batch wrapper `create --agent` already uses; `extend` becomes its second
  caller. It works by saving/restoring the `add` flag globals and invoking
  `runTeamHumanAdd(nil, args)`.
- `runTeamHumanAdd` — `team_human.go:1082`. Everything `extend` needs is
  here already; the problem is that its anchor is hardwired to cwd in five
  places:
  - `wd, err := os.Getwd()` — `team_human.go:1089`
  - `repoRoot := resolveRepoRoot(wd)` and
    `agentsRoot := filepath.Join(repoRoot, "agents", "instances")` —
    `team_human.go:1104-1105`
  - `shouldUseAPIKeyBootstrapForTeamAdd(wd)` — `team_human.go:1110`
  - `createAndAcceptTeamInviteForEmptyAgent(wd, ...)` —
    `team_human.go:1170` and `team_human.go:1190`
  - `setupTeamAddedAgentWorktree(wd, ...)` — `team_human.go:1242`

  The one structural refactor: extract the body into a function that takes
  an explicit anchor value — invite anchor dir, agents root, and the
  resolved authority (API key or invite-anchor workspace) — with
  `runTeamHumanAdd` becoming a thin cwd-derived wrapper so `add` and
  `create --agent` behavior is untouched. `extend` calls the extracted
  function with its discovered anchor. No behavior change in this step;
  existing `add`/`create` tests must stay green before `extend` lands on
  top.

### Invite authority (tiers 2–3)

- `resolveTeamInviteTarget` — `cli/go/cmd/aw/id_team.go:698`: resolves a
  workspace's active team + registry/aweb URLs. Used per candidate home.
- Local team-key mint — `createTeamInviteToken`, `id_team.go:1142`
  (`awconfig.TeamKeyExists` gate: per-user machine state, not per-home).
- Hosted mint — `createHostedTeamInviteToken`, `id_team.go:1189`
  (authenticates from the candidate home's workspace state).
- Agents-root resolution mirrors `resolveRepoRoot`
  (`cli/go/cmd/aw/inject_docs.go:166`) plus the `agents/instances` scan
  `aw team up` does (`buildTeamUpPlan`, `cli/go/cmd/aw/team_up.go:139`),
  with the SOT's cwd-first precedence added.
- Discovery itself is new code and goes in a new `team_extend.go`, not in
  `team_human.go`, so the diff on the contended file stays minimal.

### API-key authority (tier 1)

- `resolveInitAPIKey` — `cli/go/cmd/aw/init_apikey.go:102`; env const
  `AWEB_API_KEY` at `init_apikey.go:26`. Env-only today. The new
  `--api-key` flag resolves ONCE at command start (flag wins over env) into
  a value carried in the anchor struct — passed down explicitly, never by
  mutating the environment.
- Per-member bootstrap — `bootstrapTeamHumanAddAgentWithAPIKey`,
  `team_human.go:1019` → `runAPIKeyBootstrapInit`, `init_apikey.go:110`.
  Both take the key from `resolveInitAPIKey()` today
  (`team_human.go:1020`, and the gate at `team_human.go:1005`); the
  extracted-anchor refactor threads the resolved key into them instead.

### Non-TTY input policy (from default-aaeq.23)

Branch `aw-developer-aaeq23` (`be1225f7`, unmerged): adds `--username` to
`create` and calls `validateHostedNonInteractiveRequired`
(`cli/go/cmd/aw/onboarding_wizard.go:194`, already on main) before the
wizard — the pattern is `usageError("missing required flag: --<name>")`
when non-interactive. `extend` has no wizard, so it applies the same error
style directly at argument/flag validation; there is nothing to prompt for
by design. If aaeq.23's final shape adds shared helpers on
`team_human.go`, `extend` adopts them at rebase time — coordinate with
aw-developer before the first implementation commit.

## The mismatch-rollback auth requirement (first-class)

The SOT's `--team-id`-vs-API-key contract needs rollback of the first
bootstrapped member. The reviewer's recorded caution is a real defect risk:

- `rollbackJustCreatedTeamMember` — `team_human.go:1507` — resolves hosted
  auth via `resolveHostedTeamRemoveAuthWithAwebURL` — `id_team.go:2107` —
  which reads ONLY `AWEB_API_KEY` from the environment
  (`id_team.go:2109`) and the ANCHOR workspace's persisted
  `workspace.APIKey` (`id_team.go:2119`).
- In the clean-dir + `--api-key` case both are empty: the key came from a
  flag, and the anchor dir has no workspace. The documented side-effect-safe
  rollback would fail exactly when it is needed.

Requirements baked into the plan:

1. The rollback call for the API-key path takes the auth explicitly: the
   resolved `--api-key` value, or the just-created member home's persisted
   workspace api_key — `runAPIKeyBootstrapInit` persists the server-returned
   key into the created home via `initCertificateConnectWithOptions`
   (`init_apikey.go:226-231`), so the home is a valid auth source the moment
   the mismatch is detectable. Implementation: an explicit-auth variant of
   the hosted-remove call (parameter, not a new env contract), used by
   `extend`; `add`'s existing behavior is unchanged.
2. A unit test drives the mismatch path against an `httptest` server and
   asserts the remove-member request carries the explicit key in its
   `Authorization` header with `AWEB_API_KEY` unset — modeled on the
   existing API-key `add` tests (`team_human_create_test.go:1733,1817` seed
   `workspace.APIKey`).

## Command surface

New `teamHumanExtendCmd` registered next to `create`/`add`, flags per the
SOT (`--api-key`, `--team-id`, `--local`/`--global`, `--runtime`,
`--library-url`, `--blueprint`, `--work-dir`, `--start`/`--attach`/
`--no-attach`/`--session`). Output reuses `teamHumanAddOutput` with
`status: "extended"` plus resolved team id and authority tier. The
`create` soft notice (SOT: non-blocking one-liner when cwd has an active
membership and no `--byot`) is a two-line change in `runTeamHumanCreate`
(`team_human.go:372`) landing in the same series.

## Test plan (TDD, in landing order)

1. Anchor-extraction refactor: no new tests; the full existing
   `team_human` suite is the regression gate and must stay green.
2. `team_extend_test.go` (new file):
   - agents-root resolution matrix (cwd-first, enclosing
     `agents/instances`, repo root, clean dir).
   - discovery precedence: tier 1 beats populated layout; tier 2 wins with
     multi-team siblings present; tier 3 lexicographic pick; per-tier
     ambiguity error listing teams; `--team-id` filtering.
   - tier-4 error text names `--api-key`/`AWEB_API_KEY`, the scanned root,
     and `aw team create`.
   - `--team-id` + API-key mismatch: first member bootstrapped, rollback
     issued with explicit auth (the httptest assertion above), no second
     member attempted, error names both team ids.
   - non-TTY: no prompts anywhere; missing/conflicting flags produce
     `usageError` naming the flag; `--json` output shape includes team id
     and authority tier.
3. `create` notice test: active-membership cwd + no `--byot` prints the
   one-line notice to stderr and still creates.

## Dogfood harness

`scripts/dogfood-team-extend.sh` (committed with this plan; runnable once
`extend` exists — until then it fails fast at the version probe). It
exercises, against a throwaway team in a scratch directory:

- team-root call site: `aw team create` a throwaway team with one agent,
  then `extend` from the team root; assert the new home and the roster.
- agent-home call site: `extend` from inside the first agent's home; assert
  placement next to the sibling, not under it.
- clean-dir call site: `extend` in an empty dir with `--api-key`; assert
  layout is created and the member joins the key's team.
- negative: clean dir without a key → tier-4 error; `--team-id` naming a
  team the key does not own → mismatch error and no residual member/home.

Rules encoded in the script, not left to the operator: it refuses to run
without `AWEB_URL`/`AWEB_API_KEY` scoped to a throwaway team; every tmux
interaction (only if `DOGFOOD_TMUX=1`, for `--start`) uses
`tmux -L awdogfood` and never the default server; all state lives under a
`mktemp -d` root that is removed on exit.

## Landing order

1. default-aaeq.23 merges (owns `team_human.go` churn; adopt its final
   helper shape).
2. Anchor-extraction refactor, behavior-neutral, suite green.
3. `team_extend.go`: discovery + command + tests.
4. Explicit-auth rollback plumbing + mismatch tests.
5. `create` soft notice + test.
6. Dogfood run (all call sites + negatives), evidence posted to the task,
   review request to aw-reviewer-onboarding, then the merge gate.
