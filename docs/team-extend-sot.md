# `aw team extend` — command SOT

Status: design (task default-aaeq.26). Implementation lands after
default-aaeq.23 (non-TTY `aw team create`/`aw init` inputs), which it reuses.

`aw team extend` adds members to an EXISTING team. It is the sibling of
`aw team create`: same agent specs, same roster-population machinery, minus
team creation, plus membership-authority discovery. It is callable from a
directory that holds an `agents/instances` team, from an agent home, or from
a clean directory, and it is fully non-TTY (agents run it).

Vocabulary, precisely: this command is about team membership AUTHORITY — who
is entitled to add a member to the team. That is unrelated to identity SCOPE
(`:local` / `:global` in an agent spec), which says whether the new member's
identity is team-scoped or a global AWID identity. The two never mix in this
document or in the command's output.

## The three-verb model

| Verb | Purpose | Anchor | When cwd is already a team context |
|---|---|---|---|
| `aw team create <name>` | Make a NEW team, optionally populate it (`--agent`) | cwd (or `--home`) becomes the first member workspace | always creates; a non-blocking one-line notice points at `aw team extend` for adding to the EXISTING team |
| `aw team extend <agent-spec>...` | Add members to an EXISTING team, discovering the authority | discovered (see below) | proceeds; hard error suggesting `aw team create` only when no team + authority can be found |
| `aw team add <agent-spec>...` | Single/multi-member primitive using the CURRENT workspace identity | cwd's `.aw` workspace | proceeds; errors when cwd has no active team workspace |

`extend` and `create --agent` are batch wrappers over the same
roster-population path (`runTeamHumanCreateRosterAdd` →
`runTeamHumanAdd`). `add` is that primitive exposed directly: it requires the
caller to already BE a team workspace (its cwd `.aw` identity mints the
invites). What makes `extend` distinct is that it may run from a directory
with no workspace identity of its own and DISCOVERS the authority to add
members.

`aw team create`'s contract is that it ALWAYS creates a new team. It must
not refuse just because cwd already has an active team membership: an agent
standing in its own home always has one, and agent-run `create` is a design
goal (default-aaeq.23), so a hard block there would contradict it. Instead,
when cwd has an active membership and there is no `--byot`, `create` emits a
non-blocking one-line notice — you are already a member of team X;
`aw team extend` adds members to THAT team — and proceeds to create the new
team. The two halves stay symmetric but only `extend`'s side is a hard
error, because `extend` genuinely cannot proceed without a team + authority
whereas `create` always can. The notice ships together with `extend` so
both halves of the cross-suggestion exist at once.

## Synopsis

```
aw team extend <agent-spec>... [flags]
```

Agent specs are identical to `aw team add`:
`[NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]` or `NAME[:local|global]`
for empty-profile homes. Omitted names use the server-authoritative next
classic name; omitted scope comes from `profile.yaml`.

Flags (all reused from `add` where they exist there):

- `--api-key <key>` — explicit team API key; wins over discovery and bypasses
  any assertion inferred from the current workspace. The `AWEB_API_KEY` env var
  selects the same API-key authority tier, but when cwd has an active team that
  team is asserted against the server response (flag wins over env).
- `--team-id <name>:<namespace>` — disambiguate when discovery finds
  invite-capable agents in more than one team.
- `--local` / `--global` — identity-scope override for all listed specs
  (same as `add`).
- `--runtime`, `--library-url`, `--blueprint` — materialization inputs
  (same as `add`).
- `--work-dir` — git repo for the added agents' worktrees (same as `add`).
- `--start`, `--attach`/`--no-attach`, `--session` — launch after
  materializing; `--start` requires exactly one agent (same as `add`).

Not carried over: `--home` and `--layout-only` (both are `add`-primitive
concerns; a caller who needs them has a workspace and should use `add`).

## Authority discovery

Precedence is deterministic and overridable. The first tier that can
select an anchor wins; lower tiers are not consulted after that:

1. **Team API key** — explicit `--api-key`, else `AWEB_API_KEY`. Used
   directly via the API-key bootstrap path (`runAPIKeyBootstrapInit` per
   member, as `add` does in API-key mode). The key itself determines the
   team. An explicit `--api-key` does not consult workspace team state; it is
   the opt-out when the caller deliberately wants to extend a different team.

   There is one deliberate exception for an ambient `AWEB_API_KEY`: when cwd
   has an active team and the caller did not pass `--team-id`, that active team
   becomes an assertion against the key's team. This disk lookup does not
   replace API-key authority or guess a team. It makes a forgotten ambient key
   safe by checking the workspace's explicit membership context against the
   server's authoritative answer. The output authority tier is
   `api-key-workspace-asserted`; explicit-key and clean-directory API-key runs
   remain `api-key`.

   An explicit `--team-id` alongside either kind of key is also an assertion
   and wins over any workspace-derived assertion. Assertions are
   side-effect-safe: the key's team is only learned from the server response
   of the bootstrap call, so the FIRST member is bootstrapped, its response
   team id is compared to the asserted team, and on mismatch that just-created
   member is rolled back — server-side membership revoked and the local home
   removed, via the same rollback machinery the roster path already uses
   (`rollbackJustCreatedTeamMember` + home rollback) — and `extend` errors
   naming both team ids before any further member is attempted. An implicit
   mismatch says `workspace active team X does not match API key team Y`; it
   never names an unpassed `--team-id` flag. A mismatch never leaves a partial
   roster in the key's team. (If a key-introspection preflight endpoint becomes
   available, it replaces the bootstrap-then-rollback check; the observable
   contract stays the same.)
2. **The current workspace, if invite-capable** — cwd has a `.aw` workspace
   with an active team and can mint invites (below). This covers running
   `extend` from an agent home and from a team root whose first member was
   created in place by `aw team create`.
3. **A discovered invite-capable agent** — scan the candidate homes under
   the agents root (next section), gather the qualifying ones, apply the
   ambiguity rule below, and borrow the lexicographically first qualifying
   home as the invite anchor. The new members join that agent's active
   team.
4. **Error** — nothing found. The error names both missing inputs and the
   alternative verb:

   ```
   no membership authority found: no --api-key/AWEB_API_KEY, and no
   invite-capable agent workspace under <agents-root> (checked <n>
   candidate homes); run aw team extend inside a team directory, pass
   --api-key, or create a new team with aw team create <name>
   ```

Why explicit-key-first: tiers 2–3 are discovery — they depend on what
happens to be on disk. An explicit key is the caller saying exactly which
team and which authority; it must not be overridden by whatever the scan
finds. (`aw team add` keeps its existing opposite ordering — workspace
first, API key as fallback — because for `add` the cwd workspace IS the
explicit context. The asymmetry is deliberate.)

**Invite-capable**, concretely: for a candidate home,
`resolveTeamInviteTarget(home)` resolves an active team (workspace/team
state), AND one of the two invite-minting branches is available for it —
the local team key exists for the team's domain/name
(`awconfig.TeamKeyExists`; note team keys are per-user machine state, not
per-home), or the team resolves a hosted aweb URL and the home's
certificate authenticates a hosted spawn-invite
(`createHostedTeamInviteToken`). This is exactly the authority `aw team
add` exercises today via `createAndAcceptTeamInviteForEmptyAgent`; `extend`
changes where the anchor comes from, not what it can do.

Capability is proven at mint time, not pre-checked per candidate: discovery
selects the first candidate whose team state resolves (and matches
`--team-id` when given); if its mint then fails, that failure surfaces
as-is with the anchor's path named — it does not silently fall through to
the next candidate, which would make failures order-dependent and opaque.

### Team ambiguity

Ambiguity is judged WITHIN a tier, and only after every higher tier has
failed to select an anchor. A lower tier never re-opens or overrides a
higher one:

- Tier 1: the key names the team. Explicit `--api-key` consults nothing on
  disk. Ambient `AWEB_API_KEY` consults only cwd's active team for the
  side-effect-safe assertion described above; it does not scan candidate homes
  or select authority from disk.
- Tier 2: if the current workspace is invite-capable (and its active team
  matches `--team-id` when given), it is selected even when sibling homes
  under the agents root belong to other teams. Standing in a workspace is
  explicit context; the scan never runs and cannot make it ambiguous.
- Tier 3: `--team-id`, when given, filters the qualifying candidates to
  those whose active team matches. Without `--team-id`, if the qualifying
  candidates span more than one active team, `extend` errors and lists the
  teams found, asking for `--team-id`. Within a single team, the
  lexicographically first qualifying home wins.

`extend` never guesses among teams.

## Where it can be called from

The **agents root** is the directory that holds the team layout
(`.../agents/instances`). It is resolved from cwd, first match wins:

1. `<cwd>/agents/instances` exists → that.
2. cwd is inside an `agents/instances` tree (the agent-home case) → that
   enclosing `agents/instances`.
3. `<git-repo-root(cwd)>/agents/instances` exists → that (matches where
   `aw team add` and `aw team up` operate from a repo subdirectory).
4. Otherwise there is no layout yet: `<cwd>/agents/instances` is created on
   success (the clean-dir case).

New member homes are placed at `<agents-root>/<name>`, with the same
preflights, materialization, connect, configure, worktree setup, and
rollback behavior as `aw team add`.

| Call site | Example cwd | Authority available | Agents root |
|---|---|---|---|
| Team root | `myrepo/` or `myrepo/cli/` holding `agents/instances` | tier 2 if cwd itself has a team workspace; else tier 3 scan of `agents/instances/*`; tier 1 always | `<cwd>/agents/instances` |
| Agent home | `myrepo/cli/agents/instances/coordinator/` | tier 2 (the agent's own workspace); tier 1 always | the enclosing `agents/instances` |
| Clean dir | empty `newdir/` | tier 1 only (`--api-key`/`AWEB_API_KEY`); anything else is the tier-4 error | `<cwd>/agents/instances`, created |

A clean dir plus an API key is the remote-populate story: nothing on disk,
the key names the team, and `extend` builds the layout from scratch —
`aw team create` minus the create.

## Non-TTY behavior

Agents run `extend`; it must never block on a prompt. Policy (same as
default-aaeq.23, stricter because `extend` has no wizard):

- Every required input is an argument or flag. `extend` never prompts,
  TTY or not.
- A missing or unresolvable required input is an error that names the flag
  or the fix (`pass --api-key or run inside a team directory`, `pass
  --team-id, found teams: ...`) — never a silent EOF, never a hang.
- `--json` output works everywhere; the success output is the `add` output
  shape with `"status": "extended"` and the resolved team id and authority
  tier included, so callers can assert which path was used.

## Cross-references between the verbs

- `aw team create` with an active team membership in cwd (and no `--byot`):
  a non-blocking notice that names the team and suggests `aw team extend`,
  then the create proceeds. Not an error.
- `aw team extend` with no team + authority: suggests `aw team create`
  (tier-4 error above).
- `aw team extend` in a workspace that has an active team but cannot mint
  (no team key, no hosted URL, no API key): says what authority is missing
  for that team, rather than the generic tier-4 text.

## Implementation notes

- Reuse `runTeamHumanCreateRosterAdd` → `runTeamHumanAdd`. The one
  structural change: the invite anchor and the agents root are currently
  both derived from cwd inside `runTeamHumanAdd`
  (`createAndAcceptTeamInviteForEmptyAgent(wd, ...)`,
  `resolveRepoRoot(wd)`); they become explicit parameters so `extend` can
  pass the discovered anchor and the resolved agents root while `add` and
  `create` keep passing cwd-derived values.
- Depends on default-aaeq.23: the non-TTY required-input policy and any
  flag plumbing it adds to this file land first; `extend` builds on top to
  avoid churn on `team_human.go`.
- The `--api-key` flag is new surface (today the key is env-only); it feeds
  the same `resolveInitAPIKey`-consuming bootstrap path, with the flag
  taking precedence over the env var and bypassing only the ambient key's
  workspace-derived assertion. Explicit `--team-id` remains independent and
  is always enforced when supplied.
- Dogfooding: a throwaway team only; exercise all three call sites (team
  root, agent home, clean dir + API key), plus the ambiguity error and the
  tier-4 error. A tmux experiment (`--start`) must be a committed, reviewed
  harness that prepends `scripts/guard-bin` and sets `AWEB_TMUX_TMPDIR` for
  the launcher plus `TMUX_TMPDIR` for every raw tmux command. Raw tmux ignores
  `AWEB_TMUX_TMPDIR`. Tear down only the named throwaway session, never a
  server.
