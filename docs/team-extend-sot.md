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

| Verb | Purpose | Anchor | Fails when |
|---|---|---|---|
| `aw team create <name>` | Make a NEW team, optionally populate it (`--agent`) | cwd (or `--home`) becomes the first member workspace | a team context already exists here → error suggesting `aw team extend` |
| `aw team extend <agent-spec>...` | Add members to an EXISTING team, discovering the authority | discovered (see below) | no team + authority can be found → error suggesting `aw team create` |
| `aw team add <agent-spec>...` | Single/multi-member primitive using the CURRENT workspace identity | cwd's `.aw` workspace | cwd has no active team workspace |

`extend` and `create --agent` are batch wrappers over the same
roster-population path (`runTeamHumanCreateRosterAdd` →
`runTeamHumanAdd`). `add` is that primitive exposed directly: it requires the
caller to already BE a team workspace (its cwd `.aw` identity mints the
invites). What makes `extend` distinct is that it may run from a directory
with no workspace identity of its own and DISCOVERS the authority to add
members.

The `create` guard above is target behavior, not current: today
`aw team create` in a dir with existing identity material follows the
existing-identity path and either mints a new team (self-controlled
namespace) or errors on hosted-managed namespaces. The guard becomes: an
active team membership in cwd without explicit new-team intent (`--byot`)
errors and names `aw team extend`. `--byot --namespace <domain>` remains the
deliberate way to create additional teams under a namespace you control.
That guard change is small and ships with `extend` so both halves of the
cross-suggestion exist at once.

## Synopsis

```
aw team extend <agent-spec>... [flags]
```

Agent specs are identical to `aw team add`:
`[NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]` or `NAME[:local|global]`
for empty-profile homes. Omitted names use the server-authoritative next
classic name; omitted scope comes from `profile.yaml`.

Flags (all reused from `add` where they exist there):

- `--api-key <key>` — explicit team API key; wins over discovery. New flag;
  the `AWEB_API_KEY` env var is the equivalent (flag wins over env).
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

Precedence is deterministic and overridable. First match wins:

1. **Explicit team API key** — `--api-key`, else `AWEB_API_KEY`. Used
   directly via the API-key bootstrap path (`runAPIKeyBootstrapInit` per
   member, as `add` does in API-key mode). The key itself determines the
   team; no scan happens. If `--team-id` is also given and does not match
   the key's team, error.
2. **The current workspace, if invite-capable** — cwd has a `.aw` workspace
   with an active team and can mint invites (below). This covers running
   `extend` from an agent home and from a team root whose first member was
   created in place by `aw team create`.
3. **A discovered invite-capable agent** — scan the candidate homes under
   the agents root (next section), in lexicographic order, and borrow the
   first invite-capable one as the invite anchor. The new members join that
   agent's active team.
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

If `--team-id` is given, tiers 2–3 only consider workspaces whose active
team matches it. Without `--team-id`, if the qualifying candidates span more
than one active team, `extend` errors and lists the teams found, asking for
`--team-id`. It never guesses among teams.

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

## Errors that cross-reference the verbs

- `aw team create` with an active team membership in cwd (and no `--byot`):
  names the team and suggests `aw team extend`.
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
  taking precedence over the env var.
- Dogfooding: a throwaway team only; exercise all three call sites (team
  root, agent home, clean dir + API key), plus the ambiguity error and the
  tier-4 error. Any tmux experiment (`--start`) runs on an isolated socket
  (`tmux -L awdogfood`) — never the default tmux server.
