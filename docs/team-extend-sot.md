# `aw team admin extend` — command SOT

> **Status: shipped compatibility command contract.** The everyday workflow is
> [Orchestrate more local agents](grow-team.md); this document preserves the durable
> authority discovery, ambiguity, recovery, and batch semantics used by the
> implemented command and its tests. It does not make profiles, homes,
> worktrees, or runtime launch mandatory.

`aw team admin extend` adds members to an EXISTING team. It is the sibling of
`aw team admin create`: same agent specs, same roster-population machinery, minus
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
| `aw team admin create <name>` | Make a NEW team, optionally populate it (`--agent`) | cwd (or `--home`) becomes the first member workspace | always creates; a non-blocking one-line notice points at `aw team admin extend` for adding to the EXISTING team |
| `aw team admin extend <agent-spec>...` | Add members to an EXISTING team, discovering the authority | discovered (see below) | proceeds; hard error suggesting `aw team admin create` only when no team + authority can be found |
| `aw team admin add <agent-spec>...` | Single/multi-member primitive using the CURRENT workspace identity | cwd's `.aw` workspace | proceeds; errors when cwd has no active team workspace |

`extend` and `create --agent` are batch wrappers over the same
roster-population path (`runTeamHumanCreateRosterAdd` →
`runTeamHumanAdd`). `add` is that primitive exposed directly: it requires the
caller to already BE a team workspace (its cwd `.aw` identity mints the
invites). What makes `extend` distinct is that it may run from a directory
with no workspace identity of its own and DISCOVERS the authority to add
members.

`aw team admin create`'s contract is that it ALWAYS creates a new team. It must
not refuse just because cwd already has an active team membership: an agent
standing in its own home always has one, and the shipped non-TTY create path
supports agent-run `create`, so a hard block there would contradict it. Instead,
when cwd has an active membership and there is no `--byot`, `create` emits a
non-blocking one-line notice — you are already a member of team X;
`aw team admin extend` adds members to THAT team — and proceeds to create the new
team. The two halves stay symmetric but only `extend`'s side is a hard
error, because `extend` genuinely cannot proceed without a team + authority
whereas `create` always can. The notice ships together with `extend` so
both halves of the cross-suggestion exist at once.

## Synopsis

```
aw team admin extend <agent-spec>... [flags]
```

Agent specs are identical to `aw team admin add`:
`[NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]` or `NAME[:local|global]`
for empty-profile homes. Omitted names use the server-authoritative next
classic name; omitted scope comes from `profile.yaml`.

Flags (all reused from `add` where they exist there):

- `--api-key <key>` — explicit person setup key; wins over discovery and bypasses
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

1. **Person setup key** — explicit `--api-key`, else `AWEB_API_KEY`. Used
   directly via the API-key bootstrap path (`runAPIKeyBootstrapInit` per
   member, as `add` does in API-key mode). `GET /api/v1/teams/current`
   identifies `api_key_kind=person` or `workspace`. A workspace key instead
   selects the native signing creator for the requested team and prints a
   notice; without one it refuses with creator/setup-key guidance. A missing
   or unknown kind preserves the API path, without a warning. Stored
   workspace keys never create another identity. The key itself determines the
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
   and wins over any workspace-derived assertion. `extend` compares the
   asserted team with the key's canonical team from `GET /api/v1/teams/current`
   before any admission request or agent home creation. On mismatch it names
   both teams and refuses the roster. An implicit mismatch says `workspace
   active team X does not match API key team Y`, identifying the source of
   the assertion.
2. **The current workspace, if invite-capable** — cwd has a `.aw` workspace
   with an active team and can mint invites (below). This covers running
   `extend` from an agent home and from a team root whose first member was
   created in place by `aw team admin create`.
3. **A discovered invite-capable agent** — scan the candidate homes under
   the agents root (next section), gather the qualifying ones, apply the
   ambiguity rule below, and use the single qualifying
   home as the invite anchor, printing its path as the creator. The new members join that agent's active
   team.
4. **Error** — nothing found. The error names both missing inputs and the
   alternative verb:

   ```
   no membership authority found: no --api-key/AWEB_API_KEY, and no
   invite-capable agent workspace under <agents-root> (checked <n>
   candidate homes); run aw team admin extend inside a team directory, pass
   --api-key, or create a new team with aw team admin create <name>
   ```

A person's setup key is explicit creation authority and wins over disk. A
workspace key is not creation authority: the selected native workspace signs
its child using the existing invitation exchange. This rule is shared with
`add`, `init` and `add-worktree`. The service keeps the legacy API path when
key-kind metadata is absent or unknown.

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
gathers candidates whose team state resolves (and matches
`--team-id` when given); one candidate may be used. If its mint then fails, that failure surfaces
as-is with the anchor's path named — it does not silently fall through to
the next candidate, which would make failures order-dependent and opaque.

### Team ambiguity

Ambiguity is judged WITHIN a tier, and only after every higher tier has
failed to select an anchor. A lower tier never re-opens or overrides a
higher one:

- Tier 1: a person setup key names the team. Explicit person `--api-key` consults nothing on
  disk. A workspace key must select its native signing creator. Ambient `AWEB_API_KEY` consults only cwd's active team for the
  side-effect-safe assertion described above; it does not scan candidate homes
  or select authority from disk.
- Tier 2: if the current workspace is invite-capable (and its active team
  matches `--team-id` when given), it is selected even when sibling homes
  under the agents root belong to other teams. Standing in a workspace is
  explicit context; the scan never runs and cannot make it ambiguous.
- Tier 3: `--team-id`, when given, filters the qualifying candidates to
  those whose active team matches. Without `--team-id`, if the qualifying
  candidates span more than one active team, `extend` errors and lists the
  teams found, asking for `--team-id`. Within a single team, exactly one qualifying home is used and printed as
  the creator. Several homes are listed in a refusal before any write; run
  from the intended creating workspace or select its `--identity-home`.

`extend` never guesses among teams.

## Where it can be called from

The **agents root** is the directory that holds the team layout
(`.../agents/instances`). It is resolved from cwd, first match wins:

1. `<cwd>/agents/instances` exists → that.
2. cwd is inside an `agents/instances` tree (the agent-home case) → that
   enclosing `agents/instances`.
3. `<git-repo-root(cwd)>/agents/instances` exists → that (matches where
   `aw team admin add` and `aw team admin up` operate from a repo subdirectory).
4. Otherwise there is no layout yet: use `<cwd>/agents/instances` (the
   clean-dir case).

New member homes are placed at `<agents-root>/<name>`, with the same
preflights, materialization, connect, configure, worktree setup, and recovery
behavior as `aw team admin add`.

| Call site | Example cwd | Authority available | Agents root |
|---|---|---|---|
| Team root | `myrepo/` or `myrepo/cli/` holding `agents/instances` | tier 2 if cwd itself has a team workspace; else tier 3 scan of `agents/instances/*`; tier 1 always | `<cwd>/agents/instances` |
| Agent home | `myrepo/cli/agents/instances/coordinator/` | tier 2 (the agent's own workspace); tier 1 always | the enclosing `agents/instances` |
| Clean dir | empty `newdir/` | tier 1 only (`--api-key`/`AWEB_API_KEY`); anything else is the tier-4 error | `<cwd>/agents/instances`, created |

A clean dir plus an API key is the remote-populate story: nothing on disk,
the key names the team, and `extend` builds the layout from scratch —
`aw team admin create` minus the create.

## Non-TTY behavior

Agents run `extend`; it must never block on a prompt. Its policy is stricter
than the create/init wizard path because `extend` has no wizard:

- Every required input is an argument or flag. `extend` never prompts,
  TTY or not.
- A missing or unresolvable required input is an error that names the flag
  or the fix (`pass --api-key or run inside a team directory`, `pass
  --team-id, found teams: ...`) — never a silent EOF, never a hang.
- `--json` output works everywhere; the success output is the `add` output
  shape with `"status": "extended"` and the resolved team id and authority
  tier included, so callers can assert which path was used.

## Batch roster failure outcomes

Roster-wide facts available before creating a member are preflight work: spec
and profile resolution, alias and home collisions, and whether the selected
authority can mint every resolved effective identity scope. A failure in those
checks returns before any member is attempted. Scope resolution includes both
an explicit spec suffix and a profile's `profile.yaml` default.

Once roster mutation begins, the first non-preflightable member failure still
stops the batch and leaves the command exit status non-zero. Before returning,
`extend` prints an ordered outcome for every input spec in both human and JSON
modes:

- `created` — the member completed before the failure and remains in the team;
- `failed` — this spec failed, with its reason in the `reason` field;
- `not_attempted` — the untouched tail was skipped after the failure.

The `agents` array preserves command-line order and failure JSON uses
`"status": "failed"`. Earlier members remain in the team. If the failed member
has prepared recovery material or an admitted certificate, its home retains
the material required to resume the same identity. For global members
provisioned by invitation, rerun the original command from the same creator
with the same team, agent name and home. The retry uses the retained key and
invitation, including when the registry accepted the membership and its
response was lost. When there is no identity to retain, the failed member's
new local files can be rolled back.
A fully successful batch keeps the existing human and JSON output unchanged;
per-agent outcome fields are omitted on that path.

## Cross-references between the verbs

- `aw team admin create` with an active team membership in cwd (and no `--byot`):
  a non-blocking notice that names the team and suggests `aw team admin extend`,
  then the create proceeds. Not an error.
- `aw team admin extend` with no team + authority: suggests `aw team admin create`
  (tier-4 error above).
- `aw team admin extend` in a workspace that has an active team but cannot mint
  (no team key, no hosted URL, no API key): says what authority is missing
  for that team, rather than the generic tier-4 text.
