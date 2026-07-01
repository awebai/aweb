# Invite-accept and server-URL resolution consolidation

Status: in progress (epic `default-aadu`)

## Why

Two surfaces in the team-provisioning code accreted parallel implementations
over the identity/team-model epic. Each new command bolted on its own path
instead of routing through a shared one. The result is duplicated logic that
has already diverged and produced user-visible bugs.

This document is the grounded diagnosis and the target design. Line references
are current as of the branch base.

### Surface 1 — "the server URL for a team" has no single source of truth

There are ~20 functions that resolve an aweb-server URL. The rule "if empty,
use our server" (`DefaultAwebURL = https://app.aweb.ai`, `helpers.go:31`) is
copy-pasted into 7 sites, and about 5 of those are the *same*
`AWEB_URL else default` logic re-implemented:

- `resolveInitAwebURL` (`init.go:310`)
- `resolveAPIKeyInitAwebURL` (`init_apikey.go:109`) and its belt-and-suspenders
  re-default at `init_apikey.go:122`
- `acceptHostedTeamInviteWithDetails` inline (`id_team.go:1387`)
- `defaultWizardAwebURL` (`onboarding_wizard.go:322`)
- `resolveBaseURLForInit` (`helpers.go:994`)
- `executeTeamCleanupCloud` (`id_team.go:2583`, already covered by the flag
  default at `id_team.go:585`)
- worktree-invite inline (`workspace_invite.go:44`)

`awebURLForTeamInvite` (`id_team.go:768`) is the anomaly: it is the one
resolver that *forgot* the default and returns `""`. Its registry twin
`registryURLForTeamInvite` (`id_team.go:749`) does the same. When a member
provisions an agent (`aw team add`), an empty URL here makes the mint decision
(`team_human.go:1367-1378`) fall through to the local-team-key branch and fail
with `no team key` (`id_team.go:1130`) — even though the member is entitled to
mint via their hosted member cert. This was the reported "second agent-set
cannot join" failure.

### Surface 2 — "finalize an accepted membership" is scattered, not shared

There is no single function for "an invite was accepted, now record it." Each
of ~7 accept/enroll paths independently chooses which of these it writes:
TeamState membership, worktree-workspace binding, worktree membership cache,
encryption key, set-active.

Not every difference is a bug — one is a deliberate model boundary that the
consolidation must preserve:

- **Intended, not a bug:** `aw team join` / `aw team accept-invite`
  (`acceptAndStoreTeamInvite`, `id_team.go:835`) do **not** write
  `workspace.yaml`. A human joins, then runs `aw init` in the worktree, and
  `aw init` (the connect step) writes the worktree binding. This is asserted by
  `TestTeamInviteHostedUsesCloudAuthorityWithoutLocalTeamKey`
  (`id_team_test.go:1734`): no `workspace.yaml` before `aw init`. Only the
  agent-provisioning paths (`createAndAcceptTeamInviteForEmptyAgent`) write the
  binding immediately, because they produce a ready-to-run agent with no
  separate `aw init`. So "join has no `workspace.yaml`" is by design; it is
  **not** the cause of the `no team key` failure, and forcing a single finalize
  that always writes `workspace.yaml` would break this model. The real fix for
  the failure is the URL resolver (Surface 1): the invite-mint resolver must
  read the team's URL from `teams.yaml` (which join *does* write) rather than
  only from `workspace.yaml`.

- **To verify, then fix if confirmed:** BYOT creator self-enroll
  (`runTeamHumanCreateModelA`, `team_human.go:689`) skips the encryption-key
  step every other path runs; hosted accept
  (`acceptHostedTeamInviteWithDetails`) never populates `RegistryURL` on the
  returned struct. Each must be checked against whether the value is supplied
  elsewhere (e.g. registry discovered from `AwebURL`) before being treated as a
  bug — see Stage 2.

- **Genuine sharing opportunity:** `initCertificateConnectWithOptions`
  re-implements the TeamState membership write inline (`init_connect.go:121-138`)
  instead of reusing `upsertAcceptedTeamMembershipState`.

## The two config stores (grounded)

Both stores live per-worktree in that worktree's `.aw/`. They are **not** a
global-vs-local split — each worktree holds its own `teams.yaml` and
`workspace.yaml`.

### `teams.yaml` = `TeamState` (`awconfig/team_state.go:23`)

The identity's **team roster and authority**. Load-bearing-unique fields:

- `ActiveTeam` — authoritative for active-team selection
  (`selection.go:112,128`; `ActiveMembershipFor(workspace, teamState)`).
- membership `RegistryURL` — read by the mail gateway (`main.go:1229`), E2E
  encryption-key resolution (`id_encryption_key.go:331,341`), add-worktree
  registry resolution (`workspace.go:958`), `id team members`
  (`id_team.go:1070`).

### `workspace.yaml` = `WorktreeWorkspace` (`awconfig/workspace.go:23`)

**This worktree's live binding to its aweb workspace.** Load-bearing-unique
fields:

- top-level `AwebURL` — the base URL for *every* API call
  (`selection.go:107` -> `Selection.BaseURL`); also `APIKey`, and the
  repo/host binding metadata `RepoID`, `CanonicalOrigin`, `Hostname`,
  `WorkspacePath`, `HumanName`, `AgentType`.
- membership `RoleName` — role resolution (`roles.go:424`), status
  (`workspace.go:1159`), doctor (`doctor_aweb.go:488`).
- membership `WorkspaceID` — coordination self-identity (`work.go:266`),
  add-worktree collision check (`workspace.go:365`), status, doctor
  (`doctor_aweb.go:378,411`).

Each worktree gets its **own** workspace identity (a fresh `WorkspaceID`, cert,
and alias). This is exactly what `aw workspace add-worktree` depends on: a new
worktree is a new membership on the server with its own binding
(`workspace_invite.go:17` -> `initCertificateConnectWithOptions`, which writes
both `teams.yaml` and `workspace.yaml` into the new worktree's `.aw/`). Nothing
is shared across worktrees.

### The redundancy (migration leftover)

`teams.yaml` was carved out of `workspace.yaml` — proven by
`migrateTeamStateFromWorkspace` (`team_state.go:302`),
`teamStateFromLegacyWorkspace` (`team_state.go:340`), and the `active_team`
field surviving only in the legacy `worktreeWorkspaceYAML` shape
(`workspace.go:48`). The migration copied `TeamID/Alias/CertPath/JoinedAt` into
`teams.yaml` but left the same membership spine in `workspace.yaml`. So these
fields are stored and co-written in **both** memberships from the same source:
`TeamID`, `Alias`, `CertPath`, `JoinedAt`, and (vs the top-level
`workspace.AwebURL`) `AwebURL`. They are drift-prone: the mail gateway reads
`AwebURL` from `teams.yaml` first (`main.go:1216`) while every other reader
prefers the `workspace.yaml` top-level value — a live precedence inconsistency.

## Design decision

The stores serve genuinely different core concerns (roster/authority vs
worktree-binding) and neither reader set can be dropped, so **we do not merge
the two files**, and `aw workspace add-worktree` is preserved unchanged in
behaviour. We remove the *duplication* and the *divergence*:

- **One aweb-URL resolver** with the invariant *never empty for a hosted
  context*: precedence explicit-flag -> `AWEB_URL` env -> `workspace.AwebURL`
  -> active membership `AwebURL` -> `DefaultAwebURL`. Preserve the single
  cross-surface gate "our-registry implies our-server" (`init.go:379-386`).
  One registry-URL resolver likewise defaulting to `DefaultAWIDRegistryURL`.
  Route the anomaly and the ~5 duplicates through these; delete the dead
  copies.
- **One shared accept-core** for what every path genuinely has in common —
  save cert, record the `teams.yaml` membership, ensure the encryption key.
  Every accept/enroll path calls it; the two legitimately divergent steps stay
  separate and explicit: (a) how the cert was obtained (local mint / remote
  hosted accept / cross-machine fetch), and (b) whether the worktree binding is
  written now (agent-provisioning) or deferred to `aw init` (human join). We do
  **not** collapse (b) into the core — that boundary is intended (see Surface 2).
- **Store reconciliation** (the data-level application of the same principle):
  one writer for the shared spine so it cannot drift; one read-precedence
  everywhere (fix the gateway inversion); and shrink `workspace.yaml`'s
  membership to only its unique fields (`TeamID` key + `RoleName` +
  `WorkspaceID`), reading `Alias`/`CertPath`/`JoinedAt` from `teams.yaml` (the
  roster authority), with a one-time config migration for existing worktrees.

## Invariants (must hold after every stage)

1. `aw workspace add-worktree` continues to create a new per-worktree workspace
   identity with its own `teams.yaml` + `workspace.yaml`.
2. Every accept/enroll path leaves: `workspace.AwebURL` set, both stores'
   membership views agreeing, hosted memberships carrying `RegistryURL`, and a
   joined member able to `aw team add`.
3. The aweb-URL resolver never returns empty for a hosted context.
4. No behaviour change for existing single-team worktrees beyond the one-time
   migration.

## Staged plan (TDD; each stage green + reviewed before the next)

- **Stage 0** — characterization tests encoding the invariants above. Several
  fail on the base branch; that is the proof.
- **Stage 1** — one aweb-URL resolver + one registry-URL resolver; route the
  anomaly and duplicates through them; delete dead copies. Turns the URL cause
  of the `no team key` failure green on its own.
- **Stage 2** — extract the shared accept-core (save cert, record `teams.yaml`
  membership, ensure encryption key); every accept/enroll path calls it. Keep
  the worktree binding a separate step (intended join-vs-provision boundary).
  Verify and, if confirmed, fix the modelA-key and hosted-registry divergences;
  reuse the shared membership writer from `initCertificateConnectWithOptions`.
- **Stage 3** — store reconciliation: single spine writer, single
  read-precedence, shrink `workspace.yaml` membership + one-time migration.

Verification each stage: `make build` + `make test` green with pristine output,
plus AC's `e2e-cloud-user-journey` consumer (the aw command surface is read
live by AC's journey — behaviour changes re-gate them, so they land together).
