---
name: aweb-bootstrap
description: This skill should be used when helping a human create or join an aweb team from a template (aw team bootstrap), choosing a template and team source (hosted new team, BYOT, API key, invite, or current workspace forwarding), selecting work-directory vs work-repo-url, provisioning optional worktree agents, and validating/re-running bootstrap safely.
allowed-tools: "Bash(aw *)"
---

# aweb Bootstrap

Use this skill when a human wants to create a new aweb team for the first time, and you need to guide them through `aw team bootstrap` decisions and validation.

This skill is about **decision policy + safe execution**, not memorizing flags.

Related skills:

- For day-to-day coordination once the team exists: `aweb-coordination`
- For mail/chat response policy: `aweb-messaging`
- For joining an existing team, multi-team membership, custody, addressability, and contacts: `aweb-team-membership`

Long-form reference: docs/team-bootstrap.md in the aweb repo.

## Bootstrap vs join (first decision)

Bootstrap when:

- You are creating a brand-new team (new template repo clone, new identities, new role bundle).
- You want reproducible setup for multiple agents/workspaces.
- You want a “one command creates the team + installs roles + provisions agent dirs” flow.

Do NOT bootstrap when:

- The team already exists and you just need to add yourself: use `aweb-team-membership` and the `aw id team ...` commands.
- You only need another workspace for yourself: use `aw workspace add-worktree` (git worktree) or create another directory and `aw init` it.

## Pick a template (what team shape are we creating?)

Canonical templates:

- awebai/aweb-team-dev-review (2 agents)
  Use when you want the smallest meaningful team: implementation + review.

- awebai/aweb-team-company-surfaces (6 agents)
  Use when you want a cross-functional team: direction/engineering/operations/support/outreach/analytics.

Fork vs use-as-is:

- Use as-is to learn the flow or to run a standard team.
- Fork when you want to customize roles, responsibilities, or instructions.

## Before running bootstrap (safety checks)

1) Run bootstrap from a directory that is NOT already inside a git repo/worktree.

- If you are inside a git repo/worktree and you are using a remote template ref, bootstrap will refuse to clone by default.
- Use `--template-cache-dir` as the explicit escape hatch when you must run from inside a repo.

2) Decide the “work” directory model (see next section). This affects whether agents share one checkout or get isolated worktrees.

## Exactly one of: work-directory OR work-repo-url (XOR)

Bootstrap needs a directory to symlink into each agent workspace as ./work.

You must provide exactly one of:

A) --work-directory PATH

- Use when you already have a local directory you want agents to use as work.
- For code teams with worktree agents (team.yaml worktrees:), PATH must be a git repo.

B) --work-repo-url VALUE

- Use when you want bootstrap to clone a repo for you.
- VALUE can be a URL or a local path; bootstrap runs “git clone VALUE” into:

  <template-checkout>/worktrees/<derived-name>/

  where <derived-name> matches git’s default directory naming (basename, .git stripped).

- That clone destination is then used as the effective work directory (symlinked as ./work in each agent workspace).

If both flags are set, treat it as a user error and stop.

## Team source policy

Non-dry-run bootstrap needs exactly one coherent team source. The first generated agent workspace is the anchor: bootstrap connects it first, installs roles/instructions from that workspace's team context, then invites/connects the remaining agents.

Supported sources:

1) Hosted new team (aweb.ai)

- Best for first-time teams.
- Use `--username <name>` or run interactively in a TTY.
- Bootstrap uses the same hosted onboarding path as `aw init` for the first generated workspace.

2) Existing hosted team via API key

- If `AWEB_API_KEY` is set, bootstrap joins the API key's hosted team.
- `AWEB_URL` or `--aweb-url` must identify the hosted API base.
- Do not also pass `--username`, `--invite-token`, or BYOT flags.

3) Existing team via invite token

- Pass `--invite-token <token>`.
- Bootstrap accepts it into the first generated workspace, then creates further invites from that established team context.

4) Current workspace forwarding

- If the caller's cwd is already initialized for aw and no explicit source is set, bootstrap creates a one-use invite from the current active team and accepts it into the first generated workspace.
- This is the safe default for adding a template team shape to the team you are already using.

5) BYOT (bring your own team)

- Use `--namespace <domain> --team <slug>` when the team's namespace/domain and controller key live in your environment.
- BYOT includes bringing your own domain; there is no separate supported domain-only bootstrap mode.
- Bootstrap creates/ensures the team in that namespace, invites the first generated workspace, then uses it as the anchor.

Policy guidance:

- Prefer hosted for “get a working team now”.
- Prefer API key or invite when the team already exists.
- Prefer current workspace forwarding when you are already inside the target team.
- Prefer BYOT when you need local control over the team namespace/domain and routing.
- Use `--dry-run` for planning only. The old manual "print commands after installing server state from caller cwd" flow is not coherent and should not be recommended.

## Worktree agents (team.yaml worktrees:)

Worktree agents are an OPTIONAL second layer for codebases where multiple agents will edit in parallel.

- Responsibility workspaces live under agents/<responsibility>/.
- Worktree agents live under worktrees/ and each has its own git worktree checkout and its own .aw/ identity state.

Turn worktree agents on when:

- The work directory is a git repo.
- Multiple agents will change files in parallel.
- You want each agent’s edits isolated until you merge.

Leave it off when:

- Work is non-code.
- Only one agent edits at a time.

Operational note:

- Worktree agents are local-only identities by design; they are for parallel local work, not for global addressability.

## After bootstrap: validate that the team is actually usable

For each agent directory under agents/<responsibility>/:

- Run `aw workspace status` to confirm:
  - the workspace is initialized
  - the active team is correct
  - the identity is present

- Run `aw whoami` to confirm the identity fields are present.

- If you use a wake-up path (Pi extension / Claude Code channel plugin), start it inside the agent directory after initialization.

## Re-run safety and idempotence (how to avoid making a mess)

When iterating on templates or recovering from partial setup:

- Use `--dry-run` first to validate the plan.
- Use `--refresh-template` only when you intend to re-clone over a previous template checkout.
- Treat identity/certificate state under .aw/ as the source of truth; do not delete it casually.
- If you need to create a fresh workspace, do it in a new directory rather than mutating an existing identity in place.

If bootstrap fails mid-way:

- Capture the first failing command and error.
- Do not keep retrying blindly; first confirm whether some workspaces were already created and connected.
- Prefer completing the remaining agent dirs rather than redoing everything.

## Adding agents later

Two common expansions after initial bootstrap:

- Add another responsibility workspace: create a new directory and run `aw init` (or extend your template and bootstrap a new repo).
- Add another isolated code workspace on the same repo: use `aw workspace add-worktree`.

When in doubt, choose the smallest change that preserves existing identities and avoids rewriting certificates.

## References

Read these only when deeper context is needed:

- references/bootstrap-scenarios.md: scenarios, checklists, and troubleshooting.
- https://aweb.ai/docs/team-bootstrap/ : full reference guide.
- docs/team-bootstrap.md (aweb repo checkout): full reference guide.
