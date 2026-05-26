---
name: aweb-bootstrap
description: This skill should be used when helping a human create or join an aweb team from a template (aw team bootstrap), choosing a template and team source (hosted new team, BYOT, API key, invite, or current workspace forwarding), selecting work-directory vs work-repo-url, provisioning optional worktree agents, and validating/re-running bootstrap safely.
allowed-tools: "Bash(aw *)"
---

# aweb Bootstrap

Use this skill when a human wants to create or extend an aweb team from a reusable template, and you need to guide them through `aw team bootstrap` decisions and validation.

This skill is about **mental model + decision policy + safe execution**, not memorizing flags.

Related skills:

- For day-to-day coordination once the team exists: `aweb-coordination`
- For mail/chat response policy: `aweb-messaging`
- For joining an existing team, multi-team membership, custody, addressability, and contacts: `aweb-team-membership`

Long-form reference: docs/team-bootstrap.md in the aweb repo.

## Mental model: what bootstrap is assembling

`aw team bootstrap` combines four separate things that are easy to confuse:

1) Template repo — the blueprint.

- Contains `team.yaml`, role playbooks, shared instructions, and `agents/<responsibility>/AGENTS.md` files.
- The template says what responsibilities should exist and which `role_name` each should use.

2) Work directory or work repo — the thing agents work on.

- `--work-directory` points at an existing folder.
- `--work-repo-url` clones a repo into `<template>/worktrees/<derived-name>/` and uses that clone as the work directory.
- Each responsibility workspace gets this directory symlinked as `./work`.

3) Team source — the authority/context the generated agents join.

- Hosted new team, existing hosted team via `AWEB_API_KEY`, explicit `--invite-token`, current workspace forwarding, or BYOT.
- Exactly one explicit source is allowed. If no explicit source is set and cwd is already an aw workspace, bootstrap forwards that current team. If no current workspace exists and the run is interactive, bootstrap creates a hosted team. Non-interactive runs need an explicit source.

4) Generated workspaces — the identities that will act.

- Each `agents/<responsibility>/` directory becomes an aw workspace with its own identity and team certificate.
- The **first generated plan** is the anchor: bootstrap connects it first, installs roles/instructions from that workspace's team context, then invites/connects the rest.
- Do not assume a responsibility named `implementation` is special. The anchor is the first plan the CLI generated.

Aweb team source terms:

- Hosted new team: aweb.ai creates/hosts the team.
- API key: joins the hosted team represented by `AWEB_API_KEY`; `--aweb-url`/`AWEB_URL` is optional and defaults to hosted aweb.ai.
- Invite token: first generated workspace accepts an existing invite.
- Current workspace forwarding: caller cwd already has `.aw`; bootstrap creates a one-use invite from that active team.
- BYOT: bring your own team. This includes bringing your own domain/namespace and controller key. Do not describe a separate domain-only bootstrap mode.

## Bootstrap vs join (first decision)

Bootstrap when:

- You are creating a brand-new team from a template.
- You are extending an existing team with a template-defined set of agent workspaces, roles, and instructions.
- You want reproducible setup for multiple agents/workspaces.
- You want a “one command resolves the team source + installs roles + provisions agent dirs” flow.

Do NOT bootstrap when:

- The team already exists and you just need to add yourself: use `aweb-team-membership` and the `aw id team ...` commands.
- You only need another workspace for yourself: use `aw workspace add-worktree` (git worktree) or create another directory and `aw init` it.

## Pick a template (what team shape are we creating?)

Canonical templates:

- awebai/aweb-team-dev-review (2 agents)
  Use when you want the smallest meaningful team: implementation + review.

- awebai/aweb-team-company-surfaces (6 agents)
  Use when you want a cross-functional team: direction/engineering/operations/support/outreach/analytics.

Fork/edit vs use-as-is:

- Use as-is to learn the flow or to run a standard team.
- Clone or fork when you want to customize roles, responsibilities, or instructions before provisioning.
- It is safe to edit the template checkout before applying it; `aw team bootstrap` reads `team.yaml`, `roles/`, `docs/`, and `agents/` from the local template directory at run time.

## Customizing a template before applying it

When the human wants different agents, role playbooks, names, or instructions, do not try to patch the generated workspaces after bootstrap. Clone/edit the template first, then bootstrap the edited local directory.

Typical safe flow:

```bash
git clone https://github.com/awebai/aweb-team-dev-review.git my-team-template
cd my-team-template
# edit team.yaml, roles/*.md, docs/team.md, agents/<responsibility>/AGENTS.md
aw team bootstrap . --dry-run --work-directory /path/to/work
aw team bootstrap . --work-directory /path/to/work
```

What to edit:

- `team.yaml` roles: add/remove role names and point each to a role file.
- `team.yaml` agents: add/remove responsibility workspaces and set each `role_name`, `default_name`, and `default_alias`.
- `team.yaml` worktrees: add/remove local git-worktree agents for code work.
- `roles/*.md`: change operational playbooks installed with `aw roles`.
- `docs/team.md`: change shared team instructions installed after the anchor connects.
- `agents/<responsibility>/AGENTS.md`: change per-workspace startup context.

Default agent names are accepted automatically. Only use `--ask-for-agent-names` when a human specifically wants an interactive rename prompt during bootstrap.

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

Non-dry-run bootstrap needs one coherent team source. This is the most important decision: it determines which team owns the roles, instructions, tasks, mail, chat, and membership certificates created during bootstrap.

Resolution order:

- If any explicit source is set (`AWEB_API_KEY`, `--invite-token`, `--username`, or `--namespace/--team`), do not set another explicit source.
- If no explicit source is set and cwd is an initialized aw workspace, bootstrap forwards the current active team.
- If no explicit source is set, cwd is not an aw workspace, and the run is interactive, bootstrap creates/uses a hosted team through onboarding prompts.
- If no source can be resolved, stop and ask the human which team source to use.

The first generated agent workspace is the anchor: bootstrap connects it first, installs roles/instructions from that workspace's team context, then invites/connects the remaining agents and any declared worktree agents.

Supported sources:

1) Hosted new team (aweb.ai)

- Best for first-time teams.
- Use `--username <name>` or run interactively in a TTY.
- Bootstrap uses the same hosted onboarding path as `aw init` for the first generated workspace.

2) Existing hosted team via API key

- If `AWEB_API_KEY` is set, bootstrap joins the API key's hosted team.
- `--aweb-url`/`AWEB_URL` is optional; when omitted, the hosted aweb.ai default is used. Set it only to target a non-default stack.
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

Decision recipe:

- Human says “make me a new team” and has no existing aw context: use hosted (`--username` or interactive prompt).
- Human has a dashboard/API key: use `AWEB_API_KEY=... aw team bootstrap ...`; do not ask for `AWEB_URL` unless they are using a non-default stack.
- Human pasted an invite: use `--invite-token`.
- Human is already inside the team workspace that should own the new agents: use current workspace forwarding (no explicit source).
- Human controls a namespace/domain and wants the team under that namespace: use BYOT (`--namespace` + `--team`).

Policy guidance:

- Prefer hosted for “get a working team now”.
- Prefer API key or invite when the team already exists but the caller is not already inside it.
- Prefer current workspace forwarding when you are already inside the target team.
- Prefer BYOT when you need local control over the team namespace/domain and routing.
- Use `--dry-run` for planning only. It prints the resolved plan (template ref, work directory, team source, generated workspaces) without writing identities, files, or server state. Do not pair it with side-effecting flags expecting partial provisioning.

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
