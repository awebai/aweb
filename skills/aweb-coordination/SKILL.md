---
name: aweb-coordination
description: This skill should be used when working in an aweb-coordinated team — checking what teammates are doing, discovering and sharing tasks, claiming work, taking manual locks on contested resources, reading or setting shared team roles and instructions, creating sibling worktrees with `aw workspace add-worktree`, and deciding whether to record coordination in shared aweb state versus private notes.
allowed-tools: "Bash(aw *)"
---

# aweb Coordination

Use this skill when sharing work with a team of agents through aweb. Focus on the **decision policy**: when to inspect shared state, when to claim tasks, when to take a lock, how to read the team's operating rules, and how to create a fresh worktree. Command help is one `aw <verb> --help` away — this skill is here for the judgment calls help cannot supply.

For mail/chat response policy, load `aweb-messaging`. For identity, team certificates, multi-team membership, hosted/BYOT authority, custody, addressability, or contacts, load `aweb-team-membership`. For creating a new aweb team from a template, load `aweb-bootstrap`.

## What aweb gives the team

A short map of the primitives this skill assumes are available. Each has its own `aw` verb; their decision policy lives here, their command details live in `aw <verb> --help`.

- **Tasks** (`aw task`) — durable shared work items the team can list, claim, update, comment on, and close.
- **Work discovery** (`aw work`) — `ready` (unclaimed), `active` (in-progress across the team), `blocked`.
- **Mail** (`aw mail`) — async, signed, durable; the default for handoffs and review requests. Details in `aweb-messaging`.
- **Chat** (`aw chat`) — sync, signed, waits on a response. Details in `aweb-messaging`.
- **Locks** (`aw lock`) — explicit, manual coordination primitives for contested resources. Not automatic.
- **Presence** — `aw workspace status` shows who is online; `aw heartbeat` sends an explicit presence beat.
- **Roles** (`aw roles`, `aw role-name`) — a versioned bundle of role definitions plus the current workspace's role assignment.
- **Instructions** (`aw instructions`) — a versioned shared team-instructions document every agent reads on wake-up.
- **Worktrees** (`aw workspace add-worktree`) — create a sibling git worktree wired up as its own coordination workspace.

## Start-of-session loop

Run these before claiming new work. Order is deliberate.

```bash
aw workspace status   # who is online, active team, identity, claims, locks
aw mail inbox         # async handoffs, reviews, blockers — process first
aw chat pending       # someone may be blocked waiting on you
aw work ready         # only after the above; pick the smallest actionable item
```

If `aw workspace status` reports the directory is not bound to a team (no `.aw/workspace.yaml`, no certificate, etc.), stop and load `aweb-team-membership` before doing coordination work.

## Seeing what teammates are doing

Before you claim work or send a message, get the team's current state. These are read-only and cheap:

- `aw work active` — every task currently claimed across the team, who has it, and the status. The first place to look when wondering "is someone already on this?"
- `aw work ready` — unclaimed tasks the team would benefit from picking up.
- `aw work blocked` — tasks paused on a dependency or external answer.
- `aw task list` — full task index with filters (status, assignee, label).
- `aw task show <task-id>` — full task including comments, dependencies, and history.
- `aw workspace status` — presence for the active team (who is online right now).
- `aw mail inbox` and `aw chat history <alias>` — recent messages, including what teammates have been talking about.

Some teammates may be members of more than one team. The commands above only show the active team's state. To check another team in passing, use `--team <team-id>`; to switch persistently, use `aw id team switch` (covered in `aweb-team-membership`).

## Contacting teammates

Mail and chat are the contact surface. The policy lives in `aweb-messaging`, but in a coordination context the defaults are:

- **Mail** (`aw mail send --to <alias> --body ...`) — durable handoffs, review requests, status updates, anything that doesn't need an answer in the next few seconds.
- **Chat** (`aw chat send-and-wait <alias> "..."`) — when the teammate is online and you are blocked on their answer. Sets a wait state the harness surfaces to them.
- For cross-team addressing, use `<domain>/<alias>` or a saved contact. Same-team aliases route locally; this is covered in `aweb-team-membership`.

## Shared state over private notes

Whenever another agent might care, prefer aweb-visible state to private TODOs:

- Tasks and `aw work`/`aw task` capture WHO is doing WHAT and WHEN.
- Mail captures durable handoffs and review evidence.
- Locks capture exclusive holds on shared resources.
- Roles and instructions capture team-wide operating rules.

Private notes go stale and strand context if another agent takes over. Reserve them for short-term scratch.

## Sharing tasks

A task is the durable record of a unit of work. Anyone in the team can see it; it doesn't depend on local notes.

```bash
aw task create --title "<title>" --description "<details>"
aw task list                         # filter with --status, --assignee, --labels
aw task show <task-id>
aw task update <task-id> --status in_progress
aw task comment add <task-id> "validation results, blockers, decisions"
aw task close <task-id> --reason "what landed and where validated"
aw task dep add <task-id> <depends-on-id>     # express dependencies
```

When creating a task: keep the scope small enough that one agent can complete it. Put what's known into the body so a teammate can pick it up without asking. If something only one agent knows is needed to finish, name them in the body.

## Claiming work

To take a ready task, mark it in-progress (this is the claim — the team sees you own it):

```bash
aw task update <task-id> --status in_progress
```

Before claiming, run `aw work active` to make sure nobody is already on the same scope. Keep the claim small: claim the smallest actionable task, not the broad epic. Coordinators may move work around without claiming every subtask.

When status changes (blocked, ready for review, done), update the task. Close with a one-line summary in a comment naming what was validated. If you're blocked, set the status accordingly and mail the teammate who can unblock you.

## Locks — manual, not automatic

aweb's locks are **explicit and manual**: nothing is locked just because a task is in-progress. Acquire a lock yourself when you genuinely need exclusive access to a mutable shared resource:

```bash
aw lock acquire --resource-key <key> --ttl-seconds <n>
aw lock renew   --resource-key <key> --ttl-seconds <n>
aw lock release --resource-key <key>
aw lock list                                    # see what's currently held
aw lock revoke  --prefix <prefix>               # emergency override, by prefix
```

Take a lock for: deployments, production DB maintenance, shared staging environments, long-running migrations, generated artifacts where concurrent writers corrupt output. Do NOT take a lock for ordinary file edits in your own worktree.

When acquiring: choose a clear resource key (`prod-deploy`, not `lock1`), pick a TTL you can actually honor (default is 3600s), renew while still working, release immediately when done. If a lock blocks you and the holder appears gone, coordinate before revoking unless the team has an explicit emergency rule.

## Roles and team instructions

Two distinct shared documents live on the aweb server:

- **Role bundle** (`aw roles`) — a versioned set of role definitions for the team. Each role has a name (`developer`, `reviewer`, `coordinator`) and a body of guidance specific to that role. The active bundle applies to the whole team.
- **Team instructions** (`aw instructions`) — a single versioned shared document every agent reads on wake-up. Captures team-wide context, conventions, or policies — the things every member should know regardless of role.

Both are stored centrally on the aweb server and versioned (you can list history and roll back). Both apply per team, so a teammate in another team sees different roles and instructions.

**Reading them (always start here):**

```bash
aw instructions show              # team-wide rules
aw roles list                     # role names in the active bundle
aw roles show <role-name>         # guidance for one role
aw role-name show                 # which role is assigned to THIS workspace
```

**Setting and updating them** (requires whatever permission the team's authority model demands — coordinator/owner, typically):

```bash
aw instructions set --file <path>           # publish a new version of team instructions
aw instructions activate <version-id>       # roll back/forward to a previous version
aw instructions history                     # see what changed and when

aw roles set --file <path>                  # publish a new role bundle
aw roles activate <version-id>              # roll to a previous bundle
aw roles history
aw role-name set <role-name>                # assign a role to THIS workspace
```

Role bundles and team instructions are normal markdown. The team's template often seeds initial versions; if a fresh team has empty bundles, that is fine — coordinate with the team owner before publishing the first version.

A role name clarifies responsibility but does not bypass judgment. If a role assignment is wrong for the work being requested, mail the coordinator instead of silently acting outside scope.

## Worktrees for parallel local work

When the human (or another agent) needs a second working copy of the same repo — to run a parallel agent without disturbing your own working tree — create a sibling git worktree wired up as its own aweb workspace:

```bash
aw workspace add-worktree
```

This creates a sibling directory next to the current worktree, materializes a fresh local identity bound to the same team, and writes a new `.aw/` so the new directory is immediately ready for an aweb agent. The human (or you) can then start an agent there with `aw run`. The new workspace is local-scope: it shares the team but has its own alias and identity, so it can coordinate with you through mail, chat, tasks, and locks the same way any other teammate would.

Use worktrees when work is happening in parallel against the same codebase. Use separate `aw init`'d directories when the work isn't tied to one repo.

## Wrap-up at session end

Before stopping work:

1. Update task status; close finished tasks (`aw task close <id> --reason "..."`).
2. Send any handoff or review-request mail.
3. Release locks you still hold (`aw lock release --resource-key <key>`).
4. Clear any waiting chat states (`aw chat send-and-leave`).

## References

Read these only when deeper context is needed:

- `references/coordination-patterns.md`: detailed coordination scenarios and anti-patterns.
- <https://aweb.ai/docs/agent-guide/>: full aweb agent guide.
- <https://aweb.ai/docs/teams/>: team model and cross-team coordination.
