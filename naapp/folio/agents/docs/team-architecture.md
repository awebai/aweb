# Team architecture

This team was created from the `simple-dev-team` blueprint. One page so
every agent — and every human — understands the system they're running.

## Souls and instances

- A **soul** (`agents/souls/<role>/`, committed) is an agent's durable
  body: its `AGENTS.md`, `soul.yaml`, and accumulated docs/decisions/
  memory. Souls hold no identity and grow with the repo.
- An **instance** (`agents/instances/<name>/`, gitignored) is a runnable
  copy of a soul with its **own aweb identity**: a home (body symlinked to
  the soul + `.aw`) and a `work` location. One soul can back many
  instances at once.

`soul.yaml` declares the `work` mode: `main` (symlink to the main
checkout — coordinator, reviewer) or `worktree` (own git worktree on its
own branch — developers).

Aliases: bare role for standing singletons (`coordinator`);
`<role>-<purpose>` for work-specific instances (`developer-authflow`,
`reviewer-pr-7`).

## The roles

| Soul | Work | Runs | Does |
|---|---|---|---|
| **coordinator** | main | standing | turns requests into tasks, drives developers, decides merges |
| **developer** | worktree | per task | implements one task on its own branch; never merges |
| **reviewer** | main | per review | fresh-eyes verdict on a branch: ACK or amendments |

## How work flows

1. The human asks the coordinator; the coordinator writes small tasks.
2. A developer instance implements in its `work/` worktree and reports
   done with evidence.
3. A reviewer instance reads the branch from the main checkout and replies
   over chat: ACK or amendments with `file:line`.
4. The coordinator merges, requests amendments, or escalates to the human.

## Teammates come and go

Instances are created with the `spawn-instance` skill (a connected
instance invites the new identity; dashboard `aw init` is the fallback)
and removed with `retire-instance` (identity, home, worktree, branch).
Spawn on human request or when assigned work needs it — never to "get
help" on your own initiative.

> ⚠️ Never move or rename an instance home after `aw init`; aweb registers
> the workspace at its path.

## Layout

```text
agents/souls/<role>/        committed bodies
agents/roles/<role>.md      role playbooks published to aweb
agents/instructions.md      shared instructions published to aweb
agents/docs/                this doc
agents/instances/<name>/    gitignored homes: .aw + body -> soul + work
.agents/skills/             spawn-instance, retire-instance, self-maintenance
.claude/skills              symlink to .agents/skills (Claude Code)
```

When the team outgrows this — per-commit review with a fresh reviewer per
commit, reviewer skill suites — the `aweb-team-coord-worktrees` blueprint
is the same team with more machinery; graduating is adding skills.
