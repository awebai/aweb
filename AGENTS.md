# Agent Instructions

## Branches and code reviews

NEVER make work in progress or temp branches. You have been assigned a worktree
and a branch; always stay there and work there.

When you finish a task, stand back and review the code, get an independent
review, and then keep main in sync. Main is the shared branch and divergence is
the thing to avoid.

**Ordinary single-repo work: merge it yourself.** After your reviewer ACKs,
merge your branch to main and merge main back into your branch, from your own
worktree. Do not wait for anyone. Many agents cannot stay coordinated if
integration queues behind one of them.

**Ask the coordinator to integrate when the change spans repositories, cuts a
release tag, or touches production tooling.** There the risk is not your diff
but the *combination*: two branches can each pass alone and fail together, and a
tag must point at one reviewed commit. The coordinator merges those from a
detached worktree based on `origin/main`, so no working tree is touched and the
combination is built and tested before it lands.

Either way: never merge work your reviewer has not ACKed, and always merge
`origin/main` into your branch before handing off, so what was reviewed is what
lands.

A team without a coordinator self-merges everything; follow your team's explicit
instructions rather than assuming this split is universal.

## Database migrations

awid uses a single consolidated migration file
(`awid/src/awid_service/migrations/001_registry.sql`). pgdbm hashes every
applied migration and refuses to boot when the bundled file's checksum
disagrees with the row in `schema_migrations`. So:

- **Every additive schema change is a NEW ordered file** —
  `002_<name>.sql`, `003_<name>.sql`, ...
- **Never edit the existing `001_registry.sql` for schema changes.**
  Comment/whitespace fixes are fine. Anything that alters DDL is not.
- **Editing 001 in place forces a destructive dump-restore cutover.**
  This already happened once: the aala epic added
  `team_certificates.certificate TEXT` by editing 001, which forced
  the awid prod 0.3.1→0.5.1 cutover on 2026-04-25 (see
  `ai.aweb/docs/decisions.md`). Recovery escape hatch is
  `awid/scripts/prod_db_reset.py` + Makefile targets `awid-prod-*`,
  but the cost of needing it is real downtime.

If you genuinely need to fold changes back into a fresh consolidated
001 (e.g. another consolidation pass), that is a planned cutover with
coordination — not a quiet edit. Escalate to coord-aweb (John) or
coord-awid (Goto) before touching the file.

## Tmux safety

- Never create an ad-hoc script or inline cleanup trap that invokes tmux.
- Any tmux-touching dogfood or migration harness must be committed, reviewed,
  and run with `scripts/guard-bin` first on `PATH`.
- Raw tmux reads `TMUX_TMPDIR`, not `AWEB_TMUX_TMPDIR`; confusing them silently
  targets the default socket. Use a named throwaway session on an isolated
  socket and tear down only that session. Never run `tmux kill-server`.

<!-- AWEB:START -->
## aweb Coordination Rules

This project uses `aw` for coordination.

## Start Here

Run these before claiming new work. The order is deliberate.

```bash
aw workspace status   # who is online, active team, identity, claims, locks
aw mail inbox         # async handoffs, reviews, blockers - process first
aw chat pending       # someone may be blocked waiting on you
aw work ready         # only after the above; pick the smallest actionable item
```

Your inbox and your waiting chats come before the work queue because claiming
first means taking a task while a blocking message or a waiting teammate sits
unread - which is how an agent ends up idle, or working scope that changed hours
ago. `aw mail inbox` shows unread only by default, so an empty inbox and an
unreachable one look identical without `--show-all`; and `aw chat pending` only
lists the waiting conversations - open each one.

This order is canonical and matches the `aweb-coordination` skill. If you find a
different order somewhere else, that other source is stale - say so rather than
following it.

## Shared Rules

- Use `aw` for coordination work
- Treat `.aw/workspace.yaml` as the repo-local coordination identity for this worktree
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --body "..."`
- Use chat when you need a synchronous answer: `aw chat pending`, `aw chat send-and-wait <agent> "..."`
- Respond promptly to WAITING conversations
- Check `aw workspace status` before doing coordination work
- Prefer shared coordination state over local TODO notes: `aw work ready` and `aw work active`
- You will receive automatic chat notifications after each tool call via the PostToolUse hook (`aw notify`). Respond promptly when notified.

## Mail

```bash
aw mail send --to <alias> --body "message"
aw mail send --to <alias> --subject "API design" --body "message"
aw mail inbox
```

## Chat

```bash
aw chat send-and-wait <alias> "question" --start-conversation
aw chat send-and-wait <alias> "response"
aw chat send-and-leave <alias> "thanks, got it"
aw chat pending
aw chat open <alias>
aw chat history <alias>
aw chat extend-wait <alias> "need more time"
```

## Identity

Never run `aw` from another workspace or worktree when doing coordination work.

`aw` derives coordination context from `.aw/workspace.yaml` in the current worktree. Running `aw` from another repo or worktree can impersonate that workspace's agent, causing:

- Messages sent as the wrong agent
- Work claimed under the wrong identity
- Confusion in coordination

## Teamwork

You are part of a team working toward a shared goal. Optimize for the project outcome, not your individual activity.

- Help teammates when they're blocked
- Escalate blockers early rather than spinning alone
- Keep changes small and reviewable so others can build on them

## Who to ask

Roles shown in `aw workspace status` are the profile each agent runs, not who is
currently leading. When the two disagree, this section is the answer.

- **Acting lead coordinator: dev.** dev runs a *developer* profile and is acting as
  lead coordinator by Juan's assignment. Route coordination, scope questions, and
  handoffs there.
- **avi is not reachable.** `aw workspace status` still lists avi as coordinator, but
  avi has been offline for over 90 days and works in a different repository
  (`ai.aweb`). Do not route work there; a stale entry is not an absent one.
- **Identity, provisioning, profiles, and the roster: ar** (agent-resources).

If you are following an instruction that tells you to consult shared state for who
to ask, and the answer you get is offline or contradicts a live teammate, treat that
as a finding and say so - do not quietly pick one.
<!-- AWEB:END -->
