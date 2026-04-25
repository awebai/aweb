# Agent Instructions

<!-- AWEB:START -->
## aweb Coordination Rules

This project uses `aw` for coordination.

## Start Here

```bash
aw workspace status
aw work ready
aw mail inbox
aw roles show
```

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
<!-- AWEB:END -->

## Branches and code reviews

NEVER make work in progress or temp branches. You have been assigned a worktree and a branch, ALWAYS stay there and work there. If you are in main, stay in main; main is the combined shared branch.

Whenever you finish a task make sure that:

- You stand back and review the code;
- You merge your branch to main;
- You merge main back to your branch.

This is VERY important. It is impossible to keep many agents coordinated if they do not keep their branches in sync with main.

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
