This project uses **bdh** (beadhub, a wrapper on bd (beads)) for issue tracking.

## Quick Reference

```bash
bdh ready              # Find available work
bdh show <id>          # View issue details
bdh update <id> --status in_progress  # Claim work
bdh close <id>         # Complete work
bdh sync               # Sync with git
bdh :status            # Who am i, and what are other agents working on
```

Commands starting with : like `bdh :status` are for coordination; all other commands like `bdh ready` are passed on directly to bd. Communication between agents is done via the :aweb set of commands, like `bdh :aweb mail ...` and `bdh :aweb chat ...`

## Landing the Plane (Session Completion)

**When ending a work session**, you MUST complete ALL steps below. Work is NOT complete until `git push` succeeds.

**MANDATORY WORKFLOW:**

1. **File issues for remaining work** - Create issues for anything that needs follow-up
2. **Run quality gates** (if code changed) - Tests, linters, builds
3. **Update issue status** - Close finished work, update in-progress items
4. **PUSH TO REMOTE** - This is MANDATORY:
   ```bash
   git pull --rebase
   bdh sync
   git push
   git status  # MUST show "up to date with origin"
   ```
5. **Clean up** - Clear stashes, prune remote branches
6. **Verify** - All changes committed AND pushed
7. **Hand off** - Provide context for next session

**CRITICAL RULES:**
- Work is NOT complete until `git push` succeeds
- NEVER stop before pushing - that leaves work stranded locally
- NEVER say "ready to push when you are" - YOU must push
- If push fails, resolve and retry until it succeeds


## BeadHub Coordination Rules

You have a role, and you are expected to work and coordinate with a team of agents. ALWAYS prioritize the team vs your particular task. NEVER ignore notifications.

Your goal is for the team to succeed in the shared project.

The active project policy (invariants + role playbooks) is shown via `bdh :policy`.

## Start Here (Every Session)

```bash
bdh :policy    # READ CAREFULLY and follow diligently
bdh :status    # who am I? (alias/workspace/role) + team status
bdh ready      # find unblocked work
```

Use `bdh :help` for bdh-specific help.

## Rules

- Default to mail (`bdh :aweb mail list|open|send`) for coordination; use chat (`bdh :aweb chat pending|open|send|history|hang-on`) when you need a conversation with another agent.
- Respond immediately to WAITING notifications — someone is blocked.
- Notifications are for YOU, the agent, not for the human.
- Don't overwrite other agents' work without coordinating first.
- `bdh` derives your identity from the `.beadhub` file in the current worktree. If you run it from another directory you will be impersonating another agent, do not do that.

This project uses `bdh` for multi-agent coordination and issue tracking.

**Start every session:**
```bash
bdh :policy    # READ CAREFULLY and follow diligently, start here now
bdh :status    # your identity + team status
bdh ready      # find unblocked work
```

**Key rules:**
- Use `bdh` (not `bd`) so work is coordinated
- Default to mail (`bdh :aweb mail send <alias> "message"`); use chat (`bdh :aweb chat`) when blocked
- Respond immediately to WAITING notifications
- Prioritize good communication — your goal is for the team to succeed
