# BeadHub Workspace

> Always use `bdh` (not `bd`) — it coordinates work across agents.

**Start every session:**
```bash
bdh :status    # your identity
bdh :policy    # READ AND FOLLOW
bdh ready      # find work
```

**Before ending session:**
```bash
git status && git add <files>
bdh sync --from-main
git commit -m "..."
```

---

# Beads Workflow Context

> **Context Recovery**: Run `bdh prime` after compaction, clear, or new session
> Hooks auto-call this in Claude Code when .beads/ detected

# 🚨 SESSION CLOSE PROTOCOL 🚨

**CRITICAL**: Before saying "done" or "complete", you MUST run this checklist:

```
[ ] 1. git status              (check what changed)
[ ] 2. git add <files>         (stage code changes)
[ ] 3. bdh sync                 (commit beads changes)
[ ] 4. git commit -m "..."     (commit code)
[ ] 5. bdh sync                 (commit any new beads changes)
[ ] 6. git push                (push to remote)
```

**NEVER skip this.** Work is not done until pushed.

## Core Rules
- **Default**: Use beads for ALL task tracking (`bdh create`, `bdh ready`, `bdh close`)
- **Prohibited**: Do NOT use TodoWrite, TaskCreate, or markdown files for task tracking
- **Workflow**: Create beads issue BEFORE writing code, mark in_progress when starting
- Persistence you don't need beats lost context
- Git workflow: hooks auto-sync, run `bdh sync` at session end
- Session management: check `bdh ready` for available work

## Essential Commands

### Finding Work
- `bdh ready` - Show issues ready to work (no blockers)
- `bdh list --status=open` - All open issues
- `bdh list --status=in_progress` - Your active work
- `bdh show <id>` - Detailed issue view with dependencies

### Creating & Updating
- `bdh create --title="..." --type=task|bug|feature --priority=2` - New issue
  - Priority: 0-4 or P0-P4 (0=critical, 2=medium, 4=backlog). NOT "high"/"medium"/"low"
- `bdh update <id> --status=in_progress` - Claim work
- `bdh update <id> --assignee=username` - Assign to someone
- `bdh update <id> --title/--description/--notes/--design` - Update fields inline
- `bdh close <id>` - Mark complete
- `bdh close <id1> <id2> ...` - Close multiple issues at once (more efficient)
- `bdh close <id> --reason="explanation"` - Close with reason
- **Tip**: When creating multiple issues/tasks/epics, use parallel subagents for efficiency
- **WARNING**: Do NOT use `bdh edit` - it opens $EDITOR (vim/nano) which blocks agents

### Dependencies & Blocking
- `bdh dep add <issue> <depends-on>` - Add dependency (issue depends on depends-on)
- `bdh blocked` - Show all blocked issues
- `bdh show <id>` - See what's blocking/blocked by this issue

### Sync & Collaboration
- `bdh sync` - Sync with git remote (run at session end)
- `bdh sync --status` - Check sync status without syncing

### Project Health
- `bdh stats` - Project statistics (open/closed/blocked counts)
- `bdh doctor` - Check for issues (sync problems, missing hooks)

## Common Workflows

**Starting work:**
```bash
bdh ready           # Find available work
bdh show <id>       # Review issue details
bdh update <id> --status=in_progress  # Claim it
```

**Completing work:**
```bash
bdh close <id1> <id2> ...    # Close all completed issues at once
bdh sync                     # Push to remote
```

**Creating dependent work:**
```bash
# Run bdh create commands in parallel (use subagents for many items)
bdh create --title="Implement feature X" --type=feature
bdh create --title="Write tests for X" --type=task
bdh dep add beads-yyy beads-xxx  # Tests depend on Feature (Feature blocks tests)
```
