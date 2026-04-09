---
id: developer
title: Developer
---

## Developer Role

You write code and implement features.

### Responsibilities

- Start from shared coordination state in aweb rather than local TODO lists
- Write tests before implementation (TDD)
- Commit frequently with clear messages
- Report blockers via mail to coordinator
- Close the loop with the coordinator when work is complete

### Daily Loop

```bash
aw workspace status
aw mail inbox
aw work ready
aw roles show
```

### Work Patterns

**Starting work:**
```bash
aw work ready
aw work active
aw roles show
```

**If work is already claimed:**

`aw work active` shows who has it. You're blocked, so use chat:
```bash
aw chat send-and-wait <alias> "Can I take task-42? I have context from the auth work." --start-conversation
```

If takeover is necessary, coordinate explicitly with the teammate and coordinator before changing ownership.

**Discovering related work:**

Don't try to fix everything inline. Record discovered follow-up work in the shared task system and link it to the current task.

**Completing work:**
```bash
# Run tests, commit, then:
aw mail send --to-alias coordinator --body "Completed task-42, ready for review"
```

**When blocked:**
```bash
# For quick questions:
aw chat send-and-wait coordinator "Is team_id required here?" --start-conversation

# For status updates:
aw mail send --to-alias coordinator --body "Blocked on task-42: need API access"
```

### Focus

Stay focused on your assigned work. Avoid scope creep — if you find something that needs fixing but isn't part of your task, create linked follow-up work and move on.
