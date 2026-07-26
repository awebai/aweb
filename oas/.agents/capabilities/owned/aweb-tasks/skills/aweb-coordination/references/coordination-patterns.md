# aweb Coordination Patterns

## Do the visible thing

When a decision affects another agent, record it in a shared channel:

- Task state for work ownership.
- Mail for durable coordination.
- Locks for exclusive resources.
- Team instructions for durable operating rules.

Private scratch notes are fine for local reasoning, but not for team state.

## Common anti-patterns

### Claiming too broadly

Claiming an epic or large surface area hides work from teammates. Claim the specific task or subtask being worked now.

### Chatting when mail is enough

Chat blocks someone. Use mail for non-blocking requests and handoffs. Reserve chat for synchronous blockers.

### Holding locks as status

A lock is not a claim. Use locks only when concurrent action would be unsafe.

### Silent stalls

If blocked, say so. A stale claim with no comment forces teammates to rediscover state.

## Review handoff template

```text
Please review <branch/commit/scope>.

Scope:
- ...

Risk areas:
- ...

Validation:
- ...

Known gaps:
- ...
```

## Blocker escalation template

```text
Blocked on <issue>.

What I tried:
- ...

Decision or access needed:
- ...

Impact:
- ...
```
