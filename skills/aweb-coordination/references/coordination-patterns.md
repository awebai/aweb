# aweb Coordination Patterns

## Do the visible thing

When a decision affects another agent, record it in a shared channel:

- Mail for durable coordination.
- Locks for exclusive resources.
- Team instructions for durable operating rules.

Private scratch notes are fine for local reasoning, but not for team state.

## Common anti-patterns

### Chatting when mail is enough

Chat blocks someone. Use mail for non-blocking requests and handoffs. Reserve chat for synchronous blockers.

### Holding locks as status

Use locks only when concurrent action would be unsafe.

### Silent stalls

If blocked, say so. Silence forces teammates to rediscover state.

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
