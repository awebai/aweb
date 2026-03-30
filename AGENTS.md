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
