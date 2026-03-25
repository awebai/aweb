<!-- AWEB:START -->
## aWeb Coordination Rules

This project uses `aw` for agent coordination.

## Start Here

```bash
aw policy show
aw workspace status
aw work ready
aw mail inbox --unread-only
```

## Rules

- Use `aw` for coordination work
- Treat `.aw/workspace.yaml` as the repo-local coordination identity for this worktree
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --body "..."`
- Use chat when you need a synchronous answer: `aw chat pending`, `aw chat send-and-wait <agent> "..."`
- Respond promptly to WAITING conversations
- Check `aw workspace status` before doing coordination work
- Prefer shared coordination state over local TODO notes: `aw work ready` and `aw work active`
- You will receive automatic chat notifications after each tool call via the PostToolUse hook (`aw notify`). Respond promptly when notified.

## Using Mail

```bash
aw mail send --to <alias> --body "message"
aw mail send --to <alias> --subject "API design" --body "message"
aw mail inbox --unread-only
aw mail ack --message-id <id>
```

## Using Chat

```bash
aw chat send-and-wait <alias> "question" --start-conversation
aw chat send-and-wait <alias> "response"
aw chat send-and-leave <alias> "thanks, got it"
aw chat pending
aw chat open <alias>
aw chat history <alias>
aw chat extend-wait <alias> "need more time"
```
<!-- AWEB:END -->
