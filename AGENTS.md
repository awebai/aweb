<!-- BEADHUB:START -->
## BeadHub Coordination Rules

This project uses `bdh` for multi-agent coordination and issue tracking, `bdh` is a wrapper on top of `bd` (beads). Commands starting with : like `bdh :status` are managed by `bdh`. Other commands are sent to `bd`.

You are expected to work and coordinate with a team of agents. ALWAYS prioritize the team vs your particular task.

You will see notifications telling you that other agents have written mails or chat messages, or are waiting for you. NEVER ignore notifications. It is rude towards your fellow agents. Do not be rude.

Your goal is for the team to succeed in the shared project.

The active project policy as well as the expected behaviour associated to your role is shown via `bdh :policy`.

## Start Here (Every Session)

```bash
bdh :policy    # READ CAREFULLY and follow diligently
bdh :status    # who am I? (alias/workspace/role) + team status
bdh ready      # find unblocked work
```

Use `bdh :help` for bdh-specific help.

## Rules

- Always use `bdh` (not `bd`) so work is coordinated
- Default to mail (`bdh :aweb mail list|open|send`) for coordination; use chat (`bdh :aweb chat pending|open|send-and-wait|send-and-leave|history|extend-wait`) when you need a conversation with another agent.
- Respond immediately to WAITING notifications — someone is blocked.
- Notifications are for YOU, the agent, not for the human.
- Don't overwrite the work of other agents without coordinating first.
- ALWAYS check what other agents are working on with bdh :status which will tell you which beads they have claimed and what files they are working on (reservations).
- `bdh` derives your identity from the `.beadhub` file in the current worktree. If you run it from another directory you will be impersonating another agent, do not do that.
- Prioritize good communication — your goal is for the team to succeed

## Using mail

Mail is fire-and-forget — use it for status updates, handoffs, and non-blocking questions.

```bash
bdh :aweb mail send <alias> "message"                         # Send a message
bdh :aweb mail send <alias> "message" --subject "API design"  # With subject
bdh :aweb mail list                                           # Check your inbox
bdh :aweb mail open <alias>                                   # Read & acknowledge
```

## Using chat

Chat sessions are persistent per participant pair. Use `--start-conversation` when initiating a new exchange (longer wait timeout).

**Starting a conversation:**
```bash
bdh :aweb chat send-and-wait <alias> "question" --start-conversation
```

**Replying (when someone is waiting for you):**
```bash
bdh :aweb chat send-and-wait <alias> "response"
```

**Final reply (you don't need their answer):**
```bash
bdh :aweb chat send-and-leave <alias> "thanks, got it"
```

**Other commands:**
```bash
bdh :aweb chat pending          # List conversations with unread messages
bdh :aweb chat open <alias>     # Read unread messages
bdh :aweb chat history <alias>  # Full conversation history
bdh :aweb chat extend-wait <alias> "need more time"  # Ask for patience
```
<!-- BEADHUB:END -->
