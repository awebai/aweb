We use main as the sync branch.

Work is done in worktrees.

Ordinary single-repo work: merge it yourself. After your reviewer ACKs,
always merge `origin/main` into your branch before handing off, then merge your
branch to main and merge main back into your branch, from your own worktree. Do
not wait for anyone. Many agents cannot stay coordinated if integration queues
behind one of them; never merge work your reviewer has not ACKed.

Ask the coordinator to integrate when the change spans repositories, cuts a
release tag, or touches production tooling.

Do not copy teammate names, presence timestamps, or current availability into
repository or profile instructions. Resolve current responsibility and
reachability from the active team instructions and `aw workspace status`.

We use pgdbm (you probably have a skill, it lives in
https://github.com/juanre/pgdbm) for database management.

Never edit existing migrations.

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

Your inbox and your waiting chats come before the work queue because claiming first
means taking a task while a blocking message or a waiting teammate sits unread.
`aw mail inbox` shows unread only by default, so an empty inbox and an unreachable
one look identical; `aw chat pending` lists only the waiting conversations, so open
each one.

Your waiting chats come before the work queue because claiming first means taking a
task while a blocked teammate sits unread. `aw chat pending` lists only the waiting
conversations - open each one, because a teammate can be blocked on you before you
have started.

The canonical source for this order is the `aweb-coordination` skill. This block
reproduces it so it is available without loading the skill. If the two ever
disagree, the skill wins and this block is stale. Report the conflict rather
than choosing silently.

## Shared Rules

- Use `aw` for coordination work.
- Treat `.aw/workspace.yaml` as the repo-local coordination identity for this worktree.
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --body-file <body-path>`.
- Use chat when you need a synchronous answer: `aw chat pending`, then `aw chat send-and-wait <agent> --body-file <body-path>`.
- Respond promptly to waiting conversations.
- Check `aw workspace status` before doing coordination work.
- Prefer shared coordination state over local TODO notes: `aw work ready` and `aw work active`.
- Automatic chat notifications arrive after tool calls through the PostToolUse hook (`aw notify`); respond promptly when notified.

## Mail

```bash
aw mail send --to <alias> --body-file <body-path>
aw mail send --to <alias> --subject "API design" --body-file <body-path>
aw mail inbox
```

## Chat

```bash
aw chat send-and-wait <alias> --body-file <body-path> --start-conversation
aw chat send-and-wait <alias> --body-file <body-path>
aw chat send-and-leave <alias> --body-file <body-path>
aw chat pending
aw chat open <alias>
aw chat history <alias>
aw chat extend-wait <alias> --body-file <body-path>
```

## Identity

Never run `aw` from another workspace or worktree when doing coordination work.

`aw` derives coordination context from `.aw/workspace.yaml` in the current
worktree. Running it from another repo or worktree can impersonate that
workspace's agent, causing messages from the wrong agent, work claimed under the
wrong identity, and coordination confusion.

## Teamwork

You are part of a team working toward a shared goal. Optimize for the project
outcome, not your individual activity.

- Help teammates when they are blocked.
- Escalate blockers early rather than spinning alone.
- Keep changes small and reviewable so others can build on them.
