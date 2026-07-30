<!-- AWEB:START -->
## aweb Coordination Rules

This project uses `aw` for coordination.

This file is not the team's active instructions. Run `aw instructions show` for the
authoritative version, which carries sections this file does not.

## Start Here

Run these before claiming new work. The order is deliberate.

```bash
aw workspace status   # who is online, active team, identity, claims, locks
aw mail inbox         # async handoffs, reviews, blockers - process first
aw chat pending       # someone may be blocked waiting on you
aw work ready         # only after the above; pick the smallest actionable item
```

Your inbox and your waiting chats come before the work queue because claiming
first means taking a task while a blocking message or a waiting teammate sits
unread - which is how an agent ends up idle, or working scope that changed hours
ago. `aw mail inbox` shows unread only by default, so an empty inbox and an
unreachable one look identical without `--show-all`; and `aw chat pending` only
lists the waiting conversations - open each one.

This order is canonical and matches the `aweb-coordination` skill. If you find a
different order somewhere else, that other source is stale - say so rather than
following it.

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

## Who to ask

Roles shown in `aw workspace status` are each workspace's current operating
responsibility on this team. Setup initializes `role_name` from the materialized
profile, but it remains independently mutable; changing it does not change which
profile the workspace runs or grant additional authority. Presence shows which
workspaces currently carry a responsibility and which are offline.

- **Coordination, scope questions and handoffs: alice.** Route them there.
- **dev is not reachable and its home is hands-off.** Presence shows dev offline
  (last seen 2026-07-28), and dev is retired by Juan's authorization: do not
  refresh, restart, retire, or touch dev's home or its runtime. Earlier
  instructions named dev acting lead coordinator; that is stale. Note dev's
  `role_name` reads `coordinator` while its profile is `developer` - those are
  independent fields, and only the profile decides what a home materializes, so
  an enumeration keyed on `role_name` will misclassify it.
- **avi is not reachable.** `aw workspace status` still lists avi as coordinator, but
  avi has been offline for over 90 days and works in a different repository
  (`ai.aweb`). Do not route work there; a stale entry is not an absent one.
- **Identity, provisioning, profiles, and the roster: ar** (agent-resources).

If you are following an instruction that tells you to consult shared state for who
to ask, and the answer you get is offline or contradicts a live teammate, treat that
as a finding and say so - do not quietly pick one.
<!-- AWEB:END -->
