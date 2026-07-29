## aweb Coordination Rules

This project uses `aw` for coordination.

## Authority

Active team instructions are authoritative for this team's branch and
integration workflow. If a repository or profile copy disagrees, the active
team instructions win and the copy is stale. Stop and report the disagreement
rather than choosing silently.

## Branches and code reviews

Never make work-in-progress or temporary branches. Stay on the worktree and
branch assigned to you.

When you finish a task, stand back and review the code, get an independent
review, and then keep main in sync. Main is the shared branch and divergence is
the thing to avoid.

**Ordinary single-repo work: merge it yourself.** After your reviewer ACKs,
merge your branch to main and merge main back into your branch, from your own
worktree. Do not wait for anyone. Many agents cannot stay coordinated if
integration queues behind one of them.

**Ask the coordinator to integrate when the change spans repositories, cuts a
release tag, or touches production tooling.** There the risk is not your diff
but the combination: two branches can each pass alone and fail together, and a
tag must point at one reviewed commit. The coordinator merges those from a
detached worktree based on `origin/main`, so no working tree is touched and the
combination is built and tested before it lands.

Either way: never merge work your reviewer has not ACKed, and always merge
`origin/main` into your branch before handing off, so what was reviewed is what
lands.

A team without a coordinator self-merges everything; follow your team's active
instructions rather than assuming this split is universal.

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
unread. `aw mail inbox` shows unread only by default, so an empty inbox and an
unreachable one look identical without `--show-all`; `aw chat pending` lists
only waiting conversations, so open each one.

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

## Shell-safe message bodies

For Markdown, reports, or command examples, write the body to a file and use the
command's `--body-file` flag. A shell expands backticks and `$(...)` in a
double-quoted argument before `aw` starts, so `aw` cannot detect text the shell
already replaced.

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

## Who to ask

Roles shown in `aw workspace status` are the profile each agent runs, not who is
currently leading. When the two disagree, this section is the answer.

- **Acting lead coordinator: dev.** dev runs a developer profile and is acting as
  lead coordinator by Juan's assignment. Route coordination, scope questions,
  and handoffs there.
- **avi is not reachable.** `aw workspace status` still lists avi as
  coordinator, but avi has been offline for over 90 days and works in another
  repository (`ai.aweb`). Do not route work there; a stale entry is not an
  absent one.
- **Identity, provisioning, profiles, and the roster: ar** (agent-resources).

If an instruction tells you to consult shared state for who to ask and the
answer is offline or contradicts a live teammate, report the conflict instead
of quietly choosing.
