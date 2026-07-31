## aweb Coordination Rules

This project uses `aw` for coordination.

This file is not the team's active instructions. Run `aw instructions show` for the
authoritative version, which carries sections this file does not.

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
`origin/main` into your branch before handing off, so your reviewer reads it
against current main rather than against a base that has moved.

That merge does **not** by itself make what was reviewed what lands - it is the
step that makes a SHA-identity check insufficient, because the branch keeps its
ACKed tip while its contents change underneath. Before you push, follow "Before
you push to main" in the active team instructions.

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
command's `--body-file` flag.

**The hazard is a mechanism, not a surface.** *Any* shell context that
interpolates will expand backticks and `$(...)` before the program ever sees the
text - and it does so at every layer between your keyboard and the artifact, not
just on the `aw` command line:

```
<<EOF        interpolates          <<'EOF'      does not
printf "..." interpolates          printf '%s'  does not
echo "..."   interpolates          a quoted heredoc into a file  does not
```

Using `--body-file` protects the last layer only. A file written by an *unquoted*
heredoc is already corrupted before `aw` reads it - this has happened here, in a
document about not trusting unreviewed text, and nothing failed: the writer
reported success and the diff reported the expected line count. Both were true and
neither measured the thing that mattered.

**The check is a read-back, not more care.** After writing any file you intend to
publish, read the bytes back and look for the characters you meant to write:

```bash
grep -c '`' <the-written-file>    # non-zero => backticks survived, so the context did not interpolate
```

That works because the corruption and its evidence are the same characters. Note
the asymmetry: a zero is only meaningful if you *meant* to write backticks - for a
file that never had any, "none present" cannot distinguish "I wrote none" from
"the shell ate them", and that absence is not recoverable afterwards.

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
- **avi is not reachable.** `aw workspace status` still lists avi as
  coordinator, but avi has been offline for over 90 days and works in another
  repository (`ai.aweb`). Do not route work there; a stale entry is not an
  absent one.
- **Identity, provisioning, profiles, and the roster: ar** (agent-resources).

If an instruction tells you to consult shared state for who to ask and the
answer is offline or contradicts a live teammate, report the conflict instead
of quietly choosing.
