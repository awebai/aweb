We use main as the sync branch.

Work is done in worktrees.

Every landing goes through the coordinator's per-repository train. Get an
independent review ACK, push your branch, and send a landing request with the
exact head SHA, non-merge commit count and ACK message IDs. The review and
handoff requirements are detailed below; active team instructions govern.

Do not copy teammate names, presence timestamps, or current availability into
repository or profile instructions. Resolve current responsibility and
reachability from the active team instructions and `aw workspace status`.

We use pgdbm (you probably have a skill, it lives in
https://github.com/juanre/pgdbm) for database management.

Never edit existing migrations.

<!-- AWEB:START -->
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

When you finish a task, review your change and get one independent review ACK
on the exact head SHA, with the number of non-merge commits read. Add Athena
when the change touches security, auth, identity or data, and UX when
user-visible screens or words change. Test-only, config-only and tooling
changes need one reviewer.

**Every landing goes through the coordinator's per-repository train.** Authors
push their reviewed branch and send the coordinator a landing request with:

- Repository and branch.
- Exact head SHA and number of non-merge commits over `origin/main`.
- Review ACK message IDs.
- Any required landing order or dependencies.

Resolve the coordinator from active team instructions and `aw workspace status`.
Authors do not merge to main or queue individual whole-suite runs. Focused tests
remain the author's responsibility; whole suites run only in trains under the
shared suite lock. Never hand off unreviewed work.

Merge `origin/main` into your branch before handing off. If the reviewed files
are unchanged, no new ACK is needed; otherwise the same reviewer reads the
delta. The coordinator merges ACKed heads onto current `origin/main` in a
separate integration worktree, checks the three-dot diff matches the reviewed
change and that no main commits are lost, and runs one covering gate for the
repository. A green train lands the heads and reports each landed SHA; a
failing head returns to its author for a fix.

The exact SHA alone does not establish what lands after main moves. Follow
"Before you push to main" in the active team instructions for the coordinator's
integration checks.

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
than choosing silently. When the skill is not installed, this block is the
startup authority on its own; messaging needs neither the skill nor a profile
service.

## Shared Rules

- Use `aw` for coordination work.
- Treat `.aw/workspace.yaml` as the repo-local coordination identity for this worktree.
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --body-file <body-path>`.
- Use chat when you need a synchronous answer: `aw chat pending`, then `aw chat send-and-wait <agent> --body-file <body-path>`.
- Respond promptly to waiting conversations.
- Check `aw workspace status` before doing coordination work.
- Prefer shared coordination state over local TODO notes: `aw work ready` and `aw work active`.
- How notifications reach you depends on the integration your session runs: a native aweb channel, a tool hook, or the host's external wake broker. The active team instructions and your instance briefing name the mechanism in use. Respond promptly when notified; when no delivery mechanism is registered for your session, check `aw mail inbox` and `aw chat pending` yourself at task boundaries.

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

Roles shown in `aw workspace status` are each workspace's current operating responsibility on this team.
In the optional aw profile-materialization path, the profile and role label
remain distinct. Setup initializes `role_name` from the materialized profile, but it remains independently mutable;
changing it does not change which profile the workspace runs or grant additional authority.
Presence shows which workspaces currently carry a responsibility and which are offline.
For OATS-managed homes, consult the soul source and instance briefing for
durable expertise, work mode and the current assignment. A role label does
not establish identity custody or authority in either path.

Do not copy teammate names, presence timestamps, or current availability into repository or profile instructions.
Keep those changing facts and migration schedules out of durable team
instructions too. Resolve current responsibility and reachability from the active team instructions and `aw workspace status`.
Route coordination, scope questions and handoffs to the currently assigned,
reachable owner. If that owner is offline or shared state contradicts a live
teammate, report the conflict rather than silently choosing a replacement.

For lifecycle disposition, inspect the current supported command:
`aw team admin agent-status <name>`. Interpret certificate, workspace and
claim results independently, including any explicit unknown or incomplete
result. A missing local path is not retirement; an offline presence entry
does not establish process absence or abandoned responsibility. Preserve
unaccepted learning and outstanding work until their disposition is recorded.
Retire through the supported lifecycle path only within the operator's
authorization, then verify the resulting state independently.
<!-- AWEB:END -->
