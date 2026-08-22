# Agent Instructions

## Branches and code reviews

NEVER make work in progress or temp branches. You have been assigned a worktree
and a branch; always stay there and work there.

When you finish a task, stand back and review the code, get an independent
review, and then keep main in sync. Main is the shared branch and divergence is
the thing to avoid.

**Ordinary single-repo work: merge it yourself.** After your reviewer ACKs,
merge your branch to main and merge main back into your branch, from your own
worktree. Do not wait for anyone. Many agents cannot stay coordinated if
integration queues behind one of them.

**Ask the coordinator to integrate when the change spans repositories, cuts a
release tag, or touches production tooling.** There the risk is not your diff
but the *combination*: two branches can each pass alone and fail together, and a
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

A team without a coordinator self-merges everything; follow your team's explicit
instructions rather than assuming this split is universal.

## Database migrations

awid uses a single consolidated migration file
(`awid/src/awid_service/migrations/001_registry.sql`). pgdbm hashes every
applied migration and refuses to boot when the bundled file's checksum
disagrees with the row in `schema_migrations`. So:

- **Every additive schema change is a NEW ordered file** —
  `002_<name>.sql`, `003_<name>.sql`, ...
- **Never edit the existing `001_registry.sql` for schema changes.**
  Comment/whitespace fixes are fine. Anything that alters DDL is not.
- **Editing 001 in place forces a destructive dump-restore cutover.**
  This already happened once: the aala epic added
  `team_certificates.certificate TEXT` by editing 001, which forced
  the awid prod 0.3.1→0.5.1 cutover on 2026-04-25 (see
  `ai.aweb/docs/decisions.md`). Recovery escape hatch is
  `awid/scripts/prod_db_reset.py` + Makefile targets `awid-prod-*`,
  but the cost of needing it is real downtime.

If you genuinely need to fold changes back into a fresh consolidated
001 (e.g. another consolidation pass), that is a planned cutover with
coordination — not a quiet edit. Escalate to coord-aweb (John) or
coord-awid (Goto) before touching the file.

## Tmux safety

- Never create an ad-hoc script or inline cleanup trap that invokes tmux.
- Any tmux-touching dogfood or migration harness must be committed, reviewed,
  and run with `scripts/guard-bin` first on `PATH`.
- Raw tmux reads `TMUX_TMPDIR`, not `AWEB_TMUX_TMPDIR`; confusing them silently
  targets the default socket. Use a named throwaway session on an isolated
  socket and tear down only that session. Never run `tmux kill-server`.

<!-- AWEB:START -->
## aweb Coordination Rules

This project uses `aw` for coordination.

## What we are building right now

**Before you claim anything, put it through these four questions.** Continue work
that passes at least one:

1. Does it improve **mail, identity lifecycle, events, wake-up, delivery
   reliability, or cross-runtime integration**?
2. Is it required for **security, production reliability, or compatibility with
   current users**?
3. Is it necessary to **prove the new activation journey**?
4. Would we still build it if **Library, Team Builder and the app marketplace did
   not exist**?

**Pause** work primarily concerned with: profile-first onboarding; Team Builder;
`aw team admin up` expansion; runtime/home/worktree ownership; app-marketplace growth;
additional first-party naapps; dynamic gateway composition; secrets or audit
expansion unrelated to the wedge; deep service extraction justified only by the
old destination architecture.

Paused does not mean cancelled. Record what you established, then stop — do not
finish it because it is nearly done.

If a task fails all four and you think it should proceed anyway, say so to the
coordinator with the reason rather than proceeding quietly.

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

That merge does **not** by itself make what was reviewed what lands — it is the
step that makes a SHA-identity check insufficient, because the branch keeps its
ACKed tip while its contents change underneath. Before you push, follow
"Before you push to main" below.

A team without a coordinator self-merges everything; follow your team's active
instructions rather than assuming this split is universal.

## Before you push to main

Verifying that main's tip equals the SHA your reviewer ACKed is **not sufficient**.
It verifies one commit, and a fast-forward lands the branch's entire ancestry.
Three commands, three different questions:

```bash
git log --oneline origin/main..<branch>   # WHAT am I adding? Every commit needs an ACK, not just the tip.
git diff origin/main...<branch>           # IS IT WHAT WAS REVIEWED? Three dots. Compare to the reviewer's diff.
git log --oneline <branch>..origin/main   # WOULD I LOSE ANYTHING? Non-empty means main has commits you do not.
```

The **diff** is the strongest of the three, because a reviewer reads a change,
not a commit list. A commit list is an artifact of how work happened to be
arranged; it moves under a merge, a rebase or a squash, none of which change what
lands. Critically, it is the only one of the three that still means something
after you merge `origin/main` into your branch — **the step this process requires
between the ACK and the push, and the step that invalidates a SHA-identity
check.**

**Use three dots, not two.** On a branch that has merged main, `git diff A..B`
includes everyone else's merged work and is not about your change at all — it
will name files you never touched and hide the fact that yours did not change.

**If your branch lands more than once**, `git diff origin/main...HEAD` means
something different each time, because main moves underneath you between
landings. Comparing this landing's cumulative branch diff against a single
earlier ACK compares two different quantities and will look alarming for no
reason. Pair each landing with the delta *its own* ACK covered, and compare those.

### Auditing landings after the fact

Use the base main actually had **at push time** (`git push` prints it), never
today's `origin/main`. The same command run against today's main attributes
everyone else's landings to whoever pushed last. Those false positives look
exactly like the defect you are hunting, and they are *produced by correct
behaviour* — the more diligently you keep your branch current, the worse the
false positive looks.

### For reviewers

**ACK a SHA, and say how many commits you read** — "reviewed `<sha>`, N non-merge
commits". A SHA plus a count is checkable by someone who was not in the
conversation. An ACK attached to *"the change we discussed"* approves a
description, and no mechanical gate can verify it.

**Your suggestion is not pre-approved work**, and it fails in *both* directions.
The author's rendering of it is unseen — but the suggestion itself is also an
unreviewed proposal until someone other than its author has checked it against
the code. A real case: a reviewer proposed adding a `//` comment key to a
`package.json`. JSON has no comments. It was implemented faithfully, and the
faithfulness is exactly what made it feel safe. Do not soften this to "get the
rendering checked".

Suggestions arrive inside ACK mails, which is what makes "land it plus the thing
the reviewer asked for" feel like one action — it is two, and the second has no
reader. **Reviewers: if you bundle a suggestion into a verdict, say explicitly
that it needs its own round.** The author's discipline should not have to cover
your format.

### When unreviewed work has already landed

**Review it in place. Do not revert.** Reverting is for work that is *wrong*, not
for work that is *unreviewed* — the defect is the missing review and the remedy is
the review. A revert puts a conflict in front of everyone who merges main next, to
remove changes that may be perfectly good. Do not ask for a retroactive "glance so
it is covered" ACK either; that is how a review becomes a formality.

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

## Shell-safe message bodies

For Markdown, reports, or command examples, write the body to a file and use the
command's `--body-file` flag.

**The hazard is a mechanism, not a surface.** *Any* shell context that
interpolates will expand backticks and `$(...)` before the program ever sees the
text — and it does so at every layer between your keyboard and the artifact, not
just on the `aw` command line:

```
<<EOF        interpolates          <<'EOF'      does not
printf "..." interpolates          printf '%s'  does not
echo "..."   interpolates          a quoted heredoc into a file  does not
```

Using `--body-file` protects the last layer only. A file written by an *unquoted*
heredoc is already corrupted before `aw` reads it — this has happened here, in a
document about not trusting unreviewed text, and nothing failed: the writer
reported success and the diff reported the expected line count. Both were true and
neither measured the thing that mattered.

**The check is a read-back, not more care.** After writing any file you intend to
publish, read the bytes back and look for the characters you meant to write:

```bash
grep -c '`' <the-written-file>    # non-zero => backticks survived, so the context did not interpolate
```

That works because the corruption and its evidence are the same characters. Note
the asymmetry: a zero is only meaningful if you *meant* to write backticks — for a
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

Do not copy teammate names, presence timestamps, or current availability into
repository or profile instructions. Those facts change independently of the
files and turn a once-correct routing rule into a durable contradiction.
Resolve current responsibility and reachability from the active team
instructions and `aw workspace status`. Follow the responsibility named there;
if no reachable owner is named, ask a reachable coordinator or the human rather
than inferring authority from a stale role or profile.

If a repository or profile copy contradicts active team instructions or live
presence, the active instructions win. Stop and report the stale copy instead
of quietly choosing or editing another teammate's home.
<!-- AWEB:END -->
