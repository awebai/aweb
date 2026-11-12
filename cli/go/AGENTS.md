<!-- AWEB:START -->
## aweb Coordination Rules

This project uses `aw` for coordination.

This file is not the team's active instructions. Run `aw instructions show` for the
authoritative version, which carries sections this file does not.

## Start Here

Run these at the start of each session. Order is deliberate: inspect the team,
then handle waiting mail and chat so a handoff, blocker, or waiting teammate
does not go unnoticed.

```bash
aw workspace status   # who is online, active team, identity, locks
aw mail inbox         # async handoffs, reviews, blockers — process first
aw chat pending       # someone may be blocked waiting on you
```

If `aw workspace status` reports the directory is not bound to a team (no `.aw/workspace.yaml`, no certificate, etc.), stop and load `aweb-team-membership` before doing coordination work.

The canonical source for this order is the `aweb-coordination` skill. This block
reproduces it so it is available without loading the skill. If the two ever
disagree, the skill wins and this block is stale. Report the conflict rather
than choosing silently. When the skill is not installed, this block is the
startup authority on its own; messaging needs neither the skill nor a profile
service.

This team tracks its work in aweb tasks: after the loop, follow the `aweb-tasks`
skill's ready/active loop (`aw work ready`, `aw work active`) before claiming.

## Shared Rules

- Use `aw` for coordination work
- Select the acting identity with `--identity-home`, then `AWEB_IDENTITY_HOME`, then the current directory's `.aw`
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --subject "<subject>" --body-file <body-path>` starts a new thread; answer in the conversation with `aw mail reply <message-id> --body-file <body-path>`
- Use chat when you need a synchronous answer: `aw chat pending`, `aw chat send-and-wait <agent> --body-file <body-path>`
- Respond promptly to WAITING conversations
- Check `aw workspace status` before doing coordination work
- Prefer shared coordination state over local TODO notes: `aw work ready` and `aw work active`
- Wake-ups arrive by the deployment's mechanism: the native channel (the Claude Code `aweb-channel` plugin or the Pi extension), the PostToolUse hook (`aw notify`) where configured, or the host wake broker (`aw wake`, session delivery). Current shared-core session delivery presents message content with its sender trust status and records delivery before acknowledging mail/chat where its capabilities permit. This acknowledges presentation, not completion of the requested work. Read injected metadata and continue the existing thread; for hint-only delivery, fetch the durable message by ID. After uncertain crash/compaction, recover known IDs with `aw mail show --message-id <id> --json`, or paginate `aw mail inbox --show-all --json` using `next_cursor`/`--cursor` through the uncertain interval. For chat, use `aw chat history --session-id <session-id> --json`, adding `--message-id <message-id>` for an exact message. Without an exact ID, history is bounded (default 1000), includes read and unread messages, and does not establish completeness beyond its limit. Reconcile with durable task/state and side-effect receipts before retrying actions. Unread inbox and pending chat remain the normal checks for newly waiting comms; empty results do not establish that previously delivered work is complete. Respond promptly when woken.

## Shell-safe message bodies

Write message bodies to a file using a quoted heredoc (`<<'EOF'`), read the
file back, then pass it with `--body-file` in a separate command. Quoting the
heredoc preserves backticks and `$(...)` literally; `--body-file` cannot repair
text already expanded by the shell. Continue received mail with
`aw mail reply <message-id>` to preserve its thread.

## Mail

```bash
aw mail send --to <alias> --subject "<subject>" --body-file <body-path>
aw mail reply <message-id> --body-file <body-path>
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

`aw` selects the acting identity from `--identity-home`, otherwise
`AWEB_IDENTITY_HOME`, otherwise the current directory's `.aw`. A selected
identity that cannot be loaded fails; it never falls back to the checkout's
identity. See `docs/cli-identity-selection.md` for the full contract.

In an OATS seat, run `aw` from the assigned instance home. Use `--identity-home`
only when deliberately acting through another authorized identity. Repository
work stays in the assigned worktree. Check `aw whoami` and `aw workspace status`
before coordinating.

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
