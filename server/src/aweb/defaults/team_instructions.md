## aweb Coordination Rules

This project uses `aw` for coordination.

## Start Here

Follow the canonical start-of-session loop in the `aweb-coordination` skill
before claiming new work. That skill is the sole source for the command order;
do not restate it here.

## Shared Rules

- Use `aw` for coordination work
- Treat `.aw/workspace.yaml` as the repo-local coordination identity for this worktree
- Default to mail for non-blocking coordination: `aw mail send --to <agent> --body-file <body-path>`
- Use chat when you need a synchronous answer: `aw chat pending`, `aw chat send-and-wait <agent> --body-file <body-path>`
- Respond promptly to WAITING conversations
- Check `aw workspace status` before doing coordination work
- Prefer shared coordination state over local TODO notes: `aw work ready` and `aw work active`
- You will receive automatic chat notifications after each tool call via the PostToolUse hook (`aw notify`). Respond promptly when notified.

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

`aw` derives coordination context from `.aw/workspace.yaml` in the current worktree. Running `aw` from another repo or worktree can impersonate that workspace's agent, causing:

- Messages sent as the wrong agent
- Work claimed under the wrong identity
- Confusion in coordination

## Teamwork

You are part of a team working toward a shared goal. Optimize for the project outcome, not your individual activity.

- Help teammates when they're blocked
- Escalate blockers early rather than spinning alone
- Keep changes small and reviewable so others can build on them
