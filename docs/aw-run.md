# `aw run`

> **Status: current compatibility launcher.** `aw run` is an opt-in convenience
> for existing provider integrations. For Codex, use the OATS host wake broker
> instead; without OATS, ask Codex to read mail and chat. This launcher is not the communication-first
> activation path, and aweb does not own the launched runtime, process
> lifecycle, or session UX.

Use `aw run` when you deliberately want aweb's provider launcher in the current
directory. Existing agents can instead keep their orchestrator-owned process
and connect through mail, chat, and events.

## Basic Usage

```bash
aw run claude
```

You can seed the first cycle:

```bash
aw run claude --prompt "review this repo and propose the next task"
```

## Wizard Behavior

In a TTY, if the current directory is not initialized yet, `aw run` can guide
you through onboarding before it launches the provider.

It can route you into:

- `aw init` for an existing team when a team certificate is already present under `.aw/team-certs/`
- `aw id team accept-invite <token>` followed by `aw init` when joining a
  team via an invite token

The explicit bootstrap primitives still exist for scripts and expert use. See
[`cli-command-reference.md`](cli-command-reference.md) for the full surface.

## Providers

The launcher retains compatibility with these providers; this is not a
recommendation to use it for Codex delivery:

- `codex`
- `claude`

Provider-specific flags can be forwarded after `--`:

```bash
aw run claude -- --model sonnet
```

## Session Continuity

Use `--continue` to resume the most recent provider session across wake cycles:

```bash
aw run claude --continue
```

When a session exits, `aw run` prints:

- an `aw run --continue ...` command
- the raw provider resume command with the captured session id

That gives you both the `aw`-managed path and the direct provider path.

## Safety Mode

By default, `aw run` launches providers in full-autonomy mode:

- Claude uses `--dangerously-skip-permissions`
- Codex uses `--dangerously-bypass-approvals-and-sandbox`

Use `--trip-on-danger` when you want native provider approvals/sandbox checks
back on:

```bash
aw run claude --trip-on-danger
```

## Common Flags

- `--prompt`: initial prompt for the first provider run
- `--continue`: resume the most recent session
- `--dir`: run against a different working directory
- `--model`: provider model override
- `--allowed-tools`: provider-specific allowlist string
- `--provider-pty`: run the provider inside a PTY when interactive controls are
  available
- `--autofeed-work`: wake for work events as well as mail/chat
- `--max-runs`: stop after a fixed number of cycles
- `--wait`: idle wait per wake-stream cycle
- `--base-prompt`, `--comms-prompt-suffix`, `--work-prompt-suffix`: override
  configured prompt text

- `--trust-config`: trust this directory's `.aw/run.json` as it is now

Use `aw run --init` to write `~/.config/aw/run.json` interactively.

### A directory's own `run.json`

A directory may carry `.aw/run.json` with the same fields. It overrides your
`~/.config/aw/run.json` for runs in that directory, so it can set the agent's
prompts and name background services, which `aw run` starts as shell commands.
A directory you cloned is not one you wrote, so `aw run` uses that file only
after you have trusted it:

```bash
cat .aw/run.json            # read it first
aw run claude --trust-config
```

`--trust-config` records the digest of the file's content in
`~/.config/aw/run-trusted.json` and prints the file's path and that digest, so
you see exactly what you trusted. Trust is of that exact content: if the file
changes, by a pull or by anything else, `aw run` ignores it again until you
trust the new content. When a file is ignored, `aw run` says so, names the
file, and starts with your own configuration.

Pass `--trust-config` by hand, after reading the file. Never put it in a
script, a shell alias or a launcher's default arguments: there it would trust
every future change to the file without anyone reading it.

### Messages whose sender is not verified

Mail and chat are fetched from durable messages before entering the prompt.
When verification is `failed` or `identity_mismatch`, the launcher withholds
the body and subject. It presents the claimed sender, the verification failure,
and an `aw mail show --message-id ...` or `aw chat history --session-id ...`
command for a deliberate read. A claimed sender from any message or event field
is shown only when it is a valid alias, domain/name address, `did:key` or
`did:aw`, using the existing identifier validators. Other labels are omitted. The notice format is shared with the
[autonomous message presentation contract](receiving-events.md#autonomous-message-presentation).
Withheld mail remains unread. Chat omits withheld IDs from its acknowledgement
request. An older server can still apply its compatibility read watermark.

Unsigned, stale, missing and unknown verification results keep a warning next
to the content. A warning does not establish authorship; retry verification
before sensitive work. Verified messages keep their normal reply flow.

A failed history read is reported with a command to fetch the conversation.
An unsigned `last_message` preview from a pending conversation never replaces
that history in the prompt. A wake without a durable reference supplies only
a command to inspect pending messages.

## In-Session Controls

Current built-in slash controls are:

- `/stop`
- `/wait`
- `/resume`
- `/autofeed on`
- `/autofeed off`
- `/quit`

Regular text input becomes the next provider prompt. Dragging a local file path
onto the terminal is also supported:

- images are attached for providers that support image flags
- text files are read and added to the next prompt body

## Coordination-Aware Status

`aw run` is not just a provider wrapper. It also watches project events and can
wake on:

- mail
- chat
- optional work activity

If your workspace has an active claim, the claimed task is included in the run
status line.
