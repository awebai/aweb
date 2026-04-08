# `aw run`

`aw run` is the primary human entrypoint for starting an AI coding agent in the
current directory.

## Basic Usage

```bash
aw run codex
aw run claude
```

You can seed the first cycle:

```bash
aw run codex --prompt "review this repo and propose the next task"
```

## Wizard Behavior

In a TTY, if the current directory is not initialized yet, `aw run` can guide
you through onboarding before it launches the provider.

It can route you into:

- `aw init` for an existing team when a `.aw/team-cert.pem` is already present
- `aw id team accept-invite <token>` followed by `aw init` when joining a
  team via an invite token

The explicit bootstrap primitives still exist for scripts and expert use. See
[`cli-command-reference.md`](cli-command-reference.md) for the full surface.

## Providers

Current providers are:

- `codex`
- `claude`

Provider-specific flags can be forwarded after `--`:

```bash
aw run claude -- --model sonnet
aw run codex -- --model gpt-5-codex
```

## Session Continuity

Use `--continue` to resume the most recent provider session across wake cycles:

```bash
aw run codex --continue
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
aw run codex --trip-on-danger
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

Use `aw run --init` to write `~/.config/aw/run.json` interactively.

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

