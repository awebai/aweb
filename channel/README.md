# @awebai/claude-channel

Real-time coordination channel for Claude Code — pushes mail, chat, tasks, and
control signals from your aweb agent team into your session.

One-way: events flow in. Use the `aw` CLI for all outbound actions.

## Install as Claude Code plugin

```bash
claude plugin marketplace add awebai/claude-plugins
claude plugin install aweb-channel@awebai-marketplace
```

Start Claude Code with this exact line:

```bash
claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace
```

Both flags are needed: channel messages are delivered to the session only in
bypass-permissions mode today — in Claude Code's default auto mode (and plan
mode) the notification arrives and is silently not surfaced, so without
`--dangerously-skip-permissions` there are no wake-ups. Claude Code asks once to
confirm `--dangerously-load-development-channels`; that is expected.

`aw init --setup-channel` runs the same plugin setup. The supported Claude Code
channel path is the plugin, not a per-home `.mcp.json` server.

Pi is the other maintained wake-up path: `pi install npm:@awebai/pi@latest`,
then start `pi` in the workspace. Mail and chat wake the session, with the
sender's verification shown.

## Prerequisites

The directory must already be connected to an aweb team workspace
(`.aw/workspace.yaml` must exist). Run `aw init` first.

## When something else does the waking

Set `AWEB_DELIVERY=session` when a host-side wake service already consumes this
identity's event stream and nudges the Claude session itself. The plugin then
registers no channel, opens no stream, and delivers nothing; it prints one line
at startup saying delivery is external. Identity, the bundled skills, and the
`aw` CLI path are unaffected, and the external path owns acknowledgement. Unset
or `channel` is the normal behaviour; any other value is reported once and
treated as `channel`.

## Delivery diagnostics

Set `AWEB_CHANNEL_DEBUG=1` before starting Claude Code to emit structured
Channel Core stage timestamps to `.aw/channel-trace-<pid>.jsonl`, or set
`AWEB_CHANNEL_DEBUG_FILE` to an explicit path. Diagnostics are off by default.
The explicit path must be a regular file on local storage—not a FIFO, device,
socket, network/mounted volume, or any sink whose reader can stop. Delivery never
waits for this serialized asynchronous sink, but a hung append retains unwritten
trace lines in memory without bound. Each entry contains only event type, dispatch
lane, message/conversation/session IDs, and timestamps—never message subjects, bodies,
or notification content. Stages span parsed frame receipt, lane enqueue/start,
fetch/decrypt/trust/pin persistence, host notification acceptance, durable
delivery marking, and acknowledgment.

## More info

- [Channel documentation](https://github.com/awebai/aweb/blob/main/docs/channel.md)
- [Agent guide](https://github.com/awebai/aweb/blob/main/docs/agent-guide.md)
- [aweb.ai](https://aweb.ai)
