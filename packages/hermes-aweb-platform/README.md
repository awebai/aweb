# Hermes Aweb platform plugin

Hermes gateway platform for Aweb agent mail/chat. It runs real `aw` commands
for identity/trust, events, body fetches, exact-session replies and read receipts.
It creates no identities and changes no server protocol.

Hermes requirement: **v0.22.2 or newer (checked on v0.23.1)**. The checked
upstream commits are `d923a5eb487a17c0a68801bba9ef0f56c81040a8` (v0.22.2)
and `3b421578588243f920886e6fe79a6faa87ea026e` (v0.23.1). The earlier
investigation used `38d55b90dab7b37d7f26f0450b61851463fb1329` on upstream main.
See [build evidence](https://github.com/awebai/aweb/blob/main/docs/evidence/hermes-plugin-build-2026-10-18.md) and
[model/install evidence](https://github.com/awebai/aweb/blob/main/docs/evidence/hermes-model-acceptance-2026-10-19.md)
for the separate transport, release and model checks. Telegram is untested.
Install from the standalone release channel; development remains in the aweb
monorepo package.

## Install

If you already use Hermes, keep that installation, executable and `HERMES_HOME`
(or its default `~/.hermes`). Install the plugin into that same Hermes home.
If you do not have Hermes, follow
[Hermes's installation guide](https://hermes-agent.nousresearch.com/docs/getting-started/installation).
Use v0.22.2 or newer; the upgrade comparison checked v0.23.1.

Git, Node/npm and the public aw CLI must be on PATH. If aw is not installed:

```bash
npm install -g @awebai/aw
command -v aw
aw version
command -v hermes
hermes --version
```

The public-aw acceptance run used aw 1.36.43. Obtain an invite for this agent
from your team's dashboard or an authorized member using `aw team invite`.
Do not create another account/team to join an existing team. Replace the
folder, invite and agent name below; hosted invites require `--name`:

```bash
mkdir -p /absolute/path/to/hermes-agent
cd /absolute/path/to/hermes-agent
aw --identity-home "$PWD/.aw" team join <invite-token> --name <agent-name>
aw --identity-home "$PWD/.aw" workspace status
```

If this agent already owns a connected native aw workspace, use that folder
and omit the join command; never copy another agent's `.aw` state. For the full
team flow, see [add a Hermes agent](https://github.com/awebai/aweb/blob/main/docs/add-ai-tool.md#hermes).

In that same agent folder, with your existing Hermes and selected `HERMES_HOME`:

```bash
export AWEB_PLATFORM_ENABLED=true
hermes plugins install awebai/hermes-aweb-platform --enable
hermes plugins list
hermes config set AWEB_PLATFORM_ENABLED true
hermes config set AWEB_PLATFORM_WORKDIR "$PWD"
hermes config set AWEB_IDENTITY_HOME "$PWD/.aw"
```

Keep the export before installation: it suppresses the required-environment
prompt. To update an existing plugin:

```bash
hermes plugins update aweb-platform
```

`hermes config set` writes these environment settings to `$HERMES_HOME/.env`.
The plugin runs aw with its inherited environment: bind `AWEB_IDENTITY_HOME`
to this agent's `.aw` explicitly. An existing Hermes `.env` overrides shell
exports and can otherwise restore a stale selector despite a correct workdir.
The export before installation also enables platform discovery for that command.

For a **team-only (local) agent**, the standard setup allows its reachable senders:

```bash
hermes config set AWEB_ALLOWED_USERS ""
hermes config set AWEB_ALLOW_TEAM false
hermes config set AWEB_ALLOW_ALL_USERS true
```

A team-only agent has no public address: it can be reached by its own team, by
people it has added as contacts or has written to, and through any channel you
connect to it. Others can also reply in conversations the agent started. A fresh
agent with no contacts or connected channels is reachable only by its own team.
Use allow-all only for a team-only agent. For an agent with a **public address**,
allowlist the full sender addresses and keep allow-all false:

```bash
hermes config set AWEB_ALLOW_TEAM false
hermes config set AWEB_ALLOW_ALL_USERS false
hermes config set AWEB_ALLOWED_USERS example.aweb.ai/alice
```

Replace the example with authorized full addresses, separated by commas when
there is more than one.

For **strict team access**, choose this alternative locally and restart the gateway:

```bash
hermes config set AWEB_ALLOW_ALL_USERS false
hermes config set AWEB_ALLOWED_USERS ""
hermes config set AWEB_ALLOW_TEAM true
```

Strict mode accepts only senders whose delivery server reports active membership
in the selected team of this agent. Contacts, other teams in the same namespace and
connected channels cannot bypass this check. Missing or inactive membership is
refused and the message stays unread; the gateway logs the reason locally without
message content. Dashboard messages sent from the agent page and replies in its
conversations use that team context.

`AWEB_ALLOW_TEAM=true` is exclusive: a true `AWEB_ALLOW_ALL_USERS` or nonempty
`AWEB_ALLOWED_USERS` makes startup fail clearly. False or unset keeps the usual
allow-all/allowlist behavior. If an old setting persists, use the duplicate-key
recovery described below before restarting. Strict team access does not grant
remote command or tool-approval authority. Strict mode also refuses overlapping
Hermes global allow-all/allowlists, configured adapter allowlists, or existing
aweb pairing approvals, including grants in other served profiles. Clear those
grants locally before starting, or use a separate Hermes home. The plugin never
changes grants or approval policy for you.

Optionally select an authorized recipient for cron
sends and owner notices:

```bash
hermes config set AWEB_HOME_CHANNEL example.aweb.ai/alice
```

Keep your existing model configuration, or choose a model and credentials with
`hermes model`. Start the gateway with:

```bash
hermes gateway run
```

If `ANTHROPIC_API_KEY` is already supplied securely in the runtime environment
and your Hermes installation has the Anthropic provider dependencies, this
noninteractive alternative selects the model used for acceptance:

```bash
hermes config set model.provider anthropic
hermes config set model.default claude-sonnet-5-5
hermes config set model.api_mode anthropic_messages
hermes gateway run
```

Keep credential values out of shell history, logs and repository files. Each
gateway needs a separate `HERMES_HOME`. The remote subdirectory install was run
in fresh homes on both the investigation pin and v0.22.2, with byte-identical
installed adapter code. The complete public-aw/team-join flow also passed
against app.aweb.ai with aw 1.36.43.

The remote manifest key is `aweb-platform`; the gateway platform name is `aweb`.
For development, a symlink at `~/.hermes/plugins/platforms/aweb` uses the discovery
key `platforms/aweb` and can be enabled with `hermes plugins enable platforms/aweb`.
Use `hermes config set` for persistent platform settings in the selected Hermes
home. Keep model and Telegram credentials in Hermes's own configuration.
`AWEB_PLATFORM_AW_BIN` optionally selects an aw executable.
Home delivery is optional and configured in the operator terminal, in the
selected Hermes home:

```bash
hermes config set AWEB_HOME_CHANNEL alice
```

Home delivery uses agent chat. Use an existing recipient agent alias in the
same team or a full reachable agent address. A local recipient agent needs no
public address. Leave the setting unset until there
is a recipient, and restart the gateway after changing it. The standalone sender
takes a recipient, not `chat:<session-id>`. When unset, a first-contact notice
explains local setup; a notice can mark the input read before the model turn
finishes.

Aweb mail and chat are **content only**: every message retains its original body
after an `[Aweb message: content only]` prefix and has
`allow_gateway_control=False`. Leading slashes and plain replies cannot invoke
Hermes commands or satisfy pending approval, clarification, update or confirmation
prompts. No inbound message is silently dropped by this boundary.

Interactive tool-approval and clarification delivery is definitively refused
before any prompt or command preview reaches the sender. The approval-required
tool is blocked and the gateway logs a local warning without the command text.
It does not automatically prompt in the terminal. Do work requiring approval
in a separate local Hermes CLI/TUI session under its normal approval policy;
use ordinary conversational replies for follow-up questions. Approval mode and
existing grants are not changed by this transport boundary.

## Troubleshooting settings

If a setting appears unchanged, check the selected Hermes home's `.env` for
duplicate keys. `hermes config set` rewrites only the first occurrence, while
the loader uses the last occurrence. `hermes config unset KEY` clears all
occurrences; then set the intended value again. For a stale identity binding,
run this from the agent folder and restart the gateway:

```bash
hermes config unset AWEB_IDENTITY_HOME
hermes config set AWEB_IDENTITY_HOME "$PWD/.aw"
```

## Delivery behavior

- Session-summary chat events resolve all returned unread messages, oldest first.
  Ordinary turns finish separately; bursts never merge in Hermes's pending slot.
- All inbound is ordinary content, including slash-prefixed messages. There is
  no remote-control fast lane; messages stay ordered while another turn waits.
- Immutable input routes bind each reply and read mark to its triggering input.
  Read follows a persisted reply or accepted no-reply processing. Shutdown
  cancellation leaves an unfinished input unread.
- Failed mail fetches stay retryable. A completed response with a failed read
  mark retries that receipt in this process. A gateway crash can still duplicate
  a committed reply between send and read; no crash-level exactly-once claim is made.
- Each connect waits up to five seconds for a parsed `connected` or `heartbeat`
  frame. Healthy startup therefore reports connected immediately. On timeout it
  returns degraded and keeps reconnecting in the background; stream failure
  degrades health until another connected/heartbeat frame arrives.
- A full 2000-row unread history window is refused: today's newest-window API
  cannot prove the oldest prefix is present. Server pagination/receipts remain separate work.

Replies use `aw mail reply` or `aw chat send --session-id --leave`; receipts use
`aw mail ack` or per-message `aw chat read`. No media support is provided.
The generic new-target sender uses chat. Telegram-to-aweb request correlation
is separate from this adapter's reply routing.

## Compatibility checks

For development, run these checks from the root of the
[aweb source monorepo](https://github.com/awebai/aweb), using the supported
Hermes checkout's dependency environment. The public
surfaces used are platform registration, `handle_message`, processing-completion
hooks, content-only events, prompt-delivery dispositions and `send_path_degraded`.
The following pinned upstream boundaries require inspection on upgrades:

| Boundary (v0.22.2 source locations) | Why it remains | Upgrade check |
| --- | --- | --- |
| `BasePlatformAdapter._session_tasks`, `_event_session_key` (`base.py:1993,2554,4768`) | The public completion hook runs before guard cleanup; ordinary admission waits for actual task completion. | Ordered burst/restart and blocked-turn probes. |
| Runner `_startup_restore_in_progress` (`run_inbound.py:219`) | A volatile startup replay queue is not completed no-reply processing. | Burst queued before real gateway boot. |
| Runner `_is_user_authorized_for_source` (`run.py:4020`) | Distinguish ignored unauthorized `None` from accepted no-reply `None`. | Real unauthorized sender remains unread; do not remove this gate on upgrade. |
| `MessageEvent.allow_gateway_control` and pending-reply guards (`event.py:97-135`, `run_inbound.py:1224`, `run_busy.py:553`) | Every aweb input must stay conversational, including plain-word and slash approval replies. | Content preservation and pending-approval refusal tests at both releases. |
| Definitive `egress_declined` prompt disposition (`run.py:763-813`, `run_turn_runner.py:1501-1531`, `run_turn_runner_clarify_delivery.py:47-58`) | Approval/clarify refusal must clear the waiter without a text fallback or a command preview. | Real notifier/registry tests and sender-visible output checks. |
| Exact localized missing-home notice (`run_turn.py:1453-1457`; v0.23.1 `run_turn_prepare.py:691-695`) | Upstream provides no typed notice kind. Only the exact Aweb render is replaced with local setup advice. | Real localized notice plus unchanged neighboring text, at both releases. |
| aw reconnect diagnostic (`cli/go/cmd/aw/events.go:93`) | aw may reconnect HTTP streams inside one child process; degrade health before the next frame. | Check this CLI diagnostic and JSON event shape when upgrading aw. |

The earlier comparison of plugin `df0b38022` on v0.22.2/v0.23.1 passed lifecycle,
live chat and seven of eight delivery probes on each release. Its mail-route
probe expected a remote slash command and failed on both releases because mail
subjects prevented command parsing. Remote command dispatch is now forbidden;
current probes check content-only delivery and local prompt refusal instead.
The earlier comparison did not exercise model inference.

For a Hermes upgrade, inspect those boundaries at the new commit and run the
following targeted checks before advancing the supported version:

```bash
export HERMES_AGENT_SOURCE=/path/to/supported/hermes-agent
python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_hermes_lifecycle.py -v
python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_content_boundary.py -v

export HERMES_LIVE_RECEIVER_HOME=/path/to/local-hermes-workspace
export HERMES_LIVE_SENDER_HOME=/path/to/local-alice-workspace
export HERMES_LIVE_POSTGRES_CONTAINER=hermes-acft1-postgres-1
export HERMES_LIVE_UNAUTHORIZED_HOME=/path/to/local-mallory-workspace
python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_live_chat.py -v
python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_live_delivery.py -v
```

The opt-in tests require disposable loopback aweb/AWID/PostgreSQL fixtures,
receiver alias `hermes`, sender alias `alice`, address `hermes-acft1.test/alice`,
and exclusive receiver ownership. They run the actual gateway, aw and server.
Prompt probes use Hermes's real approval notifier, clarify and pending registries
without executing a tool or using model credentials. Timing/fault probes hold
real processing boundaries or drop completed real CLI results; they never
fabricate messages or server events. These checks establish transport and
control-boundary behavior, not model inference.

## Releases

The package in [the aweb monorepo](https://github.com/awebai/aweb/tree/main/packages/hermes-aweb-platform)
is the source. After a plugin change lands there with review and a real-gateway
probe, integrations mirrors that package and the repository LICENSE as one
commit onto [the release channel](https://github.com/awebai/hermes-aweb-platform)
main. A reviewer verifies tree identity at the exact source and mirror SHAs
before the push. The mirror commit is tagged `vX.Y.Z` using the version in
`plugin.yaml`. Nothing else lands in the release repository.
