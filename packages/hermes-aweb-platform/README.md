# Hermes Aweb platform plugin

Hermes gateway platform for Aweb agent mail/chat. It runs real `aw` commands
for identity/trust, events, body fetches, exact-session replies and read receipts.
It creates no identities and changes no server protocol.

Validated Hermes release: **v0.22.2**, upstream commit
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`. Support is limited to this tested
release; a broader version range is not established. The earlier investigation
used `38d55b90dab7b37d7f26f0450b61851463fb1329` on upstream main.
See [build evidence](../../docs/evidence/hermes-plugin-build-2026-10-18.md) and
[model/install evidence](../../docs/evidence/hermes-model-acceptance-2026-10-19.md)
for the separate transport, release and model checks. Telegram is untested.
The code pin below has a non-author code-review ACK; this documentation/evidence
delta still requires its own ACK before merging.

## Install

If you already use Hermes, keep that installation, executable and `HERMES_HOME`
(or its default `~/.hermes`). Install the plugin into that same Hermes home.
If you do not have Hermes, follow
[Hermes's installation guide](https://hermes-agent.nousresearch.com/docs/getting-started/installation).
The validated release remains v0.22.2; a wider version range is not established.

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
team flow, see [add a Hermes agent](../../docs/add-ai-tool.md#hermes).

In that same agent folder, with your existing Hermes and selected `HERMES_HOME`:

```bash
export AWEB_PLATFORM_ENABLED=true
hermes plugins install awebai/aweb/packages/hermes-aweb-platform \
  --ref df0b38022f1a27d22542776f4b93e8456c9e1ba9 --enable
hermes plugins list
hermes config set AWEB_PLATFORM_ENABLED true
hermes config set AWEB_PLATFORM_WORKDIR "$PWD"
hermes config set AWEB_IDENTITY_HOME "$PWD/.aw"
```

`hermes config set` writes these environment settings to `$HERMES_HOME/.env`.
The plugin runs aw with its inherited environment: bind `AWEB_IDENTITY_HOME`
to this agent's `.aw` explicitly. An existing Hermes `.env` overrides shell
exports and can otherwise restore a stale selector despite a correct workdir.
The export before installation also enables platform discovery for that command.

For a **team-only (local) agent**, enable team access:

```bash
hermes config unset AWEB_ALLOWED_USERS
hermes config set AWEB_ALLOW_ALL_USERS true
```

A team-only agent has no public address: it can be reached by its own team, by
people it has added as contacts or has written to, and through any channel you
connect to it. Others can also reply in conversations the agent started. A fresh
agent with no contacts or connected channels is reachable only by its own team.
Use allow-all only for a team-only agent. For an agent with a **public address**,
allowlist the full sender addresses and keep allow-all false:

```bash
hermes config set AWEB_ALLOW_ALL_USERS false
hermes config set AWEB_ALLOWED_USERS example.aweb.ai/alice
```

Replace the example with authorized full addresses, separated by commas when
there is more than one. Optionally select an authorized recipient for cron
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
Without a configured home channel, Hermes can send its missing-home-channel
notice as a visible reply before the model answer; that notice can mark the
input read. Likewise, a clarify prompt is a visible reply: read state does not
mean the model turn has finished. The model acceptance run configured the home
channel.

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
- Authorized `/approve`, `/deny`, `/stop`, `/new`, `/reset`, and pending clarify
  answers reach the actual gateway while another turn waits. Other messages stay ordered.
- Immutable input routes bind each reply and read mark to its triggering input.
  Read follows a persisted reply or accepted no-reply processing. An explicit
  successful stop retires its cancelled input; shutdown cancellation stays unread.
- Failed mail fetches stay retryable. A completed response with a failed read
  mark retries that receipt in this process. A gateway crash can still duplicate
  a committed reply between send and read; no crash-level exactly-once claim is made.
- Runtime health starts retrying until a parsed real stream frame, degrades on
  stream failure, and recovers only after another real frame.
- A full 2000-row unread history window is refused: today's newest-window API
  cannot prove the oldest prefix is present. Server pagination/receipts remain separate work.

Replies use `aw mail reply` or `aw chat send --session-id --leave`; receipts use
`aw mail ack` or per-message `aw chat read`. No media support is provided.
The generic new-target sender uses chat. Telegram-to-aweb request correlation
is separate from this adapter's reply routing.

## Compatibility checks

Run with the supported release checkout's dependency environment. The public
surfaces used are platform registration, `handle_message`, processing-completion
hooks, command/clarify helpers and `send_path_degraded`. These pinned private
boundaries remain because a public final-turn/guard-release receipt is absent:

| Boundary (v0.22.2 source locations) | Why it remains | Upgrade check |
| --- | --- | --- |
| `BasePlatformAdapter._session_tasks`, `_event_session_key` (`base.py:1993,2554,4768`) | The public completion hook runs before guard cleanup; ordinary admission waits for actual task completion. | Ordered burst/restart and blocked-turn probes. |
| Runner `_startup_restore_in_progress` (`run_inbound.py:219`) | A volatile startup replay queue is not completed no-reply processing. | Burst queued before real gateway boot. |
| Runner `_is_user_authorized_for_source` (`run.py:4020`) | Distinguish ignored unauthorized `None` from accepted no-reply `None`; refuse unauthorized control bypass. | Real unauthorized sender remains unread; do not remove this gate on upgrade. |
| `_dispatch_inline_reply` (`base.py:3599`) | Preserve a failed inline handler disposition when Hermes contains its exception. | Approval/clarify/stop probes through actual gateway dispatch. |
| aw reconnect diagnostic (`cli/go/cmd/aw/events.go:93`) | aw may reconnect HTTP streams inside one child process; degrade health before the next frame. | Check this CLI diagnostic and JSON event shape when upgrading aw. |

For a Hermes upgrade, inspect those boundaries at the new commit and run the
following targeted checks before advancing the supported version:

```bash
export HERMES_AGENT_SOURCE=/path/to/supported/hermes-agent
python -m unittest discover -s packages/hermes-aweb-platform/tests \
  -p test_hermes_lifecycle.py -v

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
Fixture commands use Hermes's real clarify/approval primitives without a model;
timing/fault probes hold or drop completed real CLI results, never fabricate
messages or server events. These checks establish transport behavior only.
