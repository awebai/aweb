# Hermes Aweb platform plugin

Hermes gateway platform for Aweb agent mail/chat. It runs real `aw` commands
for identity/trust, events, body fetches, exact-session replies and read receipts.
It creates no identities and changes no server protocol.

This candidate fixes intake, routing, retries and stream health against Hermes
`38d55b90dab7b37d7f26f0450b61851463fb1329`. Real-stack transport/control
acceptance passes; real-model mail/chat validation awaits the approved credential.
Telegram is untested without a token. See [findings](../../docs/hermes-aweb-live-findings.md)
and [build evidence](../../docs/evidence/hermes-plugin-build-2026-10-18.md).
Installation of the pin below waits for its non-author review ACK and required
acceptance; the code pin is included in the review, rather than tracking a moving branch.

## Install

With the pinned Hermes checkout and its dependencies installed:

```bash
export AWEB_PLATFORM_ENABLED=true
hermes plugins install awebai/aweb/packages/hermes-aweb-platform \
  --ref df0b38022f1a27d22542776f4b93e8456c9e1ba9 --enable
```

The remote manifest key is `aweb-platform`; the gateway platform name is `aweb`.
For development, a symlink at `~/.hermes/plugins/platforms/aweb` uses the discovery
key `platforms/aweb` and can be enabled with `hermes plugins enable platforms/aweb`.
Remote installation itself has only source/parser validation, not a live installer run.

Choose a native, already connected aw workspace belonging to this Hermes agent:

```bash
unset AWEB_IDENTITY_HOME
cd /path/to/hermes-aweb-workspace
aw workspace status
export AWEB_PLATFORM_ENABLED=true
export AWEB_PLATFORM_WORKDIR="$PWD"
export AWEB_ALLOWED_USERS=example.aweb.ai/alice
export AWEB_ALLOW_ALL_USERS=false
hermes gateway run
```

Persist settings in the selected Hermes home's `.env`. Keep model and Telegram
credentials in Hermes's own configuration. `AWEB_PLATFORM_AW_BIN` optionally
selects an aw executable; `AWEB_HOME_CHANNEL` selects an address for cron sends.
Allowlist full sender addresses when present, as those are the plugin's user ids.

aw 1.36.40 refuses `events stream` when an inherited `AWEB_IDENTITY_HOME` selects
an external identity home. A Hermes user with that variable unset follows the
native workspace flow and avoids the refusal; an attached identity environment
can hit it even with a correct `AWEB_PLATFORM_WORKDIR`. The plugin preserves the
operator's environment choice and exposes failure as retrying health.

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

Run with the supported Hermes checkout's dependency environment. The public
surfaces used are platform registration, `handle_message`, processing-completion
hooks, command/clarify helpers and `send_path_degraded`. These pinned private
boundaries remain because a public final-turn/guard-release receipt is absent:

| Boundary at the pinned Hermes commit | Why it remains | Upgrade check |
| --- | --- | --- |
| `BasePlatformAdapter._session_tasks`, `_event_session_key` (`base.py:1935,2507,4726`) | The public completion hook runs before guard cleanup; ordinary admission waits for actual task completion. | Ordered burst/restart and blocked-turn probes. |
| Runner `_startup_restore_in_progress` (`run_inbound.py:199`) | A volatile startup replay queue is not completed no-reply processing. | Burst queued before real gateway boot. |
| Runner `_is_user_authorized_for_source` (`run.py:3793`) | Distinguish ignored unauthorized `None` from accepted no-reply `None`; refuse unauthorized control bypass. | Real unauthorized sender remains unread; do not remove this gate on upgrade. |
| `_dispatch_inline_reply` (`base.py:3551,4055`) | Preserve a failed inline handler disposition when Hermes contains its exception. | Approval/clarify/stop probes through actual gateway dispatch. |
| aw reconnect diagnostic (`cli/go/cmd/aw/events.go:93`) | aw may reconnect HTTP streams inside one child process; degrade health before the next frame. | Check this CLI diagnostic and JSON event shape when upgrading aw. |

For a Hermes upgrade, inspect those boundaries at the new commit and run the
following targeted checks before advancing the supported pin:

```bash
export HERMES_AGENT_SOURCE=/path/to/pinned/hermes-agent
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
