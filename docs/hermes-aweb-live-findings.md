# Hermes on aweb: source and live findings

Investigation: aweb-acft.1, 2026-10-18. This supersedes the contract and packaging assumptions in [the prototype memo](hermes-aweb-gateway-integration.md).

## Decision in brief

The intended arrangement is supported by Hermes's architecture: one Hermes gateway can own both its Telegram adapter and an aweb identity. Humans can stay on Telegram while the agent receives aweb mail/chat. It does **not** automatically connect a Telegram conversation to a later aweb reply: Hermes gives the two platforms different sessions. A Telegram-to-aweb request/answer workflow still needs explicit correlation and delivery back to the original Telegram target.

The unchanged aweb plugin did not work against current upstream Hermes. It failed at startup; after the authorized lifecycle fix, real chat was silently dropped because the plugin and server disagreed about the event contract. Separately committed compatibility fixes address those blockers; a subsequent correction retains hints received while a chat drain is finishing. Real local transport now works, including a two-message chat burst and stream-process restart. **No real model reply or Telegram traffic was tested:** no model key or bot token was provisioned. This is not a production-readiness claim.

## Revisions and environment

- Hermes: clean, read-only upstream checkout of [NousResearch/hermes-agent at `38d55b90dab7b37d7f26f0450b61851463fb1329`](https://github.com/NousResearch/hermes-agent/tree/38d55b90dab7b37d7f26f0450b61851463fb1329). All Hermes file:line references below refer to this commit.
- aweb baseline: `b1820f59df40bfd69245074029a9551c133e0b80`; existing prototype originated at `62642c35`.
- Fix commits: `81147d8dc` (lifecycle), `48e76ddde` (chat fallback and real regression), and `9f55f6a4b97987f3f9851671324bd646fddfdbd6` (retain hints received during drain completion). Integrations authorized these after the original no-code briefing; no server changes were made.
- Real CLI: aw **1.36.40**, build commit `0c7b167cace6cf0c2347eff624bc3a87b8117dcf`.
- Python 3.14.8, isolated dependency environment. Hermes refuses wheel distribution; its declared core dependencies were installed into that environment and its unchanged checkout was loaded through `PYTHONPATH`.
- Real `docker-compose.e2e.yml` services: PostgreSQL, Redis, AWID and aweb, project `hermes-acft1`. Local aweb/AWID ports 28180/28110; no Library service was needed. Three real workspace identities: `hermes`, `alice`, `mallory`, team `test:hermes-acft1.test`. No production identity, account or machine was used.
- Only targeted tests ran. No whole suite, new public repository or PR was created.

## Current Hermes contracts

| Question | Finding and pinned source |
| --- | --- |
| Base adapter still supported? | Yes. `BasePlatformAdapter` requires keyword-only `connect(*, is_reconnect=False)`, `disconnect()`, `send(chat_id, content, reply_to=None, metadata=None)` and `get_chat_info(chat_id)`. `send_typing(chat_id, metadata=None)` remains supported. [base.py:2675](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platforms/base.py#L2675), [2925](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platforms/base.py#L2925), [4827](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platforms/base.py#L4827). |
| Registration still supported? | Yes. Actual `PluginContext.register_platform` constructs `PlatformEntry`; every kwarg used by this plugin was accepted by the real registry/factory. [plugins.py:773](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins.py#L773), [platform_registry.py:45](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platform_registry.py#L45). |
| Directory and pip discovery? | User `HERMES_HOME/plugins`, bundled plugins, optional project plugins, and `hermes_agent.plugins` entry points remain supported. Category directories give path-based keys such as `platforms/aweb`; user plugins need enablement. [plugins_discovery.py:72](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_discovery.py#L72), [134](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_discovery.py#L134), [189](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_discovery.py#L189), [297](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_discovery.py#L297). |
| Monorepo installation? | **Supported now.** The parser accepts `owner/repo/path` and URL `#subdir`; install resolves that subdirectory and uses sparse checkout. The old memo's “repo root only” premise is stale. [plugins_cmd.py:294](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_cmd.py#L294), [plugins_cmd_install.py:362](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_cmd_install.py#L362), [plugins_cmd_git.py:219](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/hermes_cli/plugins_cmd_git.py#L219). The real parser resolved our monorepo path correctly. Remote installation itself was not exercised. |
| Telegram and aweb concurrently? | Yes by source: the runner iterates all enabled platforms, wires each adapter, and connects them concurrently. Adapter construction checks the plugin registry first. [run_startup.py:1208](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/run_startup.py#L1208), [1265](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/run_startup.py#L1265), [run_adapters.py:1902](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/run_adapters.py#L1902). Simultaneous Telegram+aweb was not live-tested. |
| Replies stay on the originating platform? | Yes by source: session keys include platform/chat/thread; source provenance selects the delivery adapter. The final sender receives that source's chat id and reply anchor. Real aweb exact-session replies passed. [session.py:686](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/session.py#L686), [authz_mixin.py:295](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/authz_mixin.py#L295), [base.py:4346](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platforms/base.py#L4346). This isolation also means an aweb answer does not automatically return to an earlier Telegram session. |

The rest of the requested method audit found no signature drift: disconnect, send, send_typing and get_chat_info match. The added processing-completion hook matches [base.py:3483](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platforms/base.py#L3483).

## Telegram groups and several Hermes bots

Telegram privacy mode normally restricts group input to relevant commands/replies; admin bots receive broader input. Disabling privacy requires re-adding the bot. Hermes then applies its own group gates: `TELEGRAM_REQUIRE_MENTION` defaults false; exclusive mentions of another bot are excluded by default. These are separate from Telegram's delivery policy. [Telegram privacy documentation](https://core.telegram.org/bots/features#privacy-mode), [Hermes adapter.py:5756](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/plugins/platforms/telegram/adapter.py#L5756), [6379](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/plugins/platforms/telegram/adapter.py#L6379).

“Bots never see bots” is no longer an accurate universal statement. Current Telegram documentation permits command-directed or reply-directed group bot traffic when at least one participant enables Bot-to-Bot Communication Mode. An enabled receiver with admin rights or privacy disabled can also receive general bot chatter. Private bot-to-bot messages require both bots to enable the mode. This was verified in current documentation, not with a bot token. [Telegram bot-to-bot contract](https://core.telegram.org/api/bots/bot-to-bot).

Hermes carries `is_bot` from Telegram input. Its default bot-admission mode is `none`; `TELEGRAM_ALLOW_BOTS=mentions|all` enables the bot bypass of human allowlists (other explicit chat/user grants are also relevant). `TELEGRAM_BOTS_REQUIRE_MENTION=true` suppresses another bot's plain chatter and quote-only replies; that extra gate defaults false and free-response/guest branches can bypass it. Own-message echoes are dropped. A separate default loop budget admits at most 20 bot inputs in 300 seconds, then cools the conversation for 600 seconds. These controls reduce loops; they do not create a shared agent conversation or prove an arbitrary workflow terminates. [Telegram adapter.py:875](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/plugins/platforms/telegram/adapter.py#L875), [5774](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/plugins/platforms/telegram/adapter.py#L5774), [6136](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/plugins/platforms/telegram/adapter.py#L6136), [6358](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/plugins/platforms/telegram/adapter.py#L6358), [authz_mixin.py:564](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/authz_mixin.py#L564), [617](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/authz_mixin.py#L617), [bot_loop_guard.py:22](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/bot_loop_guard.py#L22).

## Live results

Full identifiers, timestamps, red/green evidence and commands are in [the evidence record](evidence/hermes-live-2026-10-18.md).

| Check | Result |
| --- | --- |
| Unchanged plugin, real Hermes gateway | **Failed:** `connect()` rejected `is_reconnect`; zero connected platforms. |
| Fixed plugin discovery/connection/real stream | **Passed** using a native local workspace with `AWEB_IDENTITY_HOME` unset. |
| Real inbound mail to Hermes | **Passed.** Normal mail reached actual model construction, which failed because no provider credential existed. Its visible configuration-error reply is not model evidence. |
| Mail transport reply then ack | **Passed** with real Hermes `/help`, empty subject: reply persisted at `23:50:02.286354Z`, inbound read at `23:50:02.290361Z`. No model was involved. |
| Original chat behavior after lifecycle fix | **Failed:** real session-summary event had no `message_id`, and no input reached Hermes. |
| Chat fallback, two unread inputs | **Passed:** separate `/help` events, oldest first, exactly two replies in their original session, each read after its reply. |
| Stream restart mid-burst | **Passed:** a real PostgreSQL row lock held the second receipt; the `aw` child was terminated, a replacement child appeared, and new input subsequently received a reply through that replacement stream. No duplicate burst replies. |
| No-reply acceptance | **Passed:** real `/start` completed without a reply and received a per-message read receipt. |
| Unauthorized sender | **Passed for mail:** `mallory` was ignored by real Hermes authorization before model creation; its mail remained unread and received no reply. Allowlisting uses the full event address when available. |
| Cheap real model reply | **Untested:** Juan must provide an approved model credential. No paid/free provider call succeeded. |
| Telegram+aweb request/answer | **Untested:** no bot token. Static concurrent-adapter support does not prove the optional cross-platform workflow. |

The test deliberately kills the **stream subprocess**, not the gateway between reply and read. It does not establish arbitrary crash-level exactly-once execution.

## Root causes, fixes and remaining limits

1. **Hermes lifecycle mismatch — fixed.** Hermes [run_adapters.py:204](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/run_adapters.py#L204) always supplies `is_reconnect`, including cold boot. Baseline plugin `adapter.py:121` accepted no keyword. The fix adopts the current keyword-only signature. A test calling the actual Hermes lifecycle failed first for both initial and reconnect calls, then passed; it also registers through actual `PluginContext`.

2. **Plugin/server chat event disagreement — fixed with a bounded fallback.** [server routes/events.py:275](../server/src/aweb/routes/events.py#L275) emits a session summary without `message_id`. Baseline plugin `adapter.py:267` returned immediately without one. The fallback in [adapter.py:272](../packages/hermes-aweb-platform/adapter.py#L272) fetches unread history without marking it read, processes every returned message oldest first in a separate lane per session, and waits for the actual Hermes processing task before advancing. Exact-session replies and per-message read receipts remain explicit. The real-stack regression was shown to fail before this change.

3. **Startup queue is not completed processing — handled in the fallback.** Hermes [run_inbound.py:199](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/run_inbound.py#L199) queues input during restore and returns `None`; its [startup queue](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/run_startup.py#L117) is process memory. The real test exposed that as an early receipt with no reply. The fallback waits for that gate to open. It currently depends on private Hermes readiness/task fields as well as the public processing-completion hook; a public awaited processing receipt would be a better upstream adapter contract.

4. **External identity-home mode — documented, not changed.** aw 1.36.40 rejects `events stream` when `AWEB_IDENTITY_HOME` selects an external home. The plugin inherits environment and supplies only `cwd` to its subprocess ([adapter.py:166](../packages/hermes-aweb-platform/adapter.py#L166)). The refusal was reproduced; the gateway still reported “connected” while the stream exited repeatedly. A normal user starting Hermes from a shell without that variable follows the native-workspace path and avoids the refusal. An OATS/attached-identity environment can hit it despite following the old workdir recipe. The prepared flow explicitly unsets it. Proper external-home support belongs in aw; clearing it silently inside the plugin would conceal an authority-selection choice.

5. **History ceiling — unresolved.** [history endpoint](../server/src/aweb/routes/chat.py#L1850) caps the response at 2000 and [its query](../server/src/aweb/messaging/chat.py#L631) returns the newest window, without pagination. The fallback refuses a full 2000-row window because older unread input may be missing; below that boundary it drains all unread in order. It does not claim an unbounded oldest-first guarantee. The durable fix is an oldest-first unread cursor, not repeated newest-window reads.

6. **Crash exactly-once — unresolved.** Reply send and read are separate commands in [adapter.py:401](../packages/hermes-aweb-platform/adapter.py#L401). A gateway crash after a visible send but before its read receipt can replay the input and duplicate the reply. A `message_id` event alone cannot remove that gap. An idempotent send keyed by source message plus a durable processing/delivery receipt would be needed for that guarantee. No gateway-crash experiment or such protocol change was made here.

7. **Other existing source-level gaps, not claimed as live reproductions.** Mail marks `_seen` before fetching ([adapter.py:234](../packages/hermes-aweb-platform/adapter.py#L234)), so a fetch failure can suppress reconnect replay within that process; I would retain retryability until successful delivery. Mail routes are mutable per conversation while Hermes `handle_message()` schedules background work ([base.py:3989](https://github.com/NousResearch/hermes-agent/blob/38d55b90dab7b37d7f26f0450b61851463fb1329/gateway/platforms/base.py#L3989)); I would bind replies to their triggering message rather than the latest conversation route. The adapter declares connection health before a live event ([adapter.py:129](../packages/hermes-aweb-platform/adapter.py#L129)); I would expose stream failure/recovery separately. These were not fixed under the limited compatibility authorization.

**Durable event-contract recommendation:** yes, server-side per-message actionable chat identifiers would be preferable to this adapter fallback, provided they enumerate all unread messages and preserve replay/order. Add oldest-first unread pagination and explicit receipt semantics; merely attaching the latest id to a summary would still lose bursts. Route that protocol proposal to the protocol expert. No server contract was changed here.

## Packaging and prepared install flow

Keep the plugin in the existing aweb repository initially. Hermes now supports monorepo subdirectories, so a separate repository is not required for a clean CLI install. A split repository would add release/ownership work without removing the compatibility issues. A pip entry point is supported but would need Python packaging that this directory does not currently ship. A bundled-plugin PR should follow real-model/Telegram validation and maintainer interest; no upstream PR was prepared for publication.

After independent review, this exact compatibility snapshot can be installed as follows. This is a **prepared investigation flow**, not a recommendation to deploy the unvalidated model path:

```bash
export AWEB_PLATFORM_ENABLED=true
hermes plugins install awebai/aweb/packages/hermes-aweb-platform \
  --ref 9f55f6a4b97987f3f9851671324bd646fddfdbd6 --enable
```

The installed manifest name is `aweb-platform`; the platform registry/config name is `aweb`. A local symlink at `plugins/platforms/aweb` instead uses the discovery key `platforms/aweb`.

Choose an already connected native aweb workspace belonging to this Hermes agent. Confirm it from that directory, then start Hermes:

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

Persist those settings in the selected Hermes home's `.env` for subsequent runs, and configure a real model with `hermes model` when its credential is provided. Keep Telegram's existing bot token and allowlist in Hermes's own credential configuration. Do not put credentials in this plugin's files or in aweb mail.

A model asked on Telegram to send **mail** needs an explicit mail-capable tool such as `aw --identity-home /path/to/hermes-aweb-workspace mail send ...`; the plugin's generic new-target sender currently uses chat, not mail ([adapter.py:433](../packages/hermes-aweb-platform/adapter.py#L433)). Returning an asynchronous answer to Telegram also needs the original Telegram destination and request correlation. Those are the remaining workflow questions for the token/model-enabled experiment, not evidence already established by loading two platforms.

## Handoff status

Three compatibility commits plus this findings/evidence commit are submitted for non-author exact-SHA review through integrations. The real-model acceptance item and optional Telegram leg remain open. Nothing should be described as fully live-validated until those missing checks run.

Knowledge consulted: `aweb/aweb-protocol-expert/lessons/delivery-receipts-and-stream-health.md@b1820f59df40` (transport sends, host acceptance and stream health are different facts).
