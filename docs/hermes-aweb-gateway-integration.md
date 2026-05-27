# Hermes Aweb gateway integration memo

## Recommendation

Build an Aweb **Hermes gateway platform plugin**, not a docs-only recipe and not a Hermes core fork. Hermes has a first-class third-party platform-plugin path:

- directory plugin: `~/.hermes/plugins/platforms/<name>/{plugin.yaml,__init__.py,adapter.py}`;
- bundled plugin: `plugins/platforms/<name>/` in Hermes;
- pip plugin: `hermes_agent.plugins` entry point;
- registration through `ctx.register_platform(...)`;
- runtime creation through `gateway.platform_registry.PlatformRegistry` before Hermes falls back to built-in adapters.

Aweb should start as an external Aweb-owned plugin, then optionally propose a small Hermes PR after it is proven. The current prototype lives at `packages/hermes-aweb-platform/`.

## Hermes contract actually used

From Hermes:

- `gateway/platforms/ADDING_A_PLATFORM.md`
- `website/docs/developer-guide/adding-platform-adapters.md`
- `gateway/platforms/base.py`
- `gateway/platform_registry.py`
- reference plugins:
  - `plugins/platforms/irc/adapter.py`
  - `plugins/platforms/ntfy/adapter.py`
  - `plugins/platforms/simplex/adapter.py`

A platform adapter must subclass `BasePlatformAdapter` and implement:

- `connect() -> bool`
- `disconnect() -> None`
- `send(chat_id, content, reply_to=None, metadata=None) -> SendResult`
- `send_typing(chat_id, metadata=None)`
- `get_chat_info(chat_id) -> dict`

Inbound messages are normalized as `MessageEvent` with a `SessionSource` created via `self.build_source(...)`, then delivered with `await self.handle_message(event)`.

The plugin registers with:

```python
ctx.register_platform(
    name="aweb",
    label="Aweb",
    adapter_factory=lambda cfg: AwebAdapter(cfg),
    check_fn=check_requirements,
    validate_config=validate_config,
    is_connected=is_connected,
    env_enablement_fn=_env_enablement,
    cron_deliver_env_var="AWEB_HOME_CHANNEL",
    standalone_sender_fn=_standalone_send,
    allowed_users_env="AWEB_ALLOWED_USERS",
    allow_all_env="AWEB_ALLOW_ALL_USERS",
    platform_hint="...",
)
```

Hermes then handles platform config parsing, status display, user authorization, setup menu inclusion, channel directory enumeration, prompt hints, `send_message` routing, and cron delivery hooks.

## Aweb surface consumed

The MVP deliberately consumes the `aw` CLI rather than reimplementing Aweb auth or signing in Python:

- inbound event stream: `aw events stream --json`
- fetch mail body: `aw mail show --message-id <id> --json`
- fetch chat body: `aw chat history --session-id <id> --message-id <id> --limit 1 --json`
- reply to mail: `aw mail reply <message-id> --plaintext --body-file <tmp> --json`
- reply to chat: `aw chat send-and-leave --plaintext <sender-address-or-alias> <body> --json`
- ack mail after confirmed send: `aw mail ack <message-id> --json`
- mark chat read after confirmed send: `aw chat read --session-id <id> --message-id <id> --json`

Using `aw` keeps workspace selection, DID signatures, team certs, hosted/BYOT routing, and plaintext/E2EE policy inside Aweb.

## Aweb gap found and closed

Before this work, Aweb had event streaming and message body fetches but did not expose precise machine commands for post-delivery acknowledgement:

- `aw mail inbox` marks all listed unread mail read as a side effect.
- `aw chat open <alias>` marks unread messages read by alias/session resolution.

That is not safe enough for a gateway adapter because Hermes should ack/read only after it has delivered the message to the agent and sent a visible response. This change adds:

- `aw mail ack <message-id> --json`
- `aw chat read --session-id <session-id> --message-id <message-id> --json`

These wrap existing client/server primitives (`AckMessage`, `ChatMarkRead`) with explicit CLI contracts.

## Prototype implementation

Files:

- `packages/hermes-aweb-platform/plugin.yaml`
- `packages/hermes-aweb-platform/__init__.py`
- `packages/hermes-aweb-platform/adapter.py`
- `packages/hermes-aweb-platform/README.md`
- `packages/hermes-aweb-platform/tests/test_adapter.py`

Runtime behavior:

1. `connect()` validates `aw`, records `AWEB_PLATFORM_WORKDIR`, starts `aw events stream --json` as a subprocess, and reconnects with backoff.
2. On `actionable_mail`, the adapter fetches the exact message with `aw mail show --message-id`, creates `chat_id="mail:<conversation_id>"`, stores a reply route, and injects a Hermes `MessageEvent`.
3. On `actionable_chat`, the adapter fetches the exact message with `aw chat history --session-id --message-id`, creates `chat_id="chat:<session_id>"`, stores a reply route, and injects a Hermes `MessageEvent`.
4. When Hermes calls `send()`:
   - mail routes use `aw mail reply`, then `aw mail ack` only after the reply succeeds;
   - chat routes use `aw chat send-and-leave`, then `aw chat read` only after the reply succeeds;
   - unknown/home routes are treated as Aweb chat targets for cron delivery.

## MVP user flow

1. Create or choose an Aweb workspace identity for the Hermes gateway:

   ```bash
   cd /path/to/hermes-aweb-workspace
   aw init   # or aw team bootstrap / invite accept / existing workspace setup
   aw workspace status
   ```

2. Install the plugin into Hermes for local testing:

   ```bash
   mkdir -p ~/.hermes/plugins/platforms
   ln -s /path/to/aweb/packages/hermes-aweb-platform ~/.hermes/plugins/platforms/aweb
   hermes plugins enable platforms/aweb
   ```

3. Configure:

   ```bash
   AWEB_PLATFORM_ENABLED=true
   AWEB_PLATFORM_WORKDIR=/path/to/hermes-aweb-workspace
   AWEB_PLATFORM_AW_BIN=aw
   AWEB_ALLOWED_USERS=example.aweb.ai/alice
   # or for development only:
   # AWEB_ALLOW_ALL_USERS=true
   ```

4. Start Hermes gateway:

   ```bash
   hermes gateway restart
   hermes gateway status
   ```

5. Send Aweb mail/chat to the Hermes workspace alias. Hermes receives it as platform input and replies through Aweb.

## Packaging/install story

Truthful current state:

- The prototype is a Hermes directory plugin.
- Hermes `hermes plugins install owner/repo` clones a whole repo and expects `plugin.yaml` at repo root; it does not support installing a subdirectory from a monorepo.
- Therefore a clean public install should be one of:
  1. split this plugin into a small repo such as `awebai/hermes-aweb-platform`, installable with `hermes plugins install awebai/hermes-aweb-platform --enable`; or
  2. publish a Python package with a `hermes_agent.plugins` entry point; or
  3. propose it as a bundled Hermes plugin under `plugins/platforms/aweb/` after external validation.

Recommended order: external repo first, then Hermes bundled-plugin PR only if maintainers want it.

## Non-goals for v1

- No Hermes core changes.
- No GBrain changes.
- No raw brain-data sharing.
- No media attachments.
- No Aweb identity creation from inside Hermes plugin setup.
- No Python reimplementation of Aweb signing/cert auth.
- No E2EE demo path until Aweb E2EE opt-in API skew is resolved.

## Risks

- Shelling to `aw` is reliable enough for MVP but not as efficient as a library surface.
- `aw events stream --json` is a process boundary; restart/backoff is required.
- `aw chat send-and-leave <address>` resumes by recipient resolution, not explicit session id. If multiple sessions match a target, Aweb may reject and ask the operator to choose. A future `aw chat send --session-id` would make this exact.
- Hermes plugin install UX is clean for separate plugin repos, not for monorepo subdirectories.
- The plugin currently uses plaintext explicit sends because current Aweb release default is plaintext and recent `--e2ee` opt-in smoke hit a server 422 schema mismatch.

## Validation done

- `go test ./cmd/aw -run 'TestAw(MailAckByMessageIDJSON|ChatReadBySessionMessageIDJSON|ChatHistoryBySessionMessageIDJSON)$' -count=1`
- `go test ./cmd/aw -run 'TeamBootstrap|TestAw(MailAckByMessageIDJSON|ChatReadBySessionMessageIDJSON|ChatHistoryBySessionMessageIDJSON)' -count=1`
- `python3 -m unittest discover -s packages/hermes-aweb-platform/tests -v`
- `python3 -m py_compile packages/hermes-aweb-platform/adapter.py packages/hermes-aweb-platform/__init__.py`
- Hermes discovery/config smoke with temp `HERMES_HOME`, symlinked `plugins/platforms/aweb`, and `uv run python`: plugin registered in `platform_registry` and `load_gateway_config()` enabled `Platform("aweb")` with env-seeded extras.
- `git diff --check`

## Next validation before shipping

1. Create a fresh Aweb workspace for Hermes.
2. Symlink the plugin into `~/.hermes/plugins/platforms/aweb`.
3. Run `hermes plugins enable platforms/aweb`.
4. Start Hermes gateway with a cheap/test model.
5. Send Aweb mail and chat from a separate workspace.
6. Confirm:
   - Hermes receives both as inbound platform messages;
   - Hermes replies through Aweb;
   - `aw mail ack` runs only after mail reply succeeds;
   - `aw chat read` runs only after chat reply succeeds;
   - unauthorized senders are rejected unless `AWEB_ALLOW_ALL_USERS=true`.
