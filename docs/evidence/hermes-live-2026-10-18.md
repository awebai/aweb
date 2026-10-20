# Hermes live evidence, 2026-10-18

See [findings and scope](../hermes-aweb-live-findings.md). All messages below are synthetic traffic on the disposable local e2e stack. Times are UTC. No model key, Telegram token or mock transport was used. These are historical runs through `dfdd0822`; they do not establish coverage of blocked-turn controls/clarification or the exact empty-history/fresh-hint race. The adapter retained-hint change was subsequently reverted without a new live rerun. That investigation fallback was not approved to land as-is. Juan subsequently approved aweb-acft.3; [its separate build record](hermes-plugin-build-2026-10-18.md) documents the replacement design and new deterministic tests. The historical logs below are unchanged.

## Baseline startup and TDD

Real Hermes commit: `38d55b90dab7b37d7f26f0450b61851463fb1329`. Unchanged plugin, actual `python -m hermes_cli.main gateway run`:

```text
2026-10-18 16:39:38,814 ERROR gateway.run: aweb error: AwebAdapter.connect() got an unexpected keyword argument 'is_reconnect'
2026-10-18 16:39:38,861 WARNING gateway.run: Gateway started with no connected platforms — 1 platform(s) queued for retry
```

These two log timestamps use the host's PDT zone. The targeted lifecycle test called real `GatewayAdapterLifecycleMixin._connect_adapter_with_timeout` through real `PluginContext` registration. Both `is_reconnect=False` and `True` reached Hermes `run_adapters.py:205` and failed with that same `TypeError`. After the signature change: one test, both subcases, PASS. An absent native workdir was used to stop at real adapter validation without starting any transport in this signature test.

Real chat regression before the fallback: two messages were sent by real aw before gateway startup; the test subscribed to the actual server stream and asserted a summary with `unread_count=2` and no `message_id`. The actual gateway produced no reply/read receipt; the test failed after 20 seconds. This is a server-driven failing case, not a manufactured event dict.

## Actual session-summary event excerpt

Selected fields from the real stream capture (the full capture also contains a `raw` copy):

```json
{"type":"actionable_chat","session_id":"44120395-0c1a-4261-93b3-a83082231a5a","conversation_id":"44120395-0c1a-4261-93b3-a83082231a5a","from_alias":"alice","from_address":"hermes-acft1.test/alice","unread_count":1,"wake_mode":"prompt"}
```

There is no message id. The corresponding real history fetch returned message `5c4e42e1-b2b3-4b39-8392-994286700019`, with `verification_status=verified`.

## Recorded real-stack chat test at dfdd0822

`test_live_chat.py`: PASS, 7.931 seconds. It starts an actual Hermes gateway, symlinks the actual plugin, sends through the real aw CLI, and queries the real PostgreSQL receipt tables. A row lock on the second incoming message holds its read receipt while the stream child is terminated. Old child PID `52410`; replacement PID `52495`. A later new message proves the replacement subscription actually delivers input.

Session: `594afc28-0681-47d8-86a4-f3c6a335b557`.

| Input | Incoming id | Reply persisted | Incoming read |
| --- | --- | --- | --- |
| `/help first` | `be67aae2-e9a8-4fe1-95e0-af29cc20bed2` | 23:54:15.897069 | 23:54:15.946244 |
| `/help second` | `cebd6dfa-1103-4d65-b2ff-d7f129629c98` | 23:54:16.005171 | 23:54:16.031086 |
| `/help after restart` | `76ca71a7-9a58-4f2b-b571-88f54467915d` | 23:54:18.115222 | 23:54:18.142615 |
| `/start` | `9a2ce0ed-1e4f-4b5b-89c5-61f7c3a7e721` | No reply, as specified by Hermes's command | 23:54:19.114189 |

Exactly three outbound rows exist in that same session, with ids `1f467084-894a-4e21-b536-5aa45bf46a8b`, `dd7002eb-d86f-40fe-8ba4-d52bfc074a71`, `92a9924b-88fe-4cb2-b08e-a2a78cda11ff`. Both original burst inputs arrived before gateway startup, in the order shown. Each received one reply; neither was dropped or duplicated across the stream restart. No wording assertion substitutes for these behavior checks.

This test exercises **stream-process restart**, not killing the gateway between a visible send and read. It does not establish exactly-once delivery across arbitrary crashes.

## Mail and authorization

Real Hermes `/help` mail, empty subject, conversation `7f1a2877-a263-46df-843e-b2ecc89454b3`:

| Row | Message id | Created | Read |
| --- | --- | --- | --- |
| alice → hermes | `e0880c6e-9a19-4a4e-9093-b29f9932d0c0` | 23:49:59.687587 | 23:50:02.290361 |
| hermes → alice | `82acfd0e-8c4e-4f53-a438-54e70bf7a039` | 23:50:02.286354 | Unread at capture |

The 7008-character real Hermes command response was stored before the source read receipt. Current `aw mail reply` itself attempts an ack after a successful send (`cli/go/cmd/aw/mail.go:769`); the adapter then issues its own explicit ack. This proves persisted-reply-before-read ordering, not that the adapter's ack was the first ack.

Unauthorized source `hermes-acft1.test/mallory`, message `d725c1b8-c05b-45af-a20c-cd6a6bb02800`: the actual gateway logged `Unauthorized user (ignored)` for that address. There is no reply; the local database still showed `read_at=NULL` at 23:50. The allowed identity was configured by full address, with `AWEB_ALLOW_ALL_USERS=false` and `gateway.unauthorized_dm_behavior=ignore`.

Earlier normal mail `f34c3f10-7fa2-4140-a0c8-c560eaf8656b` reached real Hermes agent construction and failed with `ProviderNotConfiguredError`. The resulting visible configuration-error reply is deliberately excluded from real-model success evidence. No approved credential was available.

## Reproduction commands

Build/start the four relevant services from the repository's compose file, with an unused project and loopback ports:

```bash
export LIBRARY_E2E_AWEB_PORT=28180
export LIBRARY_E2E_AWID_PORT=28110
export LIBRARY_E2E_POSTGRES_PORT=55483
export LIBRARY_E2E_AWEB_PUBLIC_ORIGIN=http://127.0.0.1:28180
export LIBRARY_E2E_AWID_PUBLIC_REGISTRY_URL=http://127.0.0.1:28110
COMPOSE_PARALLEL_LIMIT=1 docker compose -p hermes-acft1 -f docker-compose.e2e.yml build awid aweb
COMPOSE_PARALLEL_LIMIT=1 docker compose -p hermes-acft1 -f docker-compose.e2e.yml up -d --wait aweb
```

Provision real `hermes`/`alice` identities in one team on those local services through normal CLI membership and workspace-connect commands. Use a separate `mallory` identity for unauthorized traffic. These are disposable test fixtures; do not point the test at an operator/team identity.

In an environment containing the pinned Hermes checkout's dependencies:

```bash
HERMES_AGENT_SOURCE=/path/to/pinned/hermes-agent \
  python -m unittest discover -s packages/hermes-aweb-platform/tests -p test_hermes_lifecycle.py -v

HERMES_AGENT_SOURCE=/path/to/pinned/hermes-agent \
HERMES_LIVE_RECEIVER_HOME=/path/to/local/hermes \
HERMES_LIVE_SENDER_HOME=/path/to/local/alice \
HERMES_LIVE_POSTGRES_CONTAINER=hermes-acft1-postgres-1 \
  python -m unittest discover -s packages/hermes-aweb-platform/tests -p test_live_chat.py -v
```

The live test creates its own temporary Hermes home and stops its gateway. It strips inherited aweb/identity/model credentials and requires the receiver's aweb URL to be loopback. There must be no other gateway consuming the receiver.

The three existing fake-aw unit tests also passed; they are regression checks only and are not the live evidence above. No whole suite was run. Telegram and real model generation remain untested.

## Retained raw-run digests

Original operator-local logs are retained in the investigation instance's `tmp/`; only sanitized facts are published here. SHA-256 binds these records to the reported runs:

| Artifact | SHA-256 |
| --- | --- |
| lifecycle-red.log | `3421fe5287895a47dd5840ac8b39477dfc96ed3a1035a33c15cb85b09bec9136` |
| lifecycle-green.log | `1e1959bb172803df12f12a614245c76f1dbf7090643e0190dcfd6d1c19f55c92` |
| chat-live-red.log | `3fd7c99c78ccbb127d1eee0a8e63c44dc181601f56be677c7418758193af59a9` |
| chat-live-green.log | `812f91035d03751e3cb7d2cfb6baea560608050f6f5123b7664ce20929da705a` |
| hermes-gateway-startup.log | `fa1effa9f3561cf6a3874aaa359bb1cd708a410db735bfb92a009f8f9d7d32e6` |

This green run occurred after the retained-hint adapter change, but it did not deterministically hold an empty history response after its database snapshot and inject a fresh server hint before release. There is no isolated red/green for that race; it remains unresolved, and the adapter change was reverted in `a5cb6e23`. The run proves only the ordinary transport behaviors described above. One intervening attempted rerun was discarded because an earlier mail-test gateway still owned the receiver; it was stopped before the final, exclusively owned run.

| Historical dfdd0822 artifact | SHA-256 |
| --- | --- |
| chat-live-final.log | `dc675983b10606facfe38e0f2d7844bbf5c989b714a1c69ad2119ae8ef043fa3` |
