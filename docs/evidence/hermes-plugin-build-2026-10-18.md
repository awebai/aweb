# Hermes plugin build acceptance, aweb-acft.3

Juan approved plugin-side fixes from investigation tip `25d77a52`. Implementation:
`df0b38022f1a27d22542776f4b93e8456c9e1ba9`; history retained, no server changes.
Tests ran on 2026-10-19 UTC / 2026-10-18 PDT. No model credential or Telegram
token was available. **All results here are transport/control evidence, not
model-generated reply or model-chosen tool-call evidence.**

## Actual stack and harness

- Clean read-only Hermes `38d55b90dab7b37d7f26f0450b61851463fb1329`, Python3.14.8 with its declared dependencies; real aw1.36.40.
- Local `docker-compose.e2e.yml` aweb/AWID/PostgreSQL/Redis, project `hermes-acft1`, aweb28180/AWID28110/PostgreSQL55483. Disposable native workspaces for `hermes`, `alice`, `mallory`; team `test:hermes-acft1.test`. No production resources.
- `test_live_delivery.py` starts an actual `GatewayRunner` in each fresh subprocess/home. Both the real aweb plugin and a fixture command plugin load through actual Hermes discovery. The fixture calls the actual clarify registry/waiter and public `request_tool_approval`; it substitutes no gateway handler, model, CLI or server.
- The race probe delays an already completed real `aw chat history` response after its database snapshot, observes a fresh actual server summary through the live stream, then releases the result. The retry probe drops a completed real mail-fetch result once by raising at that I/O boundary; the next attempt must actually refetch and deliver it. These are scheduling/fault instruments, not fabricated event/message fixtures.
- Reply-route observations wrap actual `aw mail reply` calls and retain the exact input id and body used. Read/reply data come from real aw and local PostgreSQL. The existing burst test also starts the actual CLI gateway process, holds a real PostgreSQL receipt lock, kills its stream child and tests the replacement.
- No other gateway consumed this receiver during acceptance. Every probe tears down its gateway and clears its own pending fixture waits. No whole suite ran; only targeted plugin checks. Sampled one-minute host load was about5.9–6.6; no whole suite or suite lock was used.

## Shown failing first

The baseline is the adapter at `25d77a52`. Initial probes ran before adapter edits;
subsequent isolated mail/approval/stop reds loaded the same plugin files exported
byte-for-byte from that Git revision into an operator-local fixture directory.

| Defect | Actual red behavior | Corrected behavior |
| --- | --- | --- |
| Clarify deadlock | A real pending clarify never received later input `2` before the assertion deadline. | It resolves to choice two, then two queued ordinary fixture commands yield separate replies in order. All four inputs receive per-message receipts. |
| Approval deadlock | `/approve` cannot release the real approval gate while the original turn waits. | `/approve` and `/deny` resolve actual tool-approval waits with the expected allow/deny results. |
| Stop admission | Later `/stop` cannot release the session for a later ordinary input. | Actual Hermes cancellation runs and the later ordinary input replies. This is a platform/fixture turn, not a model agent; Hermes's stop text reports no active model task. |
| Empty-history/hint race | A fresh actual summary arrives while an empty real history response is held; after release the new input receives no reply. | The retained wake causes another real history read and a separate reply. The strengthened check verifies the same stream PID and connected-frame count, excluding reconnect recovery. |
| Mail fetch retry | A dropped completed fetch result remains unread with no eventual reply/ack. | The real fetch retries; the exact input receives one fixture reply and a read receipt. |
| Mutable mail route | A held turn replies to the newer input in the same conversation. | A concurrent `/approve` reply uses its own input; releasing the held turn replies to the original input. |
| Premature stream health | Adapter reports healthy while its first parsed real frame is deliberately held before acceptance. | Both public degraded status and persisted Hermes status show retrying, then connected on release, retrying after real child exit, connected after real recovery. |

An additional stop/shutdown regression failed against the first uncommitted
implementation: a completed earlier stop incorrectly acknowledged a later
shutdown-cancelled input. The final code requires the interrupt control to still
be executing; the test now verifies that later unfinished input stays unread.
This red is an implementation regression, not attributed to `25d77a52`.

Earlier mail probes reused the fixture's existing conversation and were affected
by older deliberately blocked test inputs. Those runs are superseded by the
isolated `--new-conversation` red/green records below. No unisolated run is used
to establish the mail fixes.

## Final results and receipts

Seven targeted delivery probes passed in **34.800s**. Each subprocess emitted
an explicit case-completion record after its assertions; the parent verifies
that record as well as its exit status. A separate unauthorized-sender probe
passed in **3.588s**: the real Hermes processing hook completed, yet input
`d5542c03-8465-4335-8dc8-dcf7ce01fda6` remained unread and had zero replies.
The hint probe was strengthened afterward to exclude reconnect and passed alone in **4.659s**: session `84164be9-e691-410d-93d9-b1359d39b14f`, fresh input `10373752-2dc9-459d-bc8e-7700a8bac0cb`, unchanged stream PID40693 and exactly one connected frame.

| Check | Receipt |
| --- | --- |
| Clarify + two ordered ordinary turns | Session `28aba647-0208-44e4-bed9-ef8462d4a86b` |
| Approve / deny | Sessions `ddbadc29-60c2-4043-9914-15d7d7d99e0f` / `3ca49434-dfc5-434d-bd04-b5869e245d05` |
| Hint race | Session `e0ac755d-395c-4600-90e3-71befd8cba5b`, new input `dde47cb1-188d-43ef-b2f0-4d10392639a6` |
| Mail fetch retry | Input `021fcef2-9a8b-45c4-a97d-67e97af691d7` |
| Overlapping mail routes | Conversation `3ae8137e-b65c-455a-88e5-32d514157c46`; control reply input `f1744ed3-d84e-4ef6-abf4-393cd397da0e`, held-turn reply input `df9204a4-16dc-4497-a43b-fae23d0cf13d` |
| Stop and shutdown receipts | Session `2b4b1dbc-e963-41e3-b10c-86e8241fec5b` |
| Health | Stream `17626` → `17678`, persisted status retrying → connected → retrying → connected |

The retained ordinary-chat regression passed in **7.957s**: session
`208dfbf7-d681-44c2-a4a5-4f13be652a92`, stream83816 →84389. Exactly three
replies for two initial `/help` inputs plus a post-restart `/help`; every read
followed its reply, and a final no-reply `/start` received its own read receipt.
This proves stream-child restart, not gateway-crash exactly-once execution.

The actual Hermes lifecycle regression passed (one test, initial/reconnect
subcases). The three legacy fake-aw unit checks passed separately; they are
unit regressions and are **not** real-stack acceptance evidence.

## Reproduction and upgrade

Use the disposable loopback stack/fixture setup in the [investigation record](hermes-live-2026-10-18.md#reproduction-commands).
Do not reuse a live agent's receiver. Run the targeted commands in the
[plugin README](../../packages/hermes-aweb-platform/README.md#compatibility-checks)
from the repository with Hermes's dependency interpreter. Set
`HERMES_LIVE_UNAUTHORIZED_HOME` to the local `mallory` workspace for the eighth
probe. That variable is used only as an explicit local test fixture; no
credentials are copied into messages or repository files.

For red reproduction, export `__init__.py`, `adapter.py` and `plugin.yaml` from
`25d77a52:packages/hermes-aweb-platform/` to an isolated scratch directory and
set `HERMES_LIVE_PLUGIN_SOURCE` to it. Run individual probe cases using the
same source/dependency/workspace environment. Baseline controls intentionally
fail before releasing their wait; the harness's teardown clears its real waits.
The baseline source remains unchanged.

The README names the public surfaces used and every remaining private Hermes
boundary, with pinned file/line references and upgrade checks. It also records
the aw internal-reconnect diagnostic dependency. Full 2000-row history windows
remain refused; no server pagination, event version or durable operation
receipt was implemented. Same-process receipt retry does not close the
arbitrary gateway-crash send/read gap or make model/tool effects exactly-once.

## Remaining acceptance

- **Real model mail reply: untested; approved credential pending from Juan.**
- **Real model chat reply: untested for the same reason.**
- **Telegram+aweb gateway and each platform's real replies: untested; no test bot token provided.**
- Remote installer execution is untested; its current parser and source install shape were audited.
- Independent exact-SHA review remains required before merge. No main merge or task-complete claim is made here.

## Raw artifact binding

Raw operator-local logs are retained under this instance's `tmp/`; only selected
synthetic ids, status and timings appear above. Historical investigation logs
are unchanged. SHA-256 values:

| Artifact | SHA-256 |
| --- | --- |
| build-health-red.log | `bbbdb433a3d03220e773529e1114ee015b9aa3dfd2057972ef58b8438b788bc1` |
| build-clarify-red.log | `a1019ac0a2aacedbb58035507aa463a49c44f53a0fea435883075dc40935f9e0` |
| build-hint-red.log | `98bd24bc15300f5b6c07c48c6756b82cb400f6596cfd78d141d076a4132162ae` |
| build-mail_retry-isolated-red.log | `4de0b3ac8dff125d437c37100994c747dc9e6f9d929b696fc8290257a09bd079` |
| build-mail_routes-isolated-red.log | `2abc28b94fdb61fb292189f1e002c63b97107f77752a1b213d2d4c142ea9b40b` |
| build-approval-red.log | `bd14dfef0aaa7c1608eeaed7dda16dac80e92375211c9a1662c8c941cff311a5` |
| build-stop-red.log | `7e182e97c801833915d2ab735d44ee6e0db4ce0ec61327c2f88059fd4ec03567` |
| build-stop-shutdown-isolated-red.log | `b672b205800735e1df32a7c76fafe3845c6997c34494538fd10110eacb08fbc4` |
| build-delivery-receipts.log | `74907ee074849a2f62ecd997955aa782e62db722c155df715c85ce6802e73a32` |
| build-chat-regression.log | `5fc89ae13d80e8bc48b974b2065bb09e8e16dbafe3673d060f6b62fba574ed02` |
| build-unauthorized-final.log | `07dbe3027091ae2ec387a20c4f803799b66cf5c135904e2b57a22527ccfdd0f1` |
| build-hint-boundary-final.log | `6a284fbce0521a236c1fc38f76600b346d80b5e45bf20061dcb4ccf4f0eff888` |
