# Hermes model, release and installer acceptance — 2026-10-19–20 UTC

The reviewed plugin code at `df0b38022f1a27d22542776f4b93e8456c9e1ba9`
passes real-model mail/chat and model-driven clarification on **Hermes v0.22.2**,
with the actual remotely installed plugin. The code-only ACK covered
`719e8503e605368796c819275436f19f7e23d76b` (8 non-merge commits).
This evidence, the README, canonical runtime/install docs, and the release-test
fixture adjustment are a new delta requiring non-author review. No merge is
claimed here. Earlier findings/evidence are historical; this record supersedes
their pending-model and untested-remote-installer statements.

## Production clean-room acceptance — 2026-10-20 UTC

**PASS:** released public aw **1.36.43**, Hermes **v0.22.2**, and the exact
README plugin pin worked against **https://app.aweb.ai/api**. The new native
member was `hermes-acft3-cleanroom` in `aweb:juan.aweb.ai`, joined using the
coordinator-supplied invite file without exposing its token. No other team or
production resource was used.

The README initially omitted the required hosted-invite `--name` flag.
`aw team join <invite-token>` refused before creating an identity. README and
add-ai-tool now give `aw team join <invite-token> --name <agent-name>`.
The corrected route was rerun from an empty workspace with a fresh npm prefix,
fresh Hermes clone/venv/home, and then the real invite join. It installed the
plugin and configured Anthropic through the documented public `hermes config
set` alternative. This was the only required README correction found by the run.

- Public route: `npm install -g @awebai/aw`, package1.36.43, build
  `b81ff1ebc1500c88a18b38bd927868790b40a9ef` (2026-10-19T22:35:02Z).
  Native binary SHA256
  `7894203e57629ce065a4a922f32a695fa94b584e70cc797a2bbbe963effbb862`.
- Hermes came from the README's v0.22.2 clone/locked-dependency route. The actual
  PATH executable and module were verified inside that fresh checkout.
- `hermes plugins install awebai/aweb/packages/hermes-aweb-platform --ref
  df0b38022f1a27d22542776f4b93e8456c9e1ba9 --enable` passed19.847s;
  installed adapter bytes matched the reviewed pin's hash below.
- The runtime was the actual foreground **`hermes gateway run`** executable;
  all messages, history and read observations used the public released aw.
  No gateway handlers, CLI/server responses, model calls or transport were replaced.
- Native connected stream, allowed-user configuration and every new test input
  were gated below one-minute load8. No suite ran for this production check.

The real Anthropic `claude-sonnet-5-5` run was
**2026-10-20T00:55:58Z–00:56:58Z**:

| Check | Evidence | Result |
| --- | --- | --- |
| Mail | Conversation `dd22e259-945b-4364-b6f0-d5cb72f94438`, input `7fd3c0ca-c243-41cc-9d0a-3347647b7de9`, model reply `d5b9b630-f279-4c28-ab20-d896370ac4c5` | Reply00:56:17.107054Z; source read00:56:17.372199Z, correct conversation |
| Ordinary chat | Session `97f2e2db-f931-498d-b1be-3139639d334c`, input `4b415e28-94c0-4216-9462-6051c6287e0c`, reply `463a96c1-3420-43a9-a944-25ad6da00fc6` | Nonce-bearing model reply in exact session; input absent from receiver's unread history |
| Model clarify | Input `8937b602-022f-4cd4-be8a-e926282ef3ae`; actual tool prompt `6d4fecce-b8dd-40aa-aeab-d1700baa5386`; answer `b99f8722-24f9-4ad0-8581-d921050d37d5` | Later `Blue` input unblocked the real model's clarify tool |
| Continuation | Reply `73d1a4d8-0f50-41d8-b332-081c7d3846e6` | `You chose Blue (prod-clarify-1de03ba1).`; both inputs absent from receiver unread history |
| Unauthorized sender | Restarted with our sender excluded; input `2648d4f4-b358-4922-ad3a-0d8aed82a59c` | Refused before model; the same two stored sessions and API-call counts remained |

Hermes's local, read-only-observed session database recorded Anthropic/model
identity, one mail API call with109 output tokens, and three chat API calls
with117 output tokens (ordinary chat plus clarify/continuation). The actual
`clarify` tool result contained `Blue`. Production chat API history does not
expose per-message read timestamps: the production check established absence
from exact-session unread history, separately from the local timestamp-order
proof below. No production database access was used.

Default Hermes refusal uses its pairing challenge, not silent ignore. It sent
a challenge in conversation `313175f7-27bc-4f05-b16c-ec0bd5bfb26f` without
admitting the input to the model. Pairing codes are not reproduced here.
The source read committed00:56:58.100285Z after the challenge committed
00:56:57.831127Z. The client ack subprocess was interrupted while receiving
that committed result during shutdown; a subsequent exact conversation read
confirmed the persisted receipt. No paid/model retry was needed.

Both foreground gateway PIDs (2770,7225) exited; `hermes gateway status`
reported **not running** and the platform's state was disconnected. The upstream
gateway retained a stale top-level `running` state file after SIGTERM (both
exit codes1). The long OATS scratch path also produced upstream
`AF_UNIX path too long` for the watchdog tick socket. Neither blocked the
transport/model checks, but these upstream operational warnings are retained.
No gateway remains consuming this test receiver. Its team membership remains
for coordinator accounting; no identity retirement was attempted.

The key stayed in runtime environment only; captured output was redacted and
runtime artifacts contained zero literal approved-key bytes. Telegram remains
untested. Operator artifacts: `production-readme-bootstrap-v2.sh`,
`production-v2-bootstrap.log`, `production-v2-install-receipt.json`,
`production-live-acceptance.py`, `production-model-receipt.json`, and
`production-gateway-{allowed,refusal}.log` under this instance's `tmp/`.

- `production-v2-bootstrap.log` SHA256 `8872e10fbd173b93749305464e503cb8dc6f7aac07a9d79ab54a185b9894260f`.
- `production-v2-install-receipt.json` SHA256 `27558cf4fd747dee2a06d9071bd703f5d902bc5d114a879c8c4e8fac3f791d62`.
- `production-model-receipt.json` SHA256 `6f18bb30c36c02a1ba5f0207e57a7bca1059c7eeb17a633aa16fb16c2ee7f98b`.

## Supported upstream release and install

The [upstream latest stable release](https://github.com/NousResearch/hermes-agent/releases/tag/v0.22.2)
was v0.22.2, published 2026-10-15T08:21:32Z, resolving to
`d923a5eb487a17c0a68801bba9ef0f56c81040a8`. The investigation commit
`38d55b90dab7b37d7f26f0450b61851463fb1329` is 1878 commits ahead of that
release and 246 ahead of the latest available canary tag,
`v0.22.2+canary.20261018T065527Z`. Neither latest tag contains the pin;
no published release containing the later investigation pin was found.
Source: upstream GitHub releases/tags and compare API, captured locally as
`hermes-release-list.json`, `hermes-upstream-tags.txt`,
`hermes-release-compare.json`, and `hermes-release-canary-compare.json`.
No PyPI version/range is inferred from these Git releases. Support is stated
for v0.22.2 only, rather than an untested range or latest-main requirement.

A fresh clone, fresh dependency environment and fresh Hermes home exercised the
[README installation route](../../packages/hermes-aweb-platform/README.md#install):
Git clone `--depth 1 --branch v0.22.2` from
`https://github.com/NousResearch/hermes-agent.git`, verify HEAD, then
`uv sync --frozen --python 3.14 --extra anthropic` (PASS, 1.679s).
Prerequisites were Git and uv 0.13.1; Python resolved to 3.14.8. No existing
Hermes environment was reused. Package caches were allowed.

Selecting that checkout's `.venv/bin` first on PATH resolved both the `hermes`
entry point and Python/module paths into the new checkout. The real executable
reported `Hermes Agent v0.22.2 (2026.9.24) · stable · local d923a5eb487a`;
the parenthesized legacy date is upstream output, not a second supported version.
The actual command

```bash
hermes plugins install awebai/aweb/packages/hermes-aweb-platform \
  --ref df0b38022f1a27d22542776f4b93e8456c9e1ba9 --enable
hermes plugins list
```

passed in the empty release home (installer 22.816s). It installed/enabled
`aweb-platform`; the gateway registered `aweb`. Installed `adapter.py` matched
`git show df0b38022:packages/hermes-aweb-platform/adapter.py` byte for byte,
SHA256 `40a0a78e3f78ff40e4f49eb5b25123fddf0b0f313c0152b802ff9c5fae6996ed`.
The same remote installation also passed at the investigation pin in a separate
empty home (18.356s). These are live installer runs, replacing the earlier
source/parser-only evidence. No public/external writes occurred.

## Release transport/control checks

The real lifecycle test passed on v0.22.2 (1.295s, initial/reconnect subcases).
The following probes used its new interpreter, real gateway, real `aw` 1.36.40,
the installed plugin bytes, and the retained disposable loopback aweb/AWID/
PostgreSQL stack. No fake CLI/server/Hermes or fabricated server event was used.
Fixture commands use Hermes's real public clarify/approval primitives; these
rows establish transport/control, independently of the model turns below.

| Probe | Result | Seconds |
| --- | --- | ---: |
| `clarify` | PASS | 5.489 |
| `hint` | PASS | 5.375 |
| `mail_retry` | PASS | 5.366 |
| `mail_routes` | PASS | 5.390 |
| `health` | PASS | 4.871 |
| `approval` | PASS | 7.298 |
| `stop` | PASS | 6.245 |
| `unauthorized` | PASS | 4.304 |
| `chat` | PASS | 9.031 |

The nine probes took 53.369s in separate processes: ordered ordinary turns and
later clarify answers, deterministic empty-history/fresh-hint recovery without
reconnect, mail fetch retry, immutable mail routes, degraded/recovered health,
approve/deny, stop, unauthorized refusal, and burst/stream-restart/no-reply.
The adapter implementation required no release-specific changes.

One fixture incompatibility was shown failing first on the real release:
`Plugin command dispatch failed: clarify() missing ... session_key and source`.
Release `gateway/run_inbound.py:1083-1101` invokes plugin commands with text only
inside its actual session-context scope; newer main also supplies keyword
context. The fixture now reads the real public
`gateway.session_context.get_session_env` when those keywords are absent, and
asserts that session key/chat id exist. The subsequent release runs pass.
This was a test-command contract difference, not an adapter delivery defect.
The updated fixture also passed clarify (4.910s) and approve/deny (6.477s)
on the original investigation pin, exercising its keyword-context path.
The earlier defect reds remain in the [build evidence](hermes-plugin-build-2026-10-18.md);
new release greens are not claimed as fresh failing-baseline proofs for each bug.

## Real model and receipt evidence

The gateway loaded `plugins/aweb-platform/adapter.py` from the actual remote
installation, asserted by its module path and byte hash. Anthropic
`claude-sonnet-5-5`, API mode `anthropic_messages`, was used on both turns.
The approved out-of-band key was read at runtime into memory/environment only.
A log-record/stream redactor was installed before Hermes imports; no key was
written to config, repository, message bodies or evidence. A final literal-key
scan found zero credential bytes in runtime artifacts/captured output.
No Telegram token was supplied: Telegram and simultaneous Telegram/aweb traffic
remain untested.

The release run lasted 2026-10-19T04:39:18Z–04:39:35Z. The native connected
receiver/sender were synthetic `hermes-acft1.test/hermes` and
`hermes-acft1.test/alice`; only the sender was allowlisted. The selected home
channel was Alice. Direct SQL observed committed rows/read receipts; wrappers
observed actual adapter sends and public processing-completion callbacks, and
preserved the immutable input route. They did not supply model or transport
results. Hermes's real model cache recorded:

| Actual model turn | Input tokens | Output tokens |
| --- | ---: | ---: |
| Mail | 3257 | 101 |
| Chat including clarify continuation | 5928 | 100 |

Mail conversation `dccfc309-e0dc-4a3b-acd2-5d4124815fff`:

- Input `22e2d184-d704-4262-9f95-9ee6a724341c` requested nonce `mail-a0a52ac9e8`.
- Exactly one actual model reply, `e9b0268d-1779-4844-ba6c-505a10164f36`, contained that nonce
  and was committed at `2026-10-19T04:39:30.555073+00:00` in the same conversation.
- Source read was committed at `2026-10-19T04:39:30.558078+00:00`, after the reply.
  Observed `reply_to` and immutable route both named the triggering input.

Chat session `07256823-135b-4508-a9a3-5e955bcefb3c`:

- Input `214fa6c8-bb19-47dd-8b29-45bbcc452e6c` asked the actual model to call clarify.
- The model opened real waiter `9eb8c2b4ce` and sent prompt
  `d0674919-b49c-4de1-9eb6-933a533d8598` in that exact session at
  `2026-10-19T04:39:34.151965+00:00`.
- Original input read followed the prompt at
  `2026-10-19T04:39:34.178855+00:00`.
- Later input `e95fe102-2522-4af7-a527-3398ce3ce45b` answered `Blue`; it reached
  the actual pending waiter while the original turn was blocked. Its read
  followed admission at `2026-10-19T04:39:34.727759+00:00`.
- The same model turn resumed, sending
  `03ccfb05-8637-468c-95db-f628cf2bb110` at
  `2026-10-19T04:39:35.74992+00:00`: `You chose Blue (identifier chat-64f3dfa838).`
  The final send retained the original triggering input's route and `reply_to`;
  neither the answer nor later delivery overwrote it. Both source messages
  were read, and the original turn's public completion callback succeeded.

The earlier investigation-pin run also passed actual model mail/chat/clarify
at 04:32:12Z–04:32:30Z (mail conversation
`219b697f-abbf-4f36-aaad-063bb5993721`, chat session
`b0361d96-3198-4d95-8e9d-4b719e0a58f0`). The release run above additionally
establishes the model path on the version the README now installs.

## Observed boundaries and unsuccessful setup attempts

Read state is presentation/admission evidence, not model-turn completion. In
an initial fresh-home run without a home channel, Hermes sent its first-run
missing-home-channel notice as a visible mail reply. In conversation
`21098067-733b-4e7a-87db-7ea9168a2d56`, notice
`75983294-7afd-481a-a75b-0b629018747b` committed at 04:30:01.535295Z;
source `ae5eb982-3b0c-471a-8a3c-7ff77e80ceff` read at 04:30:01.541663Z;
final real-model reply `a80c3710-e342-44cb-b002-7535d0941468` arrived at
04:30:12.939688Z. The harness expecting one reply/read-after-model failed.
That evidence is retained, not silently excluded. Subsequent acceptance set
`AWEB_HOME_CHANNEL`, as the documented flow now does. A clarify prompt likewise
marks the original input read before the final continuation; the later clarify
answer is accepted with no separate reply. No stronger receipt claim is made.

One scratch harness retry omitted the required `platform` field from an
explicit YAML home-channel object and failed gateway construction with
`KeyError: platform` before startup/model use. Correcting the harness to match
Hermes's actual HomeChannel shape required no product change.

All actual model input submissions and each targeted probe were gated on
one-minute load below8; release model start/end were 3.86/4.39. The shared host
briefly reached10.98 during the read-only remote installer; further probes
were deferred until below8. No whole suite ran. The runtime-only gateway was
stopped after acceptance. The existing full2000-row refusal and arbitrary
crash-between-send-and-read duplicate boundary remain; model/tool side effects
are not exactly-once.

## Reproduction and retained artifacts

The README gives the public installation route. For the disposable server
fixtures and opt-in checks, use the [build evidence](hermes-plugin-build-2026-10-18.md)
and README compatibility commands with the v0.22.2 interpreter/source. Run one
receiver at a time. The small model harness requests a nonce-bearing mail
acknowledgement and a nonce-bearing chat clarify/answer continuation, and
asserts committed routes/read ordering plus actual provider/model usage.
Do not rerun the paid turns merely to check an artifact hash.

Operator-local artifact paths below are relative to this instance's `tmp/`;
they are not prerequisites or public install paths. The scripts are
`install-hermes-release.py`, `run-hermes-release-probes.py`, and
`real-model-release-acceptance.py`. The original model harness/attempts are
`real-model-acceptance.py`, `model-attempt-1-runtime.log` and
`hermes-model-acceptance/model-attempt-1-receipt.json`. Only sanitized observations
are included here, not raw runtime logs or credentials.

| Artifact | SHA256 |
| --- | --- |
| `hermes-model-acceptance/installer-receipt.json` | `ac6c86d5595f298c79d84924541ae1e343b7c2a77a78d0c2faa7cb6e7648f8bc` |
| `hermes-model-acceptance/model-receipt.json` | `a707b900fafb6bd86eb1e0bf411112d617d84415dcc320535656f230c9669683` |
| `model-runtime.log` | `b15b42cc48d283798c3a0f06fde638147ba9c6f3419f19d00ed70794ed6fe949` |
| `hermes-release-dependencies.json` | `24ff43e6869ed052e373c64568f2c57460a6648aac5e5ba603c70435d9d504a7` |
| `hermes-release-acceptance/installer-receipt.json` | `865762c7c7cb1c644410f3919038be2efa4577ae4c52cbe841b7e8a4bff728d8` |
| `hermes-release-fixture-context-red.log` | `aaca6c32ce0e6bf19733af82417015aa42a6bae126086436ad08f058dd5b5f60` |
| `hermes-release-probe-receipts.json` | `5f5ed6a13b19430e4adddea83a8248bb917a60b313ddcfb9aac5f1a3f77f9cec` |
| `hermes-release-acceptance/model-receipt.json` | `391eaf0b48bbf1db30f4f73bc57cd83f0227c1a647db4f8cac6763db7dd7691f` |
| `model-release-runtime.log` | `3e90bdcd86291d8c36176acc67658dd4bcc0cc24b060892346da3fe39c1d652b` |
| `real-model-release-acceptance.py` | `17854aa9ba51a9a22e48896d3c1597bd8a0c9a5db3763a842200d71db1753ded` |
| `install-hermes-release.py` | `ce55cdb317c334c63ef4a7a2ef580a501130e93417c205ffae4be4ce3ab04067` |

Validation of this delta passed:

- `python3 scripts/check-doc-links.py --self-test` and normal check: 419 links.
- `bash scripts/check-doc-paths.sh --self-test` and normal check: 126 paths.
- `python3 scripts/check-extension-docs.py --self-test` and normal inventory check.
- `python3 cli/go/scripts/check_docs_regressions.py --root docs`: 86 files.
- `git diff --check`, and a literal approved-key scan of changed repository
  files plus retained runtime logs/receipts: no credential bytes found.

The two canonical docs state Hermes's integration support without inventing
materialization, `--harness hermes`, or `aw team admin up`/`--start` support.
Only README, those two canonical docs, this evidence, and the fixture adjustment
are in this follow-up delta. The adapter code remains byte-identical to the
code-reviewed pin. Current origin/main was merged into this branch before
handoff; no branch-to-main merge has occurred.
