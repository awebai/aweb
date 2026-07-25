# ARCHIVED — Channel stack map (historical snapshot)

> **This is a historical snapshot, not a source of truth.** It records the
> channel stack as it stood when the map was written, to support restructuring
> planning. It is **not maintained**, and its file paths, `:LINE` anchors and
> test counts are **expected to be stale**. Do not use it to decide what code
> exists today; read the code.
>
> - **Archived:** 2026-07-24, at repository SHA `56dddb6e`.
> - **Known to be superseded:** the "Local duplicate-code caveat" section below
>   describes `channel/src/api`, `channel/src/identity` and `channel/src/config.ts`
>   as existing. Those shadow implementations were **deleted** by default-aajc.6;
>   the runtime has always used `@awebai/channel-core`. The test counts in the
>   "Validation" section are likewise from the original run and no longer match.
> - **Why archived rather than updated:** the document's accuracy rests on
>   dozens of hand-maintained `file:line` anchors across four packages plus
>   hand-counted test totals. Keeping that true requires exactly the manual
>   upkeep that let it rot in the first place (default-aajc.16).

Original status line, as written: familiarization map for restructuring planning. Scope: `channel-core/`, `channel/`, `pi-extension/`. No implementation recommendations are tasks yet.

## Framing against SOT §3

SOT §3 says core owns the **Event/SSE channel** as shared wake infrastructure: apps emit events and agents subscribe through core (`docs/restructuring-sot.md:55`, `docs/restructuring-sot.md:66`). `channel-core`, `@awebai/claude-channel`, and `@awebai/pi` are therefore **consumers/subscribers of that core channel**, not the channel itself.

SOT §3.1 separately says core keeps "protocol transport for signed app envelopes," not messaging semantics (`docs/restructuring-sot.md:82`, `docs/restructuring-sot.md:87`). SOT §12 intentionally keeps mail/chat in core during transition, then splits `messages`/`chat` semantics last because federation/events/E2EE are currently fused (`docs/restructuring-sot.md:434`, `docs/restructuring-sot.md:442`, `docs/restructuring-sot.md:463`).

This map tags each piece as:

- **Reusable AS-IS** — suitable for the future core Event/SSE channel with little/no semantic change.
- **Messaging-semantic seam** — currently assumes mail/chat-in-core or comms-app concepts; keep for transition, but it is a future split seam when `messages`/`chat` become apps.

## Executive seam map

| Piece | Tag | Why |
|---|---|---|
| Signed API client and team-auth/identity-auth request signing | Reusable AS-IS | Core subscribers still need signed requests and cert-backed access to `/v1/events/stream` (`channel-core/src/api/client.ts:61`, `channel-core/src/api/client.ts:80`, `channel-core/src/api/client.ts:111`). |
| Workspace config/cert/key loading | Reusable AS-IS | Host consumers need local identity, active team, signing key, cert, alias, address (`channel-core/src/config.ts:58`, `channel-core/src/config.ts:91`, `channel-core/src/config.ts:97`). |
| SSE connect/parse/reconnect | Reusable AS-IS | Generic Event/SSE subscription loop; only event type vocabulary changes over time (`channel-core/src/api/events.ts:36`, `channel-core/src/api/events.ts:71`, `channel-core/src/api/events.ts:132`). |
| Delivery store / de-dupe | Reusable AS-IS | Consumer-side replay guard over event-derived message IDs, independent of domain (`channel-core/src/channel.ts:64`, `channel-core/src/channel.ts:154`, `channel-core/src/channel.ts:248`). |
| `ChannelAwakening {kind, content, meta, deliveryIntent}` | Mostly reusable AS-IS | Host-neutral wake abstraction maps well to future app events (`channel-core/src/channel.ts:33`, `channel-core/src/channel.ts:172`). Future app events may need app-id/type metadata, not a different adapter model. |
| Control/work/claim dispatch | Mostly reusable, but app-boundary-sensitive | Dispatch mechanics are generic; work/claim are task/dev semantics and should become app-emitted ambient events (`channel-core/src/channel.ts:184`, `channel-core/src/channel.ts:198`, `channel-core/src/channel.ts:209`). |
| Mail inbox fetch + ack | Messaging-semantic seam | Assumes `/v1/messages/inbox`, subjects, priority, read/ack (`channel-core/src/api/mail.ts:41`, `channel-core/src/api/mail.ts:99`, `channel-core/src/channel.ts:243`, `channel-core/src/channel.ts:291`). |
| Chat history fetch + read | Messaging-semantic seam | Assumes `/v1/chat/sessions`, unread chat state, sender waiting/leaving (`channel-core/src/api/chat.ts:33`, `channel-core/src/api/chat.ts:93`, `channel-core/src/channel.ts:302`, `channel-core/src/channel.ts:354`). |
| Message signature verification over mail/chat envelopes | Messaging-semantic seam with reusable crypto pieces | Ed25519 canonical verification is reusable; `MessageEnvelope` fields include subject/body/thread-ish IDs and mail/chat types (`channel-core/src/identity/signing.ts:8`, `channel-core/src/identity/signing.ts:38`, `channel-core/src/identity/signing.ts:135`). Future signed app envelopes should reuse crypto/conformance, not mail/chat envelope semantics. |
| Sender trust normalization / registry / TOFU | Mostly reusable AS-IS | Identity binding, `did:aw` registry verification, custody normalization, and TOFU pins apply to any app-originated signed wake (`channel-core/src/identity/trust.ts:76`, `channel-core/src/identity/trust.ts:148`, `channel-core/src/identity/registry.ts:112`, `channel-core/src/identity/pinstore.ts:11`). |
| Local decrypt provider via `aw mail show` / `aw chat history` | Messaging-semantic seam | Correct transitional E2EE boundary, but commands are comms-app-specific (`channel-core/src/local_aw.ts:19`, `channel-core/src/local_aw.ts:25`, `channel-core/src/local_aw.ts:37`). |
| Claude Code adapter | Reusable AS-IS | Thin inbound-only host adapter; outbound remains CLI (`channel/src/index.ts:39`, `channel/src/index.ts:45`, `channel/src/index.ts:63`, `channel/src/index.ts:75`). |
| Pi extension wake dispatcher | Reusable AS-IS | Thin host delivery mapping from core delivery intent to Pi message options (`pi-extension/src/wake.ts:74`, `pi-extension/src/wake.ts:100`, `pi-extension/src/wake.ts:128`). |
| Pi extension bundled skills | Reusable packaging pattern, content evolves | Package bundles canonical aweb skills and exposes them to Pi (`pi-extension/package.json:21`, `pi-extension/package.json:45`, `pi-extension/package.json:49`). Skill content will track CLI/app restructuring. |

## Current core server event source

The actual Event/SSE channel lives server-side today:

- `events.py` defines `/v1/events` (`server/src/aweb/routes/events.py:24`) and `GET /stream` (`server/src/aweb/routes/events.py:372`) with team identity auth (`server/src/aweb/routes/events.py:377`).
- `_sse_agent_events` emits a keepalive, a connected frame, initial state, then polls/diffs and emits changed events (`server/src/aweb/routes/events.py:265`, `server/src/aweb/routes/events.py:291`, `server/src/aweb/routes/events.py:294`, `server/src/aweb/routes/events.py:310`, `server/src/aweb/routes/events.py:319`, `server/src/aweb/routes/events.py:353`).
- Current event source is **not yet app-generic**: mail comes from unread `messages` rows (`server/src/aweb/routes/events.py:49`, `server/src/aweb/routes/events.py:90`), chat comes from pending conversations and waiting state (`server/src/aweb/routes/events.py:129`, `server/src/aweb/routes/events.py:163`, `server/src/aweb/routes/events.py:206`), and control signals are consumed directly (`server/src/aweb/routes/events.py:231`, `server/src/aweb/routes/events.py:258`).
- It already respects the encrypted-content boundary by redacting encrypted mail subject in event metadata (`server/src/aweb/routes/events.py:102`).
- **Load-bearing §3 seam:** server `events.py` currently emits `actionable_mail`, `actionable_chat`, and `control_*`; `channel-core` already knows `work_available`, `claim_update`, and `claim_removed` (`channel-core/src/api/events.ts:10`, `channel-core/src/api/events.ts:127`, `channel-core/src/channel.ts:198`, `channel-core/src/channel.ts:209`, `channel-core/src/channel.ts:222`). That emit-set gap marks the future move from hard-coded comms/control polling toward app-emitted core events.

**Restructuring implication:** server `events.py` is the core Event/SSE channel implementation to preserve/abstract. The TS channel stack is the subscriber/runtime family that consumes it.

## `channel-core/` detailed map

### Reusable AS-IS: config, credentials, signed API

- `resolveConfig(workdir)` loads workspace/team/identity/signing-key material and rejects unsupported legacy/missing active membership state (`channel-core/src/config.ts:58`, `channel-core/src/config.ts:59`, `channel-core/src/config.ts:77`, `channel-core/src/config.ts:87`).
- It derives current `did:key` from `.aw/signing.key`, chooses stable ID and address from cert/identity, and validates cert/team/alias consistency (`channel-core/src/config.ts:91`, `channel-core/src/config.ts:94`, `channel-core/src/config.ts:97`, `channel-core/src/config.ts:101`, `channel-core/src/config.ts:104`, `channel-core/src/config.ts:107`).
- `createChannelClient` constructs `APIClient` with DID, stable ID, signing key, team ID, and encoded team cert (`channel-core/src/channel.ts:137`).
- `APIClient.openSSE` signs the SSE request (`channel-core/src/api/client.ts:61`, `channel-core/src/api/client.ts:68`). `/v1/events/stream` falls through to team auth with `X-AWID-Team-Certificate` (`channel-core/src/api/client.ts:80`, `channel-core/src/api/client.ts:111`).

### Reusable AS-IS: SSE stream parser/reconnect

- `streamAgentEvents` opens `/v1/events/stream?deadline=...`, reconnects on stream end, backs off on connect failure, and respects abort signals (`channel-core/src/api/events.ts:36`, `channel-core/src/api/events.ts:44`, `channel-core/src/api/events.ts:48`, `channel-core/src/api/events.ts:57`).
- `parseSSEResponse` implements a host-independent SSE parser: chunks, lines, comment skip, blank-line event boundary, JSON parse (`channel-core/src/api/events.ts:71`, `channel-core/src/api/events.ts:89`, `channel-core/src/api/events.ts:102`).
- `parseAgentEvent` whitelists event names and maps legacy/current server names `actionable_mail`/`actionable_chat` to `mail_message`/`chat_message` (`channel-core/src/api/events.ts:125`, `channel-core/src/api/events.ts:132`, `channel-core/src/api/events.ts:138`). The parser mechanics are reusable; the event-name vocabulary is where future app events will extend/change.

### Messaging-semantic seam: mail/chat state fetch after lightweight wake

The server SSE frame is lightweight. `channel-core` then re-fetches comms state to get bodies and mark handling state:

- Mail: `dispatchMailEvent` calls `fetchInbox(... unreadOnly=true, limit=200, event.message_id)`, de-dupes, emits an awakening, persists delivery, and `ackMessage`s delivered mail (`channel-core/src/channel.ts:238`, `channel-core/src/channel.ts:243`, `channel-core/src/channel.ts:248`, `channel-core/src/channel.ts:280`, `channel-core/src/channel.ts:291`).
- `fetchInbox` is messaging-specific: `/v1/messages/inbox`, `subject`, `priority`, `read_at`, signed payload hydration, and message verification (`channel-core/src/api/mail.ts:10`, `channel-core/src/api/mail.ts:41`, `channel-core/src/api/mail.ts:52`, `channel-core/src/api/mail.ts:57`, `channel-core/src/api/mail.ts:99`).
- Chat: `dispatchChatEvent` requires `session_id`, calls `fetchHistory(... unreadOnly=true, limit=2000, event.message_id)`, carries `sender_waiting`/`sender_leaving`, and marks read up to the last delivered message (`channel-core/src/channel.ts:296`, `channel-core/src/channel.ts:302`, `channel-core/src/channel.ts:329`, `channel-core/src/channel.ts:342`, `channel-core/src/channel.ts:354`).
- `fetchHistory` is messaging-specific: `/v1/chat/sessions/{session}/messages`, unread filtering, chat message shape, and `/read` (`channel-core/src/api/chat.ts:16`, `channel-core/src/api/chat.ts:33`, `channel-core/src/api/chat.ts:44`, `channel-core/src/api/chat.ts:93`).

**Future seam:** when messages/chat become apps, this fetch/read/ack logic should either move to the comms app client or become app-specific event hydration. The generic core subscriber should not grow subject/thread/chat/read-receipt semantics.

### Reusable core with messaging envelope caveat: verification and trust

- Reusable crypto: canonical JSON escaping/signature verification over Ed25519 lives in `identity/signing.ts` (`channel-core/src/identity/signing.ts:38`, `channel-core/src/identity/signing.ts:135`, `channel-core/src/identity/signing.ts:178`).
- Messaging caveat: the current `MessageEnvelope` includes `subject`, `body`, `type`, `message_id`, and `conversation_id` (`channel-core/src/identity/signing.ts:8`), so this exact envelope is a comms-app construct, not the future opaque signed app envelope.
- Mail/chat callers verify either server-provided signed payload or legacy reconstructed envelope (`channel-core/src/api/mail.ts:106`, `channel-core/src/api/mail.ts:121`, `channel-core/src/api/chat.ts:102`, `channel-core/src/api/chat.ts:116`).
- Reusable trust layer: `SenderTrustManager.normalizeTrust` checks recipient binding, verifies stable global identity through registry, applies custody/TOFU pin logic, and handles rotation/replacement announcements (`channel-core/src/identity/trust.ts:76`, `channel-core/src/identity/trust.ts:116`, `channel-core/src/identity/trust.ts:148`, `channel-core/src/identity/trust.ts:175`, `channel-core/src/identity/trust.ts:327`, `channel-core/src/identity/trust.ts:357`).
- Reusable registry/pins: registry verification and TOFU pin store are identity substrate, not messaging semantics (`channel-core/src/identity/registry.ts:112`, `channel-core/src/identity/registry.ts:159`, `channel-core/src/identity/registry.ts:371`, `channel-core/src/identity/pinstore.ts:11`, `channel-core/src/channel.ts:15`).

### Messaging-semantic seam: local decryption commands

- `resolveMailForDelivery` and `resolveChatForDelivery` only inject plaintext after local decrypt succeeds (`channel-core/src/channel.ts:380`, `channel-core/src/channel.ts:400`). On failure they emit metadata-only encrypted failure awakenings (`channel-core/src/channel.ts:259`, `channel-core/src/channel.ts:319`, `channel-core/src/channel.ts:424`). This boundary is reusable.
- The current decrypt provider is comms-specific: it shells out to `aw mail show` and `aw chat history` (`channel-core/src/local_aw.ts:19`, `channel-core/src/local_aw.ts:25`, `channel-core/src/local_aw.ts:37`). Future app-encrypted event payloads need app-specific local decrypt/hydration or a generic app envelope decrypt primitive.

### Reusable AS-IS: semantic awakenings and host-neutral dispatch

- `startChannelLoop` wires the SSE generator to `dispatchAgentEvent`, adds persistent delivery de-dupe, and logs dispatch errors (`channel-core/src/channel.ts:154`, `channel-core/src/channel.ts:162`, `channel-core/src/channel.ts:164`).
- `dispatchAgentEvent` maps raw core events into host-neutral `ChannelAwakening` objects (`channel-core/src/channel.ts:172`). Control events become `deliveryIntent: "steer"` (`channel-core/src/channel.ts:184`); work/claim events become `ambient` (`channel-core/src/channel.ts:198`, `channel-core/src/channel.ts:209`, `channel-core/src/channel.ts:222`).
- Mail/chat metadata includes trust status and `verified` flag (`channel-core/src/channel.ts:269`, `channel-core/src/channel.ts:329`, `channel-core/src/channel.ts:446`). `formatAwakeningForAgent` renders the generic injected form with warning on untrusted sender (`channel-core/src/channel.ts:450`, `channel-core/src/channel.ts:455`).

**Future seam:** preserve `deliveryIntent` and `meta` as the host adapter contract; make event kinds/app metadata capable of carrying app-emitted wakes without hard-coding comms concepts into the core loop.

## `channel/` (`@awebai/claude-channel`) detailed map

### Reusable AS-IS host adapter

- Runtime entry imports the reusable core pieces from `@awebai/channel-core` (`channel/src/index.ts:8`, `channel/src/index.ts:20`), declared as `file:../channel-core` (`channel/package.json:31`).
- It resolves config, creates the client, pin store, registry resolver, and trust manager (`channel/src/index.ts:25`, `channel/src/index.ts:28`, `channel/src/index.ts:31`).
- It exposes an MCP stdio server with experimental `claude/channel` capability (`channel/src/index.ts:39`, `channel/src/index.ts:42`, `channel/src/index.ts:56`).
- Its instructions deliberately enforce one-way inbound events and outbound via `aw` CLI (`channel/src/index.ts:45`).
- It maps each core awakening to Claude Code `notifications/claude/channel` with `{content, meta}` (`channel/src/index.ts:63`, `channel/src/index.ts:75`, `channel/src/index.ts:76`).

### Local duplicate-code caveat

- `channel/src/api`, `channel/src/identity`, and `channel/src/config.ts` still exist and tests import them (`channel/test/client.test.ts:2`, `channel/test/config.test.ts:7`, `channel/test/conversation_verification.test.ts:5`). Runtime imports `channel-core`, so these files are compatibility/test debt rather than the active adapter path.

## `pi-extension/` (`@awebai/pi`) detailed map

### Reusable AS-IS host adapter

- Runtime imports the same core primitives from `@awebai/channel-core` (`pi-extension/src/index.ts:3`, `pi-extension/src/index.ts:9`), declared as `file:../channel-core` (`pi-extension/package.json:35`).
- It resolves `aw` from PATH or bundled `@awebai/aw`, then checks `aw workspace status` before starting (`pi-extension/src/index.ts:62`, `pi-extension/src/index.ts:75`, `pi-extension/src/index.ts:193`, `pi-extension/package.json:32`). This is adapter/onboarding behavior, not event semantics.
- On `session_start`, it resolves config, constructs client/pins/registry/trust, sets UI status, sends one-time welcome, and starts the core channel loop with `workdir: ctx.cwd` for local decrypt (`pi-extension/src/index.ts:179`, `pi-extension/src/index.ts:210`, `pi-extension/src/index.ts:221`, `pi-extension/src/index.ts:233`, `pi-extension/src/index.ts:243`, `pi-extension/src/index.ts:253`).
- Turn lifecycle events update dispatcher state (`pi-extension/src/index.ts:165`, `pi-extension/src/index.ts:169`).

### Reusable AS-IS wake mapping

- `deliveryOptionsForAwakening` maps core delivery intent to Pi delivery: `ambient -> nextTurn`, `steer -> steer` (+ trigger when idle), normal wake -> trigger if idle or follow-up if active (`pi-extension/src/wake.ts:74`, `pi-extension/src/wake.ts:79`, `pi-extension/src/wake.ts:83`, `pi-extension/src/wake.ts:91`).
- `createWakeDispatcher` queues awakenings, formats with core `formatAwakeningForAgent`, sends displayed `customType: "aweb-channel"` messages with metadata details, and logs failures (`pi-extension/src/wake.ts:100`, `pi-extension/src/wake.ts:120`, `pi-extension/src/wake.ts:128`, `pi-extension/src/wake.ts:141`).

### Reusable packaging pattern, content evolves

- Build syncs canonical root skills into the Pi package (`pi-extension/package.json:21`). Package metadata exposes both extension and skills to Pi (`pi-extension/package.json:45`, `pi-extension/package.json:49`). The packaging mechanism is reusable; skill text will evolve with the CLI/app restructuring.

## Validation

Ran in the main checkout.

- `channel-core`: `npm run build` passed. `npm test` is unavailable (`Missing script: "test"`; package scripts only include build/publish) (`channel-core/package.json:14`).
- `channel`: `npm run build` passed; `npm test` passed (12 test files, 105 tests) (`channel/package.json:18`, `channel/package.json:23`).
- `pi-extension`: `npm run build` passed; `npm test` passed (7 tests) (`pi-extension/package.json:23`, `pi-extension/package.json:25`).
- After validation, `git status --short channel-core channel pi-extension` was clean.

Only this new map file is intended for commit; other restructuring/SOT files in the shared main checkout belong to teammates' concurrent work.
