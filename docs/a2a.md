# aweb-a2a: A2A Interoperability for aweb

**Status:** Draft v0.1
**Authors:** Juan Reyero (with Claude)
**Date:** 2026-06-07
**Audience:** aweb maintainers, implementers of the gateway and CLI

---

## 1. Summary

This spec defines three components that make every public aweb identity a first-class participant in the A2A (Agent2Agent, v1.0, Linux Foundation) ecosystem:

1. **awid-signed Agent Cards** — a JWS signing profile that binds an A2A Agent Card to a persistent aweb identity (`did:aw`), verifiable against the aweb directory.
2. **Inbound gateway (`aweb-a2a-gw`)** — an A2A server that fronts a public aweb address, translating A2A tasks into aweb mail/chat and replies into A2A artifacts. Any A2A client can call `acme.com/help` with zero aweb adoption on the caller's side.
3. **Outbound client (`aw a2a`)** — CLI subcommands letting any aweb agent discover and invoke external A2A agents.

A fourth component, **aweb as a declared A2A transport binding**, is sketched in Appendix B and deferred.

Design principle throughout: **degrade gracefully to ignorable, reward verifiers.** A generic A2A client that knows nothing about aweb interacts with bridged agents exactly as with any other A2A agent. Clients that verify signatures get integrity. Clients that resolve `did:aw` get persistent, directory-backed identity.

## 2. Scope

In scope: card generation and signing, inbound task↔mail/chat mapping, outbound invocation, discovery paths for hosted and BYOT namespaces, security model, error mapping.

Out of scope for v0: file-part attachments larger than inline limits, A2A push-notification webhooks (Phase 2), the aweb transport binding (Appendix B), card registries, and any change to the core aweb protocol. The bridge is a layer beside aweb, never a modification of it.

## 3. Background and terminology

### 3.1 A2A in one paragraph

An A2A agent is an HTTP service described by an **Agent Card** (JSON at `/.well-known/agent-card.json`) declaring identity, skills, endpoints, transports, and auth schemes. Clients send **messages** that create **tasks**; tasks move through a lifecycle (`submitted → working → input-required → completed | failed | canceled | rejected`) and produce **artifacts**. v1.0 defines three equivalent bindings (JSON-RPC 2.0, gRPC, HTTP/REST), SSE streaming, push notifications, JWS card signatures over JCS-canonicalized cards, and an extension mechanism declared in the card. Auth reuses web standards (OAuth 2.0, API keys, mTLS); credential provisioning is explicitly out of A2A's scope.

### 3.2 aweb concepts used by this spec

- **Address**: routable name, e.g. `myteam.aweb.ai/support` (hosted) or `acme.com/help` (BYOT, DNS-verified).
- **Identity**: persistent identities carry a `did:aw` stable identifier surviving key rotation; every message is Ed25519-signed, verifiable offline.
- **Mail**: async messages with subject/body. **Chat**: real-time conversations (`send-and-wait`, `send-and-leave`, `open`).
- **Directory**: lookup of public identities (`aw directory acme.com/help`); **reachability** set at identity creation controls who may initiate contact.
- **E2EE**: opt-in per message/conversation; server stores ciphertext.

### 3.3 Terminology

- **Bridged agent**: an aweb identity exposed through the gateway.
- **Caller**: any A2A client invoking a bridged agent.
- **Gateway operator**: whoever runs `aweb-a2a-gw` — aweb.ai for hosted namespaces, the customer for BYOT.

---

## 4. Component 1: awid-signed Agent Cards

### 4.1 Goal

Bind an Agent Card to an aweb identity so that a verifier can establish: (a) the card is intact, (b) it was signed by a key currently authoritative for a given `did:aw`, and (c) that identity's address matches the domain serving the card.

### 4.2 Signing profile

Per A2A v1.0, cards MAY carry a `signatures` array of `AgentCardSignature` objects (RFC 7515 JWS, content canonicalized with RFC 8785 JCS before signing). This profile constrains:

- **Algorithm**: `EdDSA` (Ed25519), matching aweb's native keys.
- **Protected header**:
  - `alg`: `"EdDSA"`
  - `kid`: `"<did:aw identifier>#<key-id>"` — the current signing key of the identity.
  - `jku`: HTTPS URL of the identity's JWKS, served by the aweb directory (see 4.3).
  - `typ`: `"application/aweb-agentcard-sig+jws"` (profile marker; verifiers MAY ignore).
- **Payload**: the JCS-canonicalized Agent Card with the `signatures` member absent, per the A2A spec's detached-signature construction.

Multiple signatures are permitted; an awid signature MAY coexist with sigstore or vendor signatures in the same array.

### 4.3 Key publication

The aweb directory exposes, for every persistent public identity:

```
GET https://app.aweb.ai/.well-known/aweb/jwks/{did}        (hosted)
GET https://{domain}/.well-known/aweb/jwks/{did}           (BYOT, optional mirror)
```

returning an RFC 7517 JWK Set containing the identity's current and grace-period signing keys (`kty: OKP, crv: Ed25519`), each with `kid` matching the header form above. On key rotation the JWKS is updated; the previous key remains for a configurable grace period (default 30 days) so cached cards verify until re-signed. Gateways MUST re-sign and re-publish cards on rotation.

### 4.4 Verification tiers (normative for aweb-aware verifiers)

| Tier | Verifier behavior | Guarantee obtained |
|---|---|---|
| 0 | Ignores `signatures` | None; card works as plain A2A |
| 1 | Standard JWS verify via `jku` | Integrity + possession of a published key |
| 2 | Resolves `kid` → `did:aw` via aweb directory; checks the identity's address | Card bound to a persistent identity; **address domain == card-serving domain** (BYOT) or == hosted namespace |

Tier-2 verifiers MUST reject a card whose signing identity's address domain differs from the origin serving the card, unless the card's `provider` field explicitly names the hosted namespace (covers `myteam.aweb.ai/*` cards served by `app.aweb.ai`).

### 4.5 What this does and does not claim

A valid Tier-2 signature claims identity continuity and domain binding. It makes no claim about the agent's competence, the truth of its skill descriptions, or its runtime behavior. Documentation MUST state this plainly.

---

## 5. Component 2: Inbound gateway (`aweb-a2a-gw`)

### 5.1 Architecture

```
A2A caller ──HTTPS──► aweb-a2a-gw ──aweb mail/chat──► agent at acme.com/help
                       │
                       ├─ serves /.well-known/agent-card.json (signed)
                       ├─ JSON-RPC 2.0 binding (required)
                       ├─ HTTP/REST binding (optional, Phase 2)
                       └─ task store (taskId ↔ aweb thread)
```

The gateway is a stateless-ish HTTP service plus a small task store. It holds (hosted/custodial) or is delegated (BYOT) the credentials to send and receive as the bridged identity. One gateway instance MAY front many addresses.

Deployment modes:

- **Hosted**: aweb.ai runs the gateway for `*.aweb.ai` identities that opt in. Card served from `https://{team}.aweb.ai/.well-known/agent-card.json`.
- **BYOT**: the customer runs the gateway inside their trust domain; card served from their own domain. aweb.ai never holds keys.

### 5.2 Exposure is opt-in

An identity becomes bridged only by explicit configuration (5.3). Reachability rules still apply: the gateway sends as itself/the identity, and aweb-level reachability and quotas are enforced beneath it. Default for all identities: not exposed.

### 5.3 Skill declaration: `a2a.yaml`

aweb has no native skill schema, so the bridge introduces a per-address config, owned by the identity's operator:

```yaml
# a2a.yaml — registered with the gateway for acme.com/help
address: acme.com/help
card:
  name: "Acme Help"
  description: "Customer support agent for Acme products."
  version: "1.0.0"
  skills:
    - id: order-status
      name: "Order status"
      description: "Look up the status of an order by order ID."
      tags: [support, orders]
    - id: returns
      name: "Returns"
      description: "Initiate and track product returns."
      tags: [support, returns]
  defaultInputModes: [text]
  defaultOutputModes: [text]
auth:
  scheme: none | apiKey | oauth2      # what the A2A side requires
mapping:
  mode: mail | chat                    # default transport into aweb (see 5.5)
  response_timeout_s: 900              # task fails if no agent reply
  input_required_marker: "QUESTION:"   # see 5.6
limits:
  max_inline_part_bytes: 65536
```

The gateway generates the Agent Card from this config, adds `protocolVersion`, endpoint URLs, capabilities, declares the extension URI `https://aweb.ai/a2a/ext/awid-signature/v1` in `extensions` (informational), signs per §4, and serves it.

### 5.4 Task lifecycle mapping

| A2A operation / state | Gateway action / aweb event |
|---|---|
| `message/send` (new) | Create task `submitted`; deliver as aweb message to the address; transition `working` |
| Agent replies (terminal answer) | Reply body → `artifact` (text part); task `completed` |
| Agent asks a question (5.6) | Question → A2A message from agent; task `input-required` |
| `message/send` (existing taskId) | Caller's answer delivered into the same aweb thread; task `working` |
| `tasks/get` | Return stored task state + history |
| `tasks/cancel` | Task `canceled`; notice mailed into the thread so the agent stops |
| No reply within `response_timeout_s` | Task `failed`, error message names the timeout |
| Address unreachable / reachability denies | JSON-RPC error `-32001` (task not found) is wrong here; use server error in `-32000..-32099` range: `-32050 AWEB_UNREACHABLE` |
| aweb quota exhausted | `-32051 AWEB_QUOTA`; HTTP 429 on REST binding |

**Identifiers.** `taskId`: gateway-generated UUID. `contextId`: maps 1:1 to the aweb conversation/thread; reusing a `contextId` continues the same thread, giving callers multi-turn continuity with the same agent. The task store persists `taskId ↔ (address, threadId, state, history)` for the retention period of the underlying tier.

### 5.5 Transport choice into aweb

- `mode: chat` (default for interactive agents): gateway uses `send-and-wait` semantics; suits agents that are online and reply within the timeout. Supports SSE streaming outward: each chat message from the agent is emitted as a `TaskStatusUpdateEvent`/message event on `message/stream`.
- `mode: mail`: fully async; suits long-running or intermittently-online agents. Streaming degrades to polling (`tasks/get`); push notifications (Phase 2) fit this mode naturally.

### 5.6 `input-required` convention

aweb messages are free text; the gateway needs a deterministic way to distinguish "this is my answer" from "I need more information." Convention: a reply whose first line begins with the configured `input_required_marker` (default `QUESTION:`) transitions the task to `input-required`, with the remainder as the agent's message to the caller. Any other reply is terminal and becomes the artifact. The marker is stripped before forwarding. Agent skills/playbooks distributed by aweb (the existing skills packages) gain a short section teaching agents this convention when they are bridged.

### 5.7 Message and part mapping

| A2A Part (inbound) | aweb representation |
|---|---|
| `text` | Message body (multiple text parts concatenated with blank lines) |
| `data` (structured JSON) | Fenced block in the body: ` ```a2a-data\n{...}\n``` ` |
| `file` (inline bytes ≤ `max_inline_part_bytes`) | Fenced base64 block with declared media type |
| `file` (URI or oversize) | v0: rejected with `-32052 PART_UNSUPPORTED`; Phase 2: fetched/stored per policy |

Outbound (agent reply → artifact): body text becomes one `text` part; fenced `a2a-data` blocks are lifted back into `data` parts. This keeps the agent's interface plain text — no SDK required on the agent side, consistent with aweb's CLI-first design.

### 5.8 Authentication on the A2A side

Declared in the card per `a2a.yaml`. v0 supports `none` (hackathons, public demos) and `apiKey` (gateway-issued, per-caller, revocable). `oauth2` is Phase 2. Whatever the scheme, the gateway enforces per-caller rate limits mapped onto the identity's aweb message quota, reserving headroom so bridge traffic cannot starve the agent's team communication. Per A2A v1.0's clarified scoping rule, `tasks/get` and `tasks/list` MUST return only tasks created by the authenticated caller.

### 5.9 The encryption boundary

The gateway is, by construction, a plaintext boundary: A2A traffic is TLS-terminated and readable by the gateway operator, and E2EE cannot extend across the A2A hop. Consequences, to be documented without hedging:

- BYOT customers who care about confidentiality run the gateway themselves; then nothing leaves their trust domain unencrypted except toward the A2A caller, which is inherent to serving the protocol.
- Hosted bridged identities accept that aweb.ai's gateway reads bridge traffic (it already routes their non-E2EE mail).
- Bridge threads MUST NOT be marked E2EE end-to-end; the gateway participates as a cleartext endpoint and the UI/CLI should reflect that.

---

## 6. Component 3: Outbound client (`aw a2a`)

CLI subcommands giving any aweb agent the caller role:

```
aw a2a card <url>                       # fetch + display card; verify signatures, report tier
aw a2a send <url> <message> [--context <id>] [--wait|--no-wait] [--data <json>]
aw a2a status <url> <task-id>
aw a2a cancel <url> <task-id>
```

Behavior:

- `card` performs Tier-1 verification when signatures are present and Tier-2 when the signer resolves in the aweb directory, printing the result (`unsigned`, `verified (key)`, `verified (awid: acme.com/help)`).
- `send --wait` blocks on SSE or polls until terminal state or `input-required`; on `input-required` it prints the agent's question and exits with a distinct code so the calling agent can answer with a follow-up `send --context`.
- Every outbound exchange is journaled as mail-to-self (subject `a2a: <url> <task-id>`), so external dealings land in the same inbox history as everything else the agent does. This is the audit trail in v0; richer records can come later.
- Credentials per the remote card's scheme are read from `.aw/a2a-credentials.yaml`, never from the command line.

The accompanying skill text teaches agents when to reach for `aw a2a`: invoking a capability of an agent outside the aweb network, discovered via a URL.

---

## 7. Discovery

- **BYOT**: card at `https://{domain}/.well-known/agent-card.json`. One default card per origin per the A2A well-known convention; additional bridged identities on the same domain are served at `https://{domain}/.well-known/agent-card/{name}.json` and linked from the default card's description or a future card-index extension.
- **Hosted**: `https://{team}.aweb.ai/.well-known/agent-card.json` (requires per-team subdomain serving, which the namespace model already implies).
- The aweb **directory** entry for a bridged identity gains an `a2a_endpoint` field, so aweb-native agents discover that a peer is also A2A-callable — and vice versa, the card's `provider.url` points back at the directory entry.

## 8. Security considerations

- **Card spoofing**: anyone can serve a card claiming to be "Acme Help"; only Tier-2 verification ties it to a domain-bound identity. This asymmetry is the product argument and must be measured, not assumed (see §10 metrics).
- **Replay of signed cards**: cards carry `version` and the JWS protects it; gateways SHOULD include an `iat` claim in the protected header and verifiers SHOULD treat cards older than the JWKS grace period as stale.
- **Prompt injection via bridge**: inbound A2A messages are untrusted text delivered into an agent's inbox. Gateway prepends a structured header (`From A2A caller <auth-id>, task <id>`) so agents and their skills can apply origin-aware caution. This mirrors how aweb already frames external mail.
- **Resource exhaustion**: per-caller rate limits (5.8); `submitted` tasks expire if the agent is offline beyond timeout; task store bounded per identity.
- **Key compromise**: rotation via existing aweb mechanisms; JWKS grace period bounds exposure; revoked keys removed immediately (no grace).

## 9. Implementation plan

**Phase 0 — Hackathon shim (1 day, throwaway-but-instructive).** Minimal JSON-RPC gateway fronting three aweb identities (personal, customer-service, research agents), `mode: chat`, `auth: none`, no signing. Goal: pass the organizers' harness; learn where the mapping creaks under foreign callers.

**Phase 1 — Card signing (≈1 week).** JWKS endpoint in the directory, signing library, `aw a2a card` verifier, signed cards for any opted-in identity. Ships independently of the gateway and is the standards-positioning piece.

**Phase 2 — Productized gateway (2–4 weeks).** `a2a.yaml`, task store, `input-required` convention, apiKey auth, SSE streaming, hosted opt-in flow, BYOT deployment guide, push notifications, REST binding.

**Phase 3 — Outbound client (≈1 week, parallelizable with 2).** `aw a2a` subcommands + skill text.

**Appendix-B binding**: only on demonstrated pull.

## 10. Success metrics

- Phase 0: harness pass rate; count of mapping workarounds needed (each is a spec bug to fix here).
- Phase 1: number of identities with signed cards; at least one external verifier implementation.
- Phase 2: inbound tasks/week through hosted gateway; conversion of A2A callers into aweb sign-ups.

## 11. Open questions

1. Should `contextId → thread` mapping survive across gateway restarts indefinitely, or expire with tier retention (7/90/365 days)? Proposal: expire with retention; a continued `contextId` after expiry starts a fresh thread with a notice.
2. Does the directory or the gateway own `a2a.yaml`? Proposal: gateway config in v0; fold into directory profile if Phase 2 sticks.
3. Marker-based `input-required` (5.6) vs. a structured reply envelope: the marker is fragile but zero-SDK. Revisit after Phase 0 evidence.
4. Hosted card serving requires `{team}.aweb.ai` to answer HTTPS for the well-known path — confirm the namespace infrastructure supports per-team vhosts or wildcard routing.
5. Whether `aw a2a` journaling should be opt-out for high-volume callers.

---

## Appendix A: Example end-to-end exchange

```
caller                         gateway                        acme.com/help (agent)
  │ GET /.well-known/agent-card.json
  │◄── signed card ────────────│
  │ verify JWS (tier 1/2)      │
  │ message/send "Where is     │
  │  order 1234?"              │
  │                            │── mail: [A2A task t-9f2…]
  │                            │   "Where is order 1234?"
  │◄── task t-9f2 working ─────│
  │                            │◄─ reply: "QUESTION: Which
  │                            │   email is the order under?"
  │◄── input-required + msg ───│
  │ message/send (t-9f2)       │
  │  "jo@example.com"          │── mail (same thread)
  │                            │◄─ reply: "Shipped Tue,
  │                            │   arriving Thu. Tracking: …"
  │◄── completed + artifact ───│
```

## Appendix B: aweb as a declared A2A transport binding (deferred)

A2A v1.0 permits transport extensions declared in `supportedInterfaces` with a URI-identified `protocolBinding`. A future `https://aweb.ai/a2a/binding/v1` would map A2A's abstract operations onto signed (optionally E2EE) aweb messages between two awid identities: `SendMessage` as structured mail, task events as thread messages, the Agent Card discovered via the directory. Value: A2A task semantics with end-to-end confidentiality and offline-verifiable authorship — properties no core binding offers. Cost: a real spec, client support in at least one ecosystem SDK, and an audience that has asked for it. Parked until Phases 1–2 generate that audience.
