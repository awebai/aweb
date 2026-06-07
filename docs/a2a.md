# aweb-a2a: A2A Interoperability for aweb

**Status:** Draft v0.2 product contract
**Authors:** Juan Reyero, Grace, Athena
**Date:** 2026-06-07
**Audience:** aweb maintainers, awid maintainers, A2A gateway implementers, CLI implementers

---

## 1. Summary

A2A standardizes how agents communicate once a client has an Agent Card. It keeps discovery and durable identity deliberately minimal. aweb and awid supply the missing product layer: names that resolve, persistent agent identity, key rotation history, delegation, and directory discovery.

This contract defines the product path for making aweb identities first-class participants in the A2A ecosystem without creating a hackathon-only adapter:

1. **A2A gateway (`aweb-a2a-gw`)**: a real gateway service that exposes existing aweb agents as normal A2A agents through schema-correct Agent Cards and JSON-RPC endpoints.
2. **AWID A2A publication assertions**: durable registry facts that bind an aweb address to a card URL, route, gateway identity, card digest, expiry, and delegation. AWID is the trust registry, not the default runtime card host.
3. **Signed/delegated Agent Card profile**: A2A Agent Card signatures and/or delegation chains that aweb-aware verifiers can resolve through AWID.
4. **Outbound `aw a2a` client**: CLI support for aweb agents to inspect and call external A2A agents.

A future **native aweb A2A transport binding** is explicitly deferred. The gateway is a compatibility bridge for standard A2A HTTP clients. The native binding would be a protocol proposal that maps A2A task semantics onto signed/E2EE aweb messages; it should only be built after external demand exists.

Design principle: **normal A2A for generic clients, stronger verification for aweb-aware clients**. Generic clients use ordinary card URLs and JSON-RPC. aweb-aware clients can ask AWID whether the card is the active publication for a durable address and whether the gateway is authorized.

## 2. Scope

In scope:

- A2A v1.0 Agent Card generation and validation.
- Root well-known card plus per-address direct card URL conventions.
- JSON-RPC gateway for `SendMessage`, `GetTask`, `ListTasks`, and `CancelTask`.
- Optional `SendStreamingMessage` when task event streaming is available.
- Mapping A2A tasks to durable aweb messages and agent replies.
- AWID A2A publication and bridge delegation data model.
- A2A card verification tiers in `aw a2a card`.
- Security, custody, plaintext boundary, and product terminology.

Out of scope for the first product slice:

- A2A push-notification methods.
- gRPC binding.
- HTTP/REST binding beyond direct card serving.
- File parts and large attachments.
- Native aweb transport binding.
- Generic A2A card registry API standardization.
- Any claim that hosted A2A bridge traffic is end-to-end encrypted.

## 3. A2A and aweb Concepts

### 3.1 A2A Concepts Used Here

An A2A agent is an HTTP service described by an **Agent Card**. The conventional generic discovery URL is:

```text
https://{host}/.well-known/agent-card.json
```

An Agent Card declares skills, supported interfaces, protocol binding, protocol version, capabilities, input/output media types, and auth requirements. A2A v1.0 supports multiple protocol bindings; this contract targets **JSON-RPC** first.

The JSON-RPC method names in this contract use the A2A v1.0 names:

- `SendMessage`
- `SendStreamingMessage`
- `GetTask`
- `ListTasks`
- `CancelTask`
- `SubscribeToTask` (deferred)

Task states in wire-level examples use the A2A v1.0 enum names:

- `TASK_STATE_SUBMITTED`
- `TASK_STATE_WORKING`
- `TASK_STATE_INPUT_REQUIRED`
- `TASK_STATE_COMPLETED`
- `TASK_STATE_FAILED`
- `TASK_STATE_CANCELED`
- `TASK_STATE_REJECTED`

Human-facing prose may say "submitted", "working", or "completed", but implementation tables and fixtures MUST use exact A2A names.

### 3.2 aweb and AWID Concepts Used Here

- **aweb address**: routable name such as `acme.com/help` or `team.aweb.ai/support`.
- **AWID identity**: durable `did:aw` identity with current `did:key` and signed, hash-chained key history.
- **AWID registry**: DNS-rooted, federated registry for identities, addresses, delegation, and public directory data.
- **aweb agent**: an agent with a workspace, `.aw` state, role instructions, and mail/chat identity.
- **Bridge gateway identity**: the gateway's own aweb/AWID identity. It is not the same as the bridged agent identity unless explicitly hosted-custodial.
- **A2A publication assertion**: AWID fact saying an address is exposed through a card URL/route/gateway under a specific digest and expiry.
- **Bridge delegation**: AWID fact authorizing a gateway identity to bridge for an address under scoped conditions.

### 3.3 Product Framing

A2A answers: "Given this card/endpoint, how do I talk to the agent?"

AWID answers: "What durable identity and authority stands behind this agent name/card/delegation?"

The product claim is not "aweb competes with A2A." The product claim is:

> A2A is the interop protocol. AWID is the naming, identity continuity, and publication registry layer A2A leaves open.

## 4. Discovery Model

### 4.1 Root Well-Known Discovery

The only URL this contract calls **standard well-known discovery** is:

```text
https://{host}/.well-known/agent-card.json
```

For each host served by a gateway, the root card represents either:

1. a configured default bridged agent, or
2. a gateway/router agent that can route generic callers at a high level.

Root behavior:

- If exactly one bridged address exists for a host, the root card MAY default to that agent.
- If multiple bridged addresses exist, the operator MUST choose either an explicit default agent or a router card.
- The gateway MUST NOT silently choose one address as default when more than one exists.

### 4.2 Per-Address Direct Cards

Every bridged aweb address gets a stable direct card URL:

```text
https://{host}/a2a/agents/{route_id}/agent-card.json
```

This is not well-known discovery. It is a normal direct Agent Card URL suitable for:

- direct configuration;
- catalogs/registries;
- AWID directory discovery;
- event submissions that accept explicit Agent Card URLs.

Use `/a2a/agents/...`, not `/.well-known/a2a/...`, for non-standard per-address cards. The root `/.well-known/agent-card.json` remains the only well-known convention.

### 4.3 Per-Address JSON-RPC Endpoints

The direct card's default JSON-RPC interface SHOULD use a path-routed endpoint:

```text
https://{host}/a2a/agents/{route_id}/rpc
```

For direct per-address cards, `supportedInterfaces[].tenant` SHOULD be omitted by default. Path routing is easier for generic clients and avoids depending on tenant handling in every client.

`AgentInterface.tenant` remains supported for shared gateway/router cards and aweb-aware directory-discovered shared endpoints. Tenant is a routing primitive, not a discovery primitive.

### 4.4 Aweb-Aware Discovery Through AWID

AWID/directory discovery maps aweb addresses to A2A metadata:

```yaml
address: acme.com/help
did_aw: did:aw:...
a2a:
  card_url: https://acme.com/a2a/agents/r_help_01/agent-card.json
  rpc_url: https://acme.com/a2a/agents/r_help_01/rpc
  route_id: r_help_01
  tenant: null
  gateway_identity: did:aw:...
  card_digest: sha256:...
  publication_expires_at: "2026-07-07T00:00:00Z"
  verification: awid_published | delegated | unsigned | expired | mismatch
```

Generic A2A clients do not need AWID. aweb-aware clients use AWID to discover exact per-address cards and verify the publication.

## 5. Agent Card Shape

### 5.1 Required Interface Shape

Generated cards MUST use A2A v1.0 field names and media-type input/output modes. A per-address card has this shape conceptually:

```json
{
  "name": "Acme Help",
  "description": "Customer support agent for Acme products.",
  "provider": {
    "organization": "Acme",
    "url": "https://acme.com"
  },
  "version": "1.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "extensions": [
      {
        "uri": "https://aweb.ai/a2a/ext/awid-publication/v1",
        "description": "AWID publication and delegation metadata"
      }
    ]
  },
  "securitySchemes": {},
  "securityRequirements": [],
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "supportedInterfaces": [
    {
      "url": "https://acme.com/a2a/agents/r_help_01/rpc",
      "protocolBinding": "JSONRPC",
      "protocolVersion": "1.0"
    }
  ],
  "skills": [
    {
      "id": "order-status",
      "name": "Order status",
      "description": "Look up order status from an order ID.",
      "tags": ["support", "orders"]
    }
  ]
}
```

Cards MAY include additional A2A v1.0 fields. Implementation MUST validate generated cards against pinned A2A schema/proto fixtures before release.

### 5.2 Root Router Card

When a host has multiple bridged addresses and no explicit default, the root card can describe a router:

```json
{
  "name": "Acme A2A Gateway",
  "description": "A2A gateway for Acme agents. Exact agent cards are published in the Acme/aweb directory.",
  "provider": {
    "organization": "Acme",
    "url": "https://acme.com"
  },
  "version": "1.0.0",
  "capabilities": {
    "streaming": false,
    "pushNotifications": false,
    "extensions": [
      {
        "uri": "https://aweb.ai/a2a/ext/awid-publication/v1",
        "description": "AWID publication and delegation metadata"
      }
    ]
  },
  "securitySchemes": {},
  "securityRequirements": [],
  "defaultInputModes": ["text/plain"],
  "defaultOutputModes": ["text/plain"],
  "supportedInterfaces": [
    {
      "url": "https://acme.com/a2a/rpc",
      "protocolBinding": "JSONRPC",
      "protocolVersion": "1.0"
    }
  ],
  "skills": [
    {
      "id": "route-to-agent",
      "name": "Route to Acme agents",
      "description": "Routes customer tasks to configured Acme agents when enough information is provided.",
      "tags": ["router"]
    }
  ]
}
```

The router card is for generic discovery. It MUST NOT imply that generic clients can enumerate every named agent under the domain unless the card explicitly provides such a product feature.

## 6. AWID A2A Publication Assertions

### 6.1 Principle

AWID is the registry for identity/address/delegation facts. It is not the default canonical runtime store for mutable Agent Card bodies.

An agent or operator does not primarily "upload an Agent Card to AWID." It publishes an **A2A service binding assertion**:

> address X / did:aw Y is exposed through card URL U, RPC URL V, route R, gateway identity G, card digest H, revision N, and expiry T.

### 6.2 Assertion Fields

The first product contract for an AWID A2A publication assertion MUST include:

```yaml
operation: a2a_publish_card
assertion_id: a2a-pub-...
address: acme.com/help
did_aw: did:aw:...
identity_did_key: did:key:...
signer_did: did:aw:...
signer_kid: did:aw:...#key-...
card_url: https://acme.com/a2a/agents/r_help_01/agent-card.json
rpc_url: https://acme.com/a2a/agents/r_help_01/rpc
route_id: r_help_01
tenant: null
gateway_identity: did:aw:...
delegation_id: a2a-delegation-...
delegation_ref: awid://delegations/a2a-delegation-...
delegation_digest: sha256:...
card_digest_alg: sha256
card_digest: sha256:...
card_revision: 3
default_for_host: false
status: active
published_at: "2026-06-07T00:00:00Z"
expires_at: "2026-07-07T00:00:00Z"
registry_url: https://api.awid.ai
```

`card_digest` is load-bearing. Aweb-aware Tier-2 verification MUST reject or hard-warn when the served card digest does not match the active AWID publication assertion.

Material Agent Card changes require republishing the assertion with a new digest/revision. This is intentional: an Agent Card is a public service contract, not per-request dynamic state.

The assertion MUST identify the exact signed publication and delegation material used for verification. If AWID's existing revocation/event-log model supplies assertion ids, signer ids, and delegation references indirectly, the implementation can derive these fields from that model, but the verifier must still be able to report the exact assertion and delegation it trusted.

Revocation follows the AWID event/revocation model: a revoked publication or revoked delegation is not active even if its expiry is in the future.

### 6.3 Publication Authority

Allowed publication authority depends on custody:

| Address / identity custody | Who can publish A2A binding | Notes |
|---|---|---|
| Self-custodial personal/global identity | identity signing key | The agent/operator signs the publication assertion. |
| Self-custodial team address | team/address authority defined by AWID team/address rules | Must not require handing the agent key to the gateway. |
| Hosted-custodial identity | hosted service authority for that identity | Must be labeled hosted-custodial/plaintext bridge. |
| Delegated bridge | address/team authority signs delegation to gateway identity | Gateway signs cards or bridge messages under scoped delegation. |

AWID publication is separate from A2A card serving. Generic A2A clients can ignore it.

### 6.4 Optional Card Cache

AWID MAY later cache/mirror full Agent Cards for audit, availability, or "what did this address claim at time T?" views. That cache is not the authoritative runtime endpoint unless a later contract explicitly changes this model.

## 7. Signed and Delegated Agent Cards

### 7.1 A2A Signature Semantics

A2A Agent Cards MAY carry a `signatures` array. The signing profile MUST follow A2A v1.0 semantics:

- The card is canonicalized according to the A2A/JCS signing rules with the `signatures` field absent.
- The JWS signing input is the protected header plus `.` plus base64url payload, as defined by JWS.
- The protected header MUST include `alg`, `typ`, and `kid`.
- `typ` SHOULD remain the A2A/JWS-compatible value expected by validators, such as `JOSE`; do not use a custom MIME marker unless validator compatibility is proven.
- The aweb profile marker belongs in `capabilities.extensions` and AWID publication metadata, not in a custom `typ` by default.

### 7.2 JWKS and `jku`

Verifiers MUST NOT blindly trust arbitrary `jku` URLs in a card signature.

Aweb-aware verification derives or allowlists JWKS location from AWID/directory state:

1. Fetch card.
2. Compute card digest.
3. Resolve address/card publication through AWID.
4. Verify digest, signer, delegation, expiry, and key history.
5. Only then fetch/accept the expected JWKS or public key material.

### 7.3 Verification Tiers

| Tier | Behavior | Guarantee |
|---|---|---|
| 0 | Ignore signatures/publication | Plain A2A interop only. |
| 1 | Verify card JWS with trusted key/JWKS | Card integrity and possession of signing key. |
| 2 | Verify AWID publication, digest, signer/delegation, and key history | Durable aweb identity/address binding with rollback/split-view protection from AWID. |

Tier 2 does not claim the agent is competent or truthful. It claims identity continuity, publication authority, and card integrity.

### 7.4 Direct vs Delegated Signing

Supported signing models:

- **Direct identity card**: the bridged identity/address authority signs the card and publishes the AWID assertion.
- **Delegated bridge card**: the gateway identity signs the card; AWID stores a delegation from the address/team authority to the gateway identity scoped to route, card URL, RPC URL, operations, and expiry.
- **Hosted-custodial card**: hosted authority signs/publishes for hosted identities. The card/directory MUST label hosted bridge/plaintext boundary.

Self-custodial/BYOT gateways MUST NOT require the bridged agent's private key.

## 8. Gateway Architecture

### 8.1 Product Path

`aweb-a2a-gw` is a real product service, not a throwaway hackathon adapter.

```text
A2A caller
  -> HTTPS JSON-RPC
  -> aweb-a2a-gw
  -> durable aweb message to real agent
  -> agent replies through aweb
  -> gateway updates A2A task/artifact
```

The first deployment can front three aweb agents running on Hetzner, but it MUST use the same gateway/card/task architecture that product deployments use.

### 8.2 Gateway Identity

The gateway has its own aweb/AWID identity and workspace. It does not secretly impersonate self-custodial bridged agents.

For operator-configured internal/event routes before AWID delegation enforcement exists:

- the gateway identity is configured to bridge route -> address;
- every message to the agent includes structured metadata naming the A2A caller, task id, route id, target address, and gateway identity;
- docs/cards MUST label this as locally configured/unverified delegation, not AWID-verified delegation.
- customer-facing UI, CLI, cards, and docs MUST NOT call the route "verified", "AWID-backed", or "authorized for address X" until AWID publication and delegation checks are enforced. Operator-configured routes are only "configured by gateway operator."

For product-trusted external routes:

- AWID publication assertion is active;
- AWID bridge delegation is active;
- served card digest matches the AWID assertion;
- gateway key matches delegation;
- expiry and route scope are enforced.

### 8.3 Gateway Configuration

Gateway config is the source of operational card generation in v0:

```yaml
host: a2a.aweb.ai
root_card:
  mode: router # router | default_agent
  default_route_id: null
routes:
  - route_id: personal
    address: demo.aweb.ai/personal
    rpc_path: /a2a/agents/personal/rpc
    card_path: /a2a/agents/personal/agent-card.json
    mode: mail
    response_timeout_s: 120
    auth:
      scheme: none
    limits:
      max_tasks_per_minute: 30
      task_expiry_s: 900
    card:
      name: "Personal Agent"
      description: "Personal agent for the A2A customer-service chain."
      version: "1.0.0"
      defaultInputModes: ["text/plain"]
      defaultOutputModes: ["text/plain"]
      skills:
        - id: customer-intake
          name: "Customer intake"
          description: "Receives customer requests and coordinates with service agents."
          tags: ["personal", "customer-service"]
    awid_publication:
      required: false
      expected_digest: null
      expires_at: null
```

When AWID publication is enabled, config MUST not override AWID truth silently. Conflicts fail closed.

## 9. Gateway Task Mapping

### 9.1 Required JSON-RPC Methods

First product/event slice MUST implement:

- `SendMessage`
- `GetTask`
- `ListTasks`
- `CancelTask`

`SendStreamingMessage` SHOULD be implemented if task event streaming is available. It can be built on the same task store and event updates.

Deferred:

- `SubscribeToTask`
- push notification config methods
- `GetExtendedAgentCard`

### 9.2 `SendMessage`

On new A2A message:

1. Validate method, route, auth, caller scope, supported parts, and text media type.
2. Create task row with state `TASK_STATE_SUBMITTED`.
3. Convert inbound text parts into an aweb bridge message.
4. Send durable aweb message to the target agent.
5. Transition task to `TASK_STATE_WORKING`.
6. Return task immediately, optionally waiting up to a short configured window for a reply.

The gateway MUST NOT require synchronous agent liveness for `SendMessage` to succeed unless the route is explicitly configured as sync-only.

For the product async path, A2A clients SHOULD send `configuration.returnImmediately: true`. In that case the gateway returns after creating/updating the task and sending the durable aweb bridge message.

If `configuration.returnImmediately` is absent or false, the gateway follows A2A semantics by waiting until the task reaches a terminal or interrupted state. If the route wait timeout expires before an agent reply, the gateway transitions the task to `TASK_STATE_FAILED` with a timeout message and returns that failed task. Callers that want durable async follow-up SHOULD set `configuration.returnImmediately: true` and poll `GetTask`.

Our own CLI mapping:

- `aw a2a send --no-wait` sets `configuration.returnImmediately: true`.
- `aw a2a send --wait` prefers `SendStreamingMessage`; if streaming is unavailable, it uses `SendMessage` without `returnImmediately` when supported, otherwise `SendMessage` with polling `GetTask`.

### 9.3 `GetTask`

Returns the task, current state, message history, and artifacts visible to the authenticated caller.

Tasks MUST be scoped by caller/auth context. One caller MUST NOT be able to fetch another caller's tasks by guessing task ids.

### 9.4 `ListTasks`

Returns only tasks created by the authenticated caller for the requested route/interface. Pagination is required before public product launch.

For unauthenticated public/event routes, caller scope MUST still be isolated. Acceptable v0 scopes include anonymous session cookie, explicit opaque task bearer token, or IP/token-bucket scope when no better identity exists. If the gateway cannot isolate unauthenticated callers safely, `ListTasks` MUST be disabled for that route and `GetTask` MUST require an unguessable task bearer token.

### 9.5 `CancelTask`

Marks task `TASK_STATE_CANCELED` and sends a cancellation notice into the aweb thread so the bridged agent can stop work. It cannot guarantee that a running external model call is interrupted.

### 9.6 `SendStreamingMessage`

When implemented, `SendStreamingMessage` uses the same task row and event stream. It can:

- stream `TASK_STATE_SUBMITTED` / `TASK_STATE_WORKING`;
- stream agent intermediate messages if the aweb side emits them;
- end with `TASK_STATE_COMPLETED`, `TASK_STATE_INPUT_REQUIRED`, `TASK_STATE_FAILED`, or `TASK_STATE_REJECTED`.

Streaming is not a separate execution path.

## 10. Aweb Bridge Message Format

### 10.1 Inbound Message to Agent

The gateway sends a durable aweb message containing structured task metadata and the caller's text. The exact envelope should be easy for an agent to read and easy for a gateway to parse.

Example:

````markdown
```a2a-task
{
  "task_id": "t_123",
  "context_id": "c_456",
  "route_id": "personal",
  "target_address": "demo.aweb.ai/personal",
  "gateway_identity": "did:aw:...",
  "caller_id": "api-key:demo-harness",
  "state": "TASK_STATE_WORKING"
}
```

Customer message:

Where is order 1234?
````

Agents MUST treat A2A caller content as untrusted external input.

### 10.2 Reply Envelope

Product v0 uses a structured fenced reply block. `QUESTION:` is accepted as compatibility sugar, not the long-term protocol.

Preferred reply:

````markdown
```a2a-reply
{
  "state": "completed",
  "artifacts": [
    {"type": "text", "text": "Order 1234 shipped Tuesday and arrives Thursday."}
  ]
}
```
````

Allowed `state` values in the block:

- `completed`
- `input_required`
- `failed`
- `rejected`
- `TASK_STATE_COMPLETED`
- `TASK_STATE_INPUT_REQUIRED`
- `TASK_STATE_FAILED`
- `TASK_STATE_REJECTED`

These are gateway-local bridge values, not the A2A wire object itself. The gateway accepts the lower-case aliases for zero-SDK agent ergonomics and the exact `TASK_STATE_*` names for future helpers/tooling.

Mapping:

| Agent reply | A2A task state |
|---|---|
| `a2a-reply` with `state: completed` | `TASK_STATE_COMPLETED` |
| `a2a-reply` with `state: input_required` | `TASK_STATE_INPUT_REQUIRED` |
| `a2a-reply` with `state: failed` | `TASK_STATE_FAILED` |
| `a2a-reply` with `state: rejected` | `TASK_STATE_REJECTED` |
| First line starts `QUESTION:` | `TASK_STATE_INPUT_REQUIRED` |
| No structured block | `TASK_STATE_COMPLETED`; full body is text artifact |

Future helper:

```bash
aw a2a-bridge reply --task <id> --completed --text "..."
aw a2a-bridge reply --task <id> --input-required --text "Which email is the order under?"
```

The helper is the product direction. The fenced block is the zero-SDK v0 bridge.

### 10.3 Part Support

First slice:

- inbound `text` parts only;
- outbound text artifacts only;
- data/file parts rejected with a structured unsupported-content error.

Data and file mapping are Phase 2.

## 11. Plaintext and E2EE Boundary

The A2A gateway is a plaintext boundary.

- A2A traffic is TLS-terminated and readable by the gateway operator.
- The gateway reads task text in order to bridge it.
- Hosted bridge routes MUST NOT be called end-to-end encrypted.
- BYOT customers needing confidentiality run their own gateway inside their trust boundary.
- Native aweb transport binding is the only path to A2A-like semantics with end-to-end encrypted aweb messages, and it is deferred.

Cards, docs, dashboard UI, and CLI output MUST say this plainly.

## 12. Outbound `aw a2a`

CLI surface:

```bash
aw a2a card <url>
aw a2a send <url> <message> [--context <id>] [--wait|--no-wait] [--data <json>]
aw a2a status <url> <task-id>
aw a2a cancel <url> <task-id>
```

Behavior:

- `card` fetches the card, validates schema, prints interface URLs, auth requirements, and verification tier.
- Tier-2 verification consults AWID publication assertions when the card maps to an aweb address.
- `send --wait` uses `SendStreamingMessage` when available, otherwise `SendMessage` plus polling `GetTask`.
- On `TASK_STATE_INPUT_REQUIRED`, the CLI exits with a distinct status and prints the question.
- Credentials are read from `.aw/a2a-credentials.yaml`, not command-line flags.
- Optional journaling to aweb mail-to-self can be enabled later; it should not be mandatory for high-volume callers.

## 13. Security Considerations

### 13.1 Card Spoofing

Anyone can serve a card claiming a name. Tier-2 AWID verification is what binds a card URL/digest/delegation to an address with identity history.

### 13.2 Gateway Impersonation

The gateway must not silently impersonate self-custodial agents. Messages sent by the gateway should be visibly from the gateway identity and include on-behalf-of metadata until a stronger product-specific sender model is designed.

### 13.3 Replay and Stale Cards

AWID publication assertions include digest, revision, and expiry. Aweb-aware verifiers reject expired assertions and digest mismatches.

### 13.4 Key Rotation

AWID key history is the source of identity continuity. Verifiers check the current key and history chain, not just one JWS key in isolation.

### 13.5 Resource Exhaustion

Gateway enforces:

- per-caller rate limits;
- per-route task limits;
- task expiry;
- maximum message size;
- bounded task history.

### 13.6 Prompt Injection

A2A caller content is external untrusted input. Gateway task envelopes must make origin/caller/task explicit in the agent-visible message.

## 14. Implementation Plan

### Phase 1: Spec Correction and Fixtures

- Patch this document to exact A2A v1.0 method/schema/enum/signature language.
- Add golden fixtures from pinned A2A proto/schema:
  - hosted default Agent Card;
  - BYOT default Agent Card;
  - BYOT multi-agent gateway/root router card;
  - `SendMessage` JSON-RPC request/response;
  - `GetTask` JSON-RPC request/response.
- Add schema validation tests for generated cards.
- Decide and document exact canonical digest bytes for cards.

### Phase 2: Gateway Skeleton and Cards

- Add `aweb-a2a-gw` service.
- Load route config.
- Serve root card and per-route cards.
- Generate path-routed `supportedInterfaces`, no tenant by default.
- Compute deterministic card digest.
- Mark cards unsigned/unverified until AWID publication is implemented.

### Phase 3: JSON-RPC Task Store

- Implement `SendMessage`, `GetTask`, `ListTasks`, `CancelTask`.
- Store task id, context id, caller scope, route id, state, aweb thread/message ids, history, artifacts.
- Validate caller scoping.
- Reject unsupported content types cleanly.

### Phase 4: Aweb Bridge Adapter

- Send structured `a2a-task` message to real aweb agent.
- Receive/poll/subscribe for replies.
- Parse `a2a-reply`, `QUESTION:`, and default-completed replies.
- Update task store.
- Deploy first three agents on Hetzner using normal aweb workspaces.

### Phase 5: AWID Publication and Delegation

- Define AWID A2A publication assertion.
- Define bridge delegation assertion.
- Add directory fields.
- Add `aw a2a card` Tier-2 verification.
- Enforce digest/delegation/expiry for product-trusted routes.

### Phase 6: Streaming and Product Hardening

- Implement `SendStreamingMessage`.
- Add optional API key/OAuth auth modes.
- Add metrics, logs, and operational dashboards.
- Add BYOT gateway deployment guide.

### Deferred: Native Aweb Transport Binding

Define only after external A2A clients show demand for A2A semantics over signed/E2EE aweb messages.

## 15. Hackathon Deployment Using Product Path

The A2A hackathon should use this product gateway, not bespoke throwaway SDK agents.

Initial event deployment:

```text
https://a2a.aweb.ai/a2a/agents/personal/agent-card.json
https://a2a.aweb.ai/a2a/agents/customer-service/agent-card.json
https://a2a.aweb.ai/a2a/agents/research/agent-card.json
```

Each card points at:

```text
https://a2a.aweb.ai/a2a/agents/{route}/rpc
```

Behind the gateway:

- three real aweb agents run on Hetzner;
- each has a normal workspace, role instructions, and `.aw` identity;
- gateway sends A2A task envelopes through aweb;
- agents reply with `a2a-reply` fenced blocks;
- gateway updates A2A tasks.

If event infrastructure only supports root well-known discovery per domain, use subdomain fallback:

```text
https://personal.a2a.aweb.ai/.well-known/agent-card.json
https://customer-service.a2a.aweb.ai/.well-known/agent-card.json
https://research.a2a.aweb.ai/.well-known/agent-card.json
```

Subdomains are compatibility fallback, not the default product model.

## 16. Open Questions

1. Exact A2A v1.0 schema source and generated fixture tooling.
2. Exact canonical digest bytes for `card_digest`.
3. Whether `ListTasks` is required by the event harness.
4. Whether first deployment uses mail threads or chat threads as the durable aweb primitive.
5. Exact gateway wake path for Hetzner agents.
6. Auth mode for public event routes.
7. Minimal AWID publication implementation needed before product launch.

## Appendix A: Product Examples

### A.1 Hosted Default Agent

```text
Root card:
  https://team.aweb.ai/.well-known/agent-card.json

Direct card:
  https://team.aweb.ai/a2a/agents/r_support/agent-card.json

RPC:
  https://team.aweb.ai/a2a/agents/r_support/rpc

AWID:
  team.aweb.ai/support -> card_url, rpc_url, route_id, digest, hosted-custodial signer
```

### A.2 BYOT Default Agent

```text
Root card:
  https://acme.com/.well-known/agent-card.json

Direct card:
  https://acme.com/a2a/agents/r_help/agent-card.json

RPC:
  https://acme.com/a2a/agents/r_help/rpc

AWID:
  acme.com/help -> card_url, rpc_url, route_id, digest, delegation
```

### A.3 BYOT Multi-Agent Gateway

```text
Root card:
  https://acme.com/.well-known/agent-card.json
  describes Acme A2A Gateway/router.

Direct cards:
  https://acme.com/a2a/agents/r_help/agent-card.json
  https://acme.com/a2a/agents/r_research/agent-card.json
  https://acme.com/a2a/agents/r_returns/agent-card.json

Directory:
  acme.com/help     -> r_help card/rpc
  acme.com/research -> r_research card/rpc
  acme.com/returns  -> r_returns card/rpc
```

## Appendix B: Native Aweb A2A Transport Binding (Deferred)

A future `https://aweb.ai/a2a/binding/v1` could map A2A operations onto signed and optionally E2EE aweb messages between AWID identities. That would provide A2A task semantics with aweb identity, offline-verifiable authorship, and E2EE.

This is not part of the gateway product slice. It becomes worth specifying only if external A2A SDKs or clients want to implement it.
