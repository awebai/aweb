# Core app-emitted events + agent subscriptions contract (m3.2)

Status: **interface-first draft** for `default-aaaj.2` cross-validation with
`aweb` core, `aw`/channel-core, and `ac` before implementation.

Goal: make the core Event/SSE channel app-generic without changing the host
adapter contract shape: awakenings still carry `kind`, `content`, `meta`, and
`deliveryIntent`, and host adapters still interpret the existing
`wake | steer | ambient` delivery-intent taxonomy. Channel-core adds exactly
one generic app awakening kind, `kind: "app"`; app-specific identity stays in
`meta`, not in an open-ended kind vocabulary.

## Delivery intent taxonomy

Reuse `ChannelDeliveryIntent` exactly:

- `wake` — interrupt idle/sleeping agent work and deliver promptly.
- `steer` — inject into/steer the current turn when the subscribed agent has
  explicitly opted into that behavior.
- `ambient` — deliver as next-turn/non-interrupting context.

This taxonomy covers the target cases:

- `tasks/task.status_changed` for a coordinator: usually `wake`.
- `folio/doc.changed` for a doc-following agent: `wake` or `ambient`, chosen by
  the subscriber.
- high-priority control-like app workflows: `steer`, but only when the agent's
  subscription chose `steer`; an app emission alone cannot force escalation.

## Manifest-declared event catalog

An app manifest may declare the app events it can emit. This mirrors `tools`:

```json
{
  "events": [
    {
      "type": "doc.changed",
      "description": "A document changed.",
      "default_delivery_intent": "wake",
      "resource_ref": {
        "description": "Document slug",
        "examples": ["pitch"]
      }
    }
  ],
  "event_emitters": [
    {
      "kid": "emit-2026-06",
      "did_key": "did:key:z6Mk..."
    }
  ]
}
```

Rules:

- Manifest event `type` is app-local (for example `doc.changed`); core combines
  it with `app.id` to produce the fully-qualified event type
  `folio/doc.changed`.
- `default_delivery_intent` uses `wake | steer | ambient` and seeds the
  subscription UI/default. When a subscription omits `delivery_intent`, core
  stores this manifest default as the subscription's effective intent. The
  subscriber may override it; the stored subscriber choice governs delivery.
- `resource_ref` describes the opaque resource key shape for humans/clients; core
  only exact-matches the string.
- `event_emitters` lists app-owned service signing keys allowed to emit events
  for this pinned manifest digest. The app holds the private key; team agents do
  not. Key rotation is an explicit manifest update/re-install because install
  pins the digest.

## App-emitted event shape

Apps emit team-scoped events into core; core never polls app-owned databases.

```http
POST /v1/events/app
```

Request body:

```json
{
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake",
  "payload": {
    "title": "Pitch deck",
    "version": "7"
  }
}
```

Field rules:

- `type`: app-namespaced event type, `<app_id>/<event_name>`.
  - `app_id` matches the installed app id / manifest namespace.
  - `event_name` is app-owned, lower-case dot/underscore/hyphen path text such
    as `doc.changed`, `asset.video.status`, or `task.status_changed`.
- `resource_ref`: optional opaque app-owned resource key (doc slug, task ref,
  token, asset id). Core treats it as an exact-match string only.
- `delivery_intent`: producer recommendation/audit metadata using
  `wake | steer | ambient`. It defaults from the manifest event's
  `default_delivery_intent` when omitted. It does **not** override the
  subscriber's chosen delivery intent.
- `payload`: optional small JSON object for metadata needed in the wake. No
  secrets or encrypted plaintext; app-specific hydration remains app-owned.

Team scope comes from auth/authorization, not a global broadcast body field. App
event emission and subscription state are team data.

Emit authorization is app-scoped, privileged, and attributable: the producer is
an app acting in a team, not a random team member and not the hosted gateway.
Apps do not sign as the team and do not hold team certificates.

Proposed v1 app-service credential:

```http
Authorization: AWEB-App DIDKey <did:key> <base64-signature>
X-AWEB-App-ID: folio
X-AWEB-App-Key-ID: emit-2026-06
X-AWEB-Team-ID: default:atext.aweb.ai
X-AWEB-Timestamp: 2026-06-17T12:00:00Z
X-AWEB-Signed-Payload: <base64url canonical JSON>
```

The canonical signed payload is:

```json
{
  "v": 1,
  "auth": "app-event",
  "aud": "https://aweb.example",
  "method": "POST",
  "path": "/v1/events/app",
  "team_id": "default:atext.aweb.ai",
  "app_id": "folio",
  "kid": "emit-2026-06",
  "did_key": "did:key:z6Mk...",
  "body_sha256": "...",
  "timestamp": "2026-06-17T12:00:00Z"
}
```

Core accepts an emit only when all of these are true:

1. the app-service signature verifies over the canonical payload;
2. `team_id` and `app_id` from headers/payload match the request body and route
   context;
3. `app_id` is installed for `team_id`;
4. `(kid, did_key)` appears in the pinned manifest digest's `event_emitters`;
5. body `type` has prefix `<app_id>/`; and
6. the pinned manifest for that installed app declares the emitted app-local
   event type.

Core records `producer_app_id`, `producer_key_id`, `producer_did_key`, and team
attribution with the event. An app cannot emit for another app namespace, for a
team where it is not installed, with a key absent from the pinned manifest, or
for an undeclared event type. Discovery of app manifests remains public; app
event emission is an installed-app capability.

Response:

```json
{
  "event_id": "uuid",
  "team_id": "default:atext.aweb.ai",
  "app_id": "folio",
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake",
  "created_at": "2026-06-17T12:00:00Z"
}
```

## Agent subscription model

An agent subscribes, within its authenticated team, to one event type plus an
optional exact resource filter and chooses the delivery intent it consents to.
If the caller omits `delivery_intent`, core defaults it from the manifest event's
`default_delivery_intent`. The subscriber may override that default; once stored,
the subscription's `delivery_intent` is the effective delivery behavior.

```http
POST /v1/events/subscriptions
```

Request body:

```json
{
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake"
}
```

Response:

```json
{
  "subscription_id": "uuid",
  "team_id": "default:atext.aweb.ai",
  "agent_id": "uuid",
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake",
  "created_at": "2026-06-17T12:00:00Z",
  "updated_at": "2026-06-17T12:00:00Z"
}
```

Additional endpoints:

```http
GET /v1/events/subscriptions
DELETE /v1/events/subscriptions/{subscription_id}
```

Rules:

- Subscriptions are keyed by `(team_id, agent_id, type, resource_ref)`; `POST`
  upserts the chosen `delivery_intent`.
- `resource_ref: null` (or omitted) means all resources of that `type`.
- Exact resource subscriptions and type-wide subscriptions may both match; core
  emits one SSE wake per agent event using the strongest subscriber-selected
  intent, ordered `steer > wake > ambient`, and de-dupes duplicate matches by
  `(event_id, agent_id)`.
- No subscription means no delivery. Apps do not broadcast to every team agent by
  default.
- Hosted control planes/gateways may manage subscriptions on behalf of hosted
  custodial identities using normal authority for that `agent_id`; they do not
  get a separate event-relay or hydration path.

## Matching and SSE delivery

Core matches an emitted event when:

1. `event.team_id == subscription.team_id`,
2. `event.type == subscription.type`, and
3. `subscription.resource_ref IS NULL OR subscription.resource_ref == event.resource_ref`.

If multiple subscriptions for the same agent match one emitted event, core
resolves a single effective `delivery_intent` by strongest subscriber-selected
intent, ordered `steer > wake > ambient`. This strongest-intent resolution is
server/core-side; channel-core receives one resolved `app_event` frame.

Matched events are delivered through the existing authenticated
`GET /v1/events/stream` SSE channel.

Proposed SSE frame:

```sse
event: app_event
data: {
  "type": "app_event",
  "event_id": "uuid",
  "app_id": "folio",
  "app_event_type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake",
  "producer_delivery_intent": "ambient",
  "payload": {"title":"Pitch deck","version":"7"},
  "created_at": "2026-06-17T12:00:00Z"
}
```

- `delivery_intent` is the effective subscriber-selected intent.
- `producer_delivery_intent` preserves the app's emitted recommendation for
  debugging/audit.
- `event_id` is stable for de-dupe across reconnects and host delivery retries.
- Existing mail/chat/control events continue to stream unchanged during the
  bundled-comms transition.

Channel consumer contract: channel-core accepts an `app_event` SSE event and maps
it into the existing `ChannelAwakening` object shape as:

```ts
{
  kind: "app",
  content: "",
  deliveryIntent: data.delivery_intent,
  meta: {
    type: "folio/doc.changed",
    app_id: "folio",
    app_event_type: "folio/doc.changed",
    resource_ref: "docs/pitch",
    producer_delivery_intent: "ambient",
    event_id: "uuid",
    ...payload-as-string-metadata
  }
}
```

The adapter boundary remains `{kind, content, meta, deliveryIntent}`. Adapters do
not gain one kind per app event; app-specific routing data lives in `meta`.
Because app event `content` is empty metadata-only wake content, channel-core
adds a generic app render in `formatAwakeningForAgent` using `meta.type` (the
app event type), `resource_ref`, and a compact payload summary. This is a
channel-core consumer task; adapters remain unchanged.

## Channel-core consumer behavior

The consumer-side change is intentionally narrow and contained to channel-core:

- `parseAgentEvent` accepts `app_event` SSE frames.
- `dispatchAgentEvent` maps `app_event` to `ChannelAwakening` with `kind: "app"`.
- `deliveryIntent` is `data.delivery_intent` (effective subscriber-selected
  intent), never `producer_delivery_intent`.
- `event_id` is the channel-core de-dupe key for app events.
- `producer_delivery_intent` is copied into `meta` for audit/debug only.
- Channel-core does **not** fetch or hydrate app data on app events. The payload
  is metadata-only wake content; deeper state comes from the app's own CLI/API.

## Durability and replay semantics

These are wake signals, not an app event ledger:

- Core stores emitted app events long enough for active/reconnecting SSE clients
  to receive and de-dupe them.
- Clients may receive duplicate app events after reconnect; `event_id` is the
  de-dupe key used by channel-core.
- Core may expire old delivered/undelivered app events by TTL.
- Apps that need authoritative state must expose their own app API; the wake
  carries enough metadata to decide whether to hydrate.

## Concrete examples

### Task status wake

Subscription:

```json
{"type":"tasks/task.status_changed","delivery_intent":"wake"}
```

Emission:

```json
{
  "type":"tasks/task.status_changed",
  "resource_ref":"default-aaaj.2",
  "delivery_intent":"ambient",
  "payload":{"old_status":"open","new_status":"in_progress"}
}
```

Effective SSE delivery to that subscriber uses `delivery_intent: "wake"`.

### Folio document follower

Subscription:

```json
{"type":"folio/doc.changed","resource_ref":"pitch","delivery_intent":"ambient"}
```

Emission:

```json
{
  "type":"folio/doc.changed",
  "resource_ref":"pitch",
  "delivery_intent":"wake",
  "payload":{"version":"7"}
}
```

Effective SSE delivery to that subscriber uses `delivery_intent: "ambient"`;
the app cannot escalate beyond the subscriber's chosen behavior.

### Folio async asset processing

`folio/asset.video.status` with `resource_ref = <asset_id>` wakes an owning or
following agent instead of forcing polling of `/assets/{id}`.

## Open cross-validation points

1. **aweb/aw/ac:** cross-validate the proposed `AWEB-App DIDKey` credential and
   manifest `event_emitters` key source for `POST /v1/events/app`.
