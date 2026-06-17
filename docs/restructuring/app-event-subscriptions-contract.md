# Core app-emitted events + agent subscriptions contract (m3.2)

Status: **interface-first draft** for `default-aaaj.2` cross-validation with
`aweb` core, `aw`/channel-core, and `ac` before implementation.

Goal: make the core Event/SSE channel app-generic without changing the host
adapter contract shape: awakenings still carry `kind`, `content`, `meta`, and
`deliveryIntent`, and host adapters still interpret the existing
`wake | steer | ambient` delivery-intent taxonomy.

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
- `delivery_intent`: producer default/recommendation and audit metadata using
  `wake | steer | ambient`. It does **not** override the subscriber's chosen
  delivery intent.
- `payload`: optional small JSON object for metadata needed in the wake. No
  secrets or encrypted plaintext; app-specific hydration remains app-owned.

Team scope comes from auth/authorization, not a global broadcast body field. An
emit is accepted only for a team where the app is installed/authorized to emit
that `app_id` event. Discovery of app manifests remains public; app event
emission and subscription state are team data.

Response:

```json
{
  "event_id": "uuid",
  "team_id": "default:atext.aweb.ai",
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake",
  "created_at": "2026-06-17T12:00:00Z"
}
```

## Agent subscription model

An agent subscribes, within its authenticated team, to one event type plus an
optional exact resource filter and chooses the delivery intent it consents to.

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

## Matching and SSE delivery

Core matches an emitted event when:

1. `event.team_id == subscription.team_id`,
2. `event.type == subscription.type`, and
3. `subscription.resource_ref IS NULL OR subscription.resource_ref == event.resource_ref`.

Matched events are delivered through the existing authenticated
`GET /v1/events/stream` SSE channel.

Proposed SSE frame:

```sse
event: app_event
data: {
  "type": "app_event",
  "event_id": "uuid",
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

Channel consumer note for cross-validation: this requires channel-core to accept
an `app_event` SSE event and map it into the existing `ChannelAwakening` object
shape with `deliveryIntent = data.delivery_intent` and app metadata in `meta`.
The adapter boundary remains `{kind, content, meta, deliveryIntent}`; the exact
`kind` value for generic app wakes should be confirmed by the channel owner
before implementation.

## Durability and replay semantics

These are wake signals, not an app event ledger:

- Core stores emitted app events long enough for active/reconnecting SSE clients
  to receive and de-dupe them.
- Clients may receive duplicate app events after reconnect; `event_id` is the
  de-dupe key.
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

1. **channel-core:** confirm whether generic app wakes can add a `kind: "app"`
   while preserving the `ChannelAwakening` shape, or whether another existing
   kind mapping is required for the no-adapter-change constraint.
2. **aweb core:** confirm emit authorization shape for first implementation:
   team-auth caller, internal trusted app call, or app-auth tied to installed
   `app_id`.
3. **ac:** confirm hosted gateway/control-plane only needs subscription
   management, not app-event hydration, for m3.2.
