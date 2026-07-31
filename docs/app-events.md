# App-emitted events and subscriptions

Status: **shipped experimental public contract**. Owner: the aweb OSS event
extension surface. Server implementation and tests:

- `server/src/aweb/app_events.py`
- `server/src/aweb/routes/events.py`
- `server/tests/test_app_events_http.py`
- `channel-core/src/channel.ts`
- `channel-core/test/channel_core_dispatch.test.ts`

The storage schema is `server/src/aweb/migrations/aweb/009_app_events.sql`.
Credential byte parity is pinned by
`cli/go/internal/conformance/vectors/app-emit-credential-v1.json`.

App events are optional metadata wakes for installed apps. They are not the
mail/chat delivery path, an authoritative app event ledger, or part of the
default product journey.

## Maturity and important limits

The HTTP routes, signer binding, subscription matching, and channel-core
`kind: "app"` consumer ship today. The current delivery implementation is still
experimental:

- `GET /v1/events/stream` polls app events from a five-minute lookback window;
- an SSE connection lasts at most 300 seconds and clients reconnect;
- there is no per-subscriber durable delivery cursor or app-event ack;
- reconnects may replay an `event_id`, and events older than the lookback are not
  recovered by this stream;
- retrying a successful emit creates another event with another `event_id`;
- event payloads are metadata only and are not encrypted by this contract.

Use mail for durable action requests. An app remains authoritative for its own
state; an awakening tells the agent when it may be useful to query that app.

## Delivery intent

The shared values are:

- `wake` — prompt an idle runtime promptly;
- `steer` — steer an active turn when the host supports it;
- `ambient` — non-interrupting, next-turn context.

An app declaration has a default. An emitter may record a producer intent, but
the subscriber's stored choice governs delivery. If type-wide and exact-resource
subscriptions both match, the server emits one event for the agent using the
strongest subscriber choice in this order:

```text
steer > wake > ambient
```

A producer cannot escalate a subscriber from `ambient` to `wake` or `steer`.

## Install-time declarations

The strict app-manifest v1 CLI model accepts `event_emitters` but does not model
an `events` array. The experimental server install request separately accepts
both event declarations and public emit keys:

```json
{
  "events": [
    {
      "type": "doc.changed",
      "description": "A document changed.",
      "default_delivery_intent": "wake"
    }
  ],
  "event_emitters": [
    {"kid": "emit-2026-06", "did_key": "did:key:z6Mk..."}
  ]
}
```

This split is a current experimental compatibility limit: do not add `events`
to a v1 CLI manifest, because strict decoding rejects the unknown field. The
installer supplies declarations to `POST /v1/apps/install`; the server does not
fetch a manifest to derive or verify them.

The install route in [`app-registry.md`](app-registry.md) records those values
under the supplied manifest digest. The full emitted type is
`<app_id>/<local_type>`, for example `folio/doc.changed`. A key is accepted only
when its `(app_id, origin, digest, kid, did_key)` row is active for the team's
currently installed digest.

The app owns the emit private key. A team agent, a team controller, and an
embedding host must not reuse their signing keys as app emit keys.

## Emit authentication

```http
POST /v1/events/app
Authorization: AWEB-App DIDKey <did:key> <raw-standard-base64-signature>
X-AWEB-App-ID: folio
X-AWEB-App-Key-ID: emit-2026-06
X-AWEB-Team-ID: default:example.com
X-AWEB-Timestamp: 2026-06-17T12:00:00Z
X-AWEB-Signed-Payload: <base64url canonical JSON>
```

The signed payload is canonical JSON:

```json
{
  "app_id": "folio",
  "aud": "https://aweb.example",
  "auth": "app-event",
  "body_sha256": "<lowercase hex sha256 of exact request bytes>",
  "did_key": "did:key:z6Mk...",
  "kid": "emit-2026-06",
  "method": "POST",
  "path": "/v1/events/app",
  "team_id": "default:example.com",
  "timestamp": "2026-06-17T12:00:00Z",
  "v": 1
}
```

`aud` is the configured external server origin, not a caller-controlled `Host`
header. `path` is the external raw request target, including a deployment
`root_path` and raw query string. A server mounted under `/api` therefore
verifies `/api/v1/events/app`.

The verifier requires:

1. exact canonical JSON and a valid Ed25519 signature;
2. timestamp within the signed-request skew window;
3. method, raw path, team, app, key id, DID key, body hash, and timestamp equal
   the live request and headers;
4. audience in the server's configured public-origin set;
5. the emit key active under the team's installed app digest;
6. the body type in the emitter's own namespace; and
7. that local event type recorded at install for the active digest.

This credential proves an installed app emit key authorized one request. It is
not a team certificate and does not grant arbitrary app or team operations.

## Emit body and response

Request:

```json
{
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "ambient",
  "payload": {"title": "Pitch deck", "version": "7"}
}
```

- `resource_ref` is an optional opaque exact-match string.
- `delivery_intent` is optional producer metadata; omission uses the manifest
  default.
- `payload` is a small JSON object. Do not put secrets or encrypted plaintext in
  it; every matching channel consumer can receive this metadata.

Response:

```json
{
  "event_id": "uuid",
  "team_id": "default:example.com",
  "app_id": "folio",
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "ambient",
  "created_at": "2026-06-17T12:00:00+00:00"
}
```

The response intent is the producer/default intent recorded on the event, not a
particular subscriber's effective intent.

## Subscriptions

A team member manages only its own subscriptions with normal team-certificate
auth.

```http
POST /v1/events/subscriptions
GET /v1/events/subscriptions
DELETE /v1/events/subscriptions/{subscription_id}
```

Create or update body:

```json
{
  "type": "folio/doc.changed",
  "resource_ref": "docs/pitch",
  "delivery_intent": "wake"
}
```

Rules:

- `(team_id, agent_id, type, resource_ref)` is unique; POST upserts the intent.
- Omitted or null `resource_ref` matches every resource for that type.
- Omitted intent uses the declaration's default.
- The type must be declared by an app installed for the caller's team.
- No subscription means no app-event delivery.
- DELETE is scoped to the authenticated team member and returns 404 for an
  absent or other-member subscription.
- GET also has a trusted host-integration read context in source. That internal
  context is not a portable third-party protocol; independent clients use team
  auth.

## Matching and SSE frame

A subscription matches when team and type are equal and its resource is null or
exactly equals the event resource. The authenticated agent receives matches on
the existing stream:

```http
GET /v1/events/stream?deadline=<RFC3339 timestamp>
```

```sse
event: app_event
data: {"type":"app_event","event_id":"uuid","app_id":"folio","app_event_type":"folio/doc.changed","resource_ref":"docs/pitch","delivery_intent":"wake","producer_delivery_intent":"ambient","payload":{"version":"7"},"created_at":"..."}
```

`delivery_intent` is the resolved subscriber choice;
`producer_delivery_intent` is audit/debug metadata.

Channel-core maps this frame to the stable host-adapter shape:

```ts
{
  kind: "app",
  content: "folio/doc.changed — docs/pitch — version=7",
  deliveryIntent: "wake",
  meta: {
    type: "folio/doc.changed",
    app_id: "folio",
    app_event_type: "folio/doc.changed",
    resource_ref: "docs/pitch",
    producer_delivery_intent: "ambient",
    event_id: "uuid",
    payload: "{\"version\":\"7\"}"
  }
}
```

App-specific identity stays in metadata; adapters do not gain a new awakening
kind for every app. Channel-core uses `event_id` for duplicate suppression and
does not fetch app state. Host adapters may sanitize or summarize metadata
before injection, but they must preserve the delivery intent and event identity.

## Compatibility and change control

This is the only current public app-event contract. The old restructuring-path
draft has been removed. Changes to auth bytes require an updated app-emit vector
and both producer and verifier tests. Changes to frame shape require server and
channel-core tests. A durable cursor, ack, encrypted payload format, or
exactly-once emit key would be a new contract rather than an implied property of
this experimental surface.
