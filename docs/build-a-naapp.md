# Build a naapp

A naapp (native agentic app) is an HTTP service that agents call through a
public v1 app manifest. You own the service, its data and its authorization
policy. aweb supplies request signing, CLI discovery and optional event delivery.
This guide is an author's path through the public contracts, not a requirement
to use a particular hosting provider or framework.

## 1. Run the minimum app server

Serve these surfaces from your app's origin:

- A public, unauthenticated `GET /.well-known/aweb-app.json` describing your
  tools. Use `manifest_version: 1`, a non-reserved `app.id`, your own
  `app.version`, and an origin such as `https://notes.example` with no path,
  query, fragment or user information.
- The HTTP routes declared by those tools. For each tool, declare its method,
  relative path, input schema, explicit path/query/body parameter placement,
  body mode, scopes and mutation classification. Validate inputs and enforce
  resource access in the service; the CLI is not a complete JSON Schema
  validator or an application authorization engine.
- Public usage instructions, pointed to by `app.llms_txt` and `app.skills`
  when provided. Explain required inputs, responses, errors and retry semantics.

Start with the [small manifest fixture](../test-vectors/app-manifests/synthetic-simple/aweb-app.json)
and the [manifest field and HTTP mapping rules](app-manifest.md). The CLI
preserves response bodies; v1 has no output-selector or streaming-response
contract. For raw bodies, declare `body.raw_param` and `body.content_type` and
teach `--body-file`/stdin use. JSON-looking strings are not a substitute for
repeated query parameters.

Omit a tool's `auth` field for signed team-auth requests. The only explicit
alternative is `"auth": "none"`, restricted to non-mutation tools. Such a tool
is public and must be safe without a caller identity. Do not write
`"auth": "team-cert"`; the v1 parser rejects it.

The manifest's `scopes` describe application requirements; they do not mint
resident grants or establish a hosted entitlement. Your service must enforce
its own policy after authenticating the caller. A team certificate is not a
license to read every team's data.

## 2. Authenticate each signed request

Implement [team-auth request envelope v2](team-auth-envelope-v2.md), rather than
an app-specific interpretation of the headers. The request carries:

```text
Authorization: DIDKey <member did:key> <base64 signature>
X-AWEB-Timestamp: <RFC3339 UTC timestamp>
X-AWEB-Signed-Payload: <base64url canonical JSON>
X-AWID-Team-Certificate: <base64 certificate JSON>
```

Before application side effects, perform every check:

1. Parse the signing DID, signature, timestamp and certificate. Require the
   certificate's team ID, certificate ID and member identity. Enforce a clock
   skew window of at most five minutes.
2. Verify the Ed25519 signature over the exact decoded signed-payload bytes;
   require canonical JSON and `v: 2`.
3. Bind the signed `aud` to a configured public app origin, **never a supplied
   Host header**. Bind uppercase `method`, the external raw percent-encoded
   `path` including any mount prefix and raw query, and `body_sha256` to the
   actual request bytes. Bind `timestamp` to the timestamp header and `team_id`
   to the presented certificate. Do not parse and reserialize the body before
   hashing it.
4. Resolve that team's public signing key through your configured, trusted
   AWID registry. Verify the certificate's signature against it and require
   `certificate.member_did_key` to equal the request signer. A self-signed
   certificate or an untrusted key supplied by the caller is not team authority.
5. Check the certificate ID against authoritative revocation state, using a
   bounded cache. Refuse on revoked certificates or when a required refresh
   cannot establish complete state. Then apply your own team/resource policy.

For an independent app without an operator credential, read
`GET /v1/namespaces/example.com/teams/engineering/certificates/{certificate_id}/status`.
This tokenless path requires AWID at or above the release that introduces `/status`; availability depends on the registry operator deploying that release.
This anonymous read works for public and private teams. It returns exactly
`team_id`, the **current** `team_did_key`, `status` (`active` or `revoked`), and
`revoked_at` (null for active). Require the expected team ID and a consistent
response, verify the presented certificate against that current key, and refuse
revoked certificates. An active result alone is never authentication: after key
rotation, an old-key certificate may still have an active record but its
signature no longer verifies. Cache by **both team ID and certificate ID**, for
at most 60 seconds. On a failed refresh, refuse; never reuse expired facts.

**Publication prerequisite:** this status-based path requires a published
certificate record. An unknown team, unknown certificate, or certificate from a
different team returns the same 404 response; refuse authentication. The `aw`
membership issuance paths publish certificates by default. A custom BYOT
controller that signs outside `aw` must also publish member certificates using
`POST /v1/namespaces/{domain}/teams/{name}/certificates` for independent apps to
verify them. Publication is an availability requirement for this verifier, not
a replacement for controller signatures. No operator token is needed.

Apps already holding the registry's trusted service credential retain their
team/history path. Read team facts, then certificate history with
`active_only=false`, following every `next_cursor` until `has_more` is false;
fail closed if a bound or error prevents completion. Private-team metadata,
member lookup, certificate lists and revocations still require read authority;
the narrow status route exposes no members, aliases, addresses or history.
Do not reuse an app-targeted signature against AWID or ask for a member's key.
The [Library verifier](../naapp/library/src/library/auth.py) demonstrates both
paths, with [real-registry status tests](../naapp/library/tests/test_certificate_status.py)
and [token cache tests](../naapp/library/tests/test_awid_team_cache.py). This is
reference source, not a claim about any separately deployed app's version.

Use every positive and negative case in the
[team-auth v2 vectors](vectors/team-auth-envelope-v2.json), including wrong
origin/path, altered body and missing version. Add service tests for revoked
certificates, signer/certificate mismatch, failed registry refresh and
cross-team resource access. The old compact v1 compatibility path does not bind
method/path/audience; do not adopt it for a new relying-party client.

V2 is request-bound, not replay-proof. A captured request can be replayed within
the timestamp window. Design application idempotency for operations where a
repeat would be harmful; do not advertise exactly-once execution.

## 3. Emit a notification that can wake an agent

Events are optional. Use the [app-event contract](app-events.md) for the exact
headers, signature bytes, request bodies and matching rules. There are three
separate setup steps before emitting:

1. Publish `events` declarations and public `event_emitters` in your manifest.
   For example, declare app-local `doc.changed` with default intent `wake`.
   The emit private key belongs to the app; never reuse an agent or team
   controller key for it.
2. A team-authorized installer fetches, validates and hashes the exact manifest
   bytes, then registers the app, digest, declarations and emitter keys using
   `POST /v1/apps/install` on the chosen aweb server. This is the optional
   [server app registry](app-registry.md). It does not fetch or independently
   verify the manifest. **`aw plugin install` does not perform this registration.**
3. The receiving member creates its own subscription with team-certificate
   authentication, for example `POST /v1/events/subscriptions` with
   `{"type":"notes/doc.changed","delivery_intent":"wake"}`. An optional
   `resource_ref` limits it to an exact resource. No subscription means no
   app-event delivery.

The app signs `POST /v1/events/app` with the dedicated `AWEB-App DIDKey`
credential. Its canonical v1 payload binds app/key/team IDs, the configured
server audience, method, raw request target, body hash and timestamp. The server
requires that emit key and event type under the team's currently installed
manifest digest. Use the [app-emit vectors](../cli/go/internal/conformance/vectors/app-emit-credential-v1.json)
for byte-level conformance. This credential authorizes app events, not general
team operations.

Emit small metadata such as a resource reference and version, not secrets or
document content. Subscribers receive an `app_event` on `/v1/events/stream`.
The **subscriber's stored intent** controls delivery; the producer's intent is
only metadata and cannot escalate an ambient subscription. Channel-core turns
the frame into `kind: "app"` with `deliveryIntent: "wake"` when the resolved
subscription calls for it. It does not fetch the resource for the agent.

A running, configured receiver is still required; see
[receiving events and waking agents](receiving-events.md). `wake` prompts an
idle runtime through its adapter; it does not start an absent agent process.
Current app-event streams have a five-minute lookback, reconnects and duplicate
possibilities, with no durable subscriber cursor or app-event acknowledgement.
Keep authoritative state queryable in your app. Use mail for durable action
requests rather than promising durable delivery from these notifications.

**Grant integration limit:** app calls and event subscription management are
separate authorities. Current subscription writes require team-certificate
authentication; they do not accept a worker's grant credential. The grant stream
requires `events.read`, and app frames additionally require `coord.read` under
the current stream filter. A delegated app tool alone establishes neither.
Coordinate subscription and receiver configuration with the identity operator;
do not make a grant worker borrow a resident key.

## 4. Let agents discover, install and call it

Provide the public manifest URL and the [CLI naapp access guide](naapp-access.md).
For an app named `notes` with a `list` tool, a resident runs:

```sh
aw plugin install https://notes.example/.well-known/aweb-app.json
aw notes list
```

Local and global residents sign with their own selected team's certificate.
Installation in a resident identity home also approves that app's ID and origin
for future grants. The per-OS-user manifest store is shared discovery state;
approval is separate, per resident. Installing a manifest without an identity
approves no resident. `aw plugin list` is not evidence of delegation.

For a worker grant, the resident's next mint snapshots the approved app's finite
signed tools, origin and manifest hash. Custody signs only from that snapshot;
a worker manifest cannot widen or redirect authority. Grant homes can list and
invoke, but cannot install, update or remove apps. Missing delegated tools fail
with `app_tool_denied` before an app request. Public `auth: none` tools do not
need signing authority.

A mint reports actual `apps` and `skipped_apps`; missing or invalid installed
apps are excluded. Do not infer authority from the public manifest or treat an
old mint receipt as proof a grant is currently valid. Newly approved apps reach
workers on re-mint; existing grants do not silently widen. Removing a resident's
approval affects subsequent mints, not existing snapshots or other residents.

`aw plugin update` explicitly refreshes local manifest bytes. A changed approved
origin requires explicit reinstallation. Server registry installation and
updates remain separate; publishing new bytes does not update either a local
cache or a team's registry digest automatically.

## 5. Version against the public contracts

| Surface | What authors can rely on | Change boundary |
| --- | --- | --- |
| Team-auth v2 | Canonical request bytes and signature, target/body/team binding, certificate and revocation checks | Current public protocol; conformance vectors govern interoperability |
| Manifest v1 | Declared fields and deterministic tool-to-HTTP interpretation, including strict event metadata | Experimental public extension with frozen v1 interpretation; a breaking mapping needs a new `manifest_version` and vectors |
| Resident/grant CLI access | Resident approval, finite custody snapshots and explicit updates | Shipped behavior described in `naapp-access.md`; discovery is not authority |
| Registry and app events | Explicit digest installs, app-key authentication, subscriptions and current frame shape | Shipped experimental OSS extensions; no durable app-event cursor, ack or exactly-once promise |

Use `app.version` for your app's releases; it is distinct from `manifest_version`.
Preserve old routes and parameter meanings for installed manifests and existing
grant snapshots. Do not require every consumer to refresh atomically.

The aweb team owns the public protocol, interpreter, registry and event
contracts. Changes require corresponding source, tests, vectors where
applicable, and documentation review; an individual app cannot redefine their
meaning. You own your application schema and business behavior. Hosted tool
composition, billing, credential provisioning and deployment policy are not
promised by a manifest or the optional OSS registry. Test the particular
server, client and runtime versions you support before claiming an integration.
