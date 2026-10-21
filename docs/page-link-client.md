# Browser transport for capability links

The shared host-side client lives in `naapp-lib/renderer/link-client.mjs` and is
shipped in the `aweb_naapp.pages` package as `assets/page-link-client.js`.
Serve that module from the app origin, with the host's strict CSP and
no-referrer policy. It is separate from `page-renderer.js`: the renderer never
receives the link secret, browser key or session object. See
[page links](page-links.md) §§2–3 for the wire contract.

The host's first script imports and constructs it synchronously, before other
application fetches. Construction captures the canonical `#k=<secret>` fragment
and immediately removes the entire fragment with `history.replaceState`, even
when it is invalid. Do not log or instrument the initial URL or exchange body.
The host supplies the public link ID from its route, not from page JSON.

```js
import { createLinkClient } from "/assets/page-link-client.js";

const transport = createLinkClient({
  linkId: "lnk_example",
  // Optional: the exact external path when the app is mounted under a prefix.
  sessionPath: "/mounted/v1/links/lnk_example/session",
});
const { link, expires_at } = await transport.connect();
const response = await transport.request(
  "/mounted/v1/pages/pg_example?projection=1",
);
if (!response.ok) throw await response.json();
const snapshot = await response.json();
```

`connect()` generates a fresh WebCrypto Ed25519 pair with a non-extractable
private key, exports only the public key as a canonical `did:key`, and posts the
secret and public key to the exchange. Unsupported browsers refuse with
`unsupported_crypto`; there is no alternate key type. It returns only the
expiry and public link metadata (`page_id`, `mode`, `actions`). Session ID,
private key and CSRF token remain in the closure. Concurrent calls share the
pending exchange. A later explicit `connect()` renews the session with a new
key. Renewal waits for pending writes, then invalidates previous-session reads;
it never aborts a write or its response body. A completed write returns its
response even if the session expired during the fetch. Explicit `clear()` stays
terminal and aborts writes as well as reads.

`request(rawPathWithQuery, {method, body, contentType})` returns a Fetch
`Response`; the host interprets HTTP errors and maps the JSON to its adapter.
The method defaults to `GET`. Paths must be exact same-origin external targets,
including the mount prefix, query order and percent encoding. Use URL-encoded
query parameters. Targets that a browser would normalize, fragments and
cross-origin URLs refuse before signing. There is no prefix stripping.

Bodies are serialized strings or `Uint8Array` bytes, copied before hashing.
GET/HEAD have no body. The content type defaults to `application/json` when a
body is supplied; binary callers can supply `application/octet-stream`.
Every request, including page reads and independently paginated widget queries,
carries the canonical `AWEB-Link-Request` and `X-AWEB-Signed-Payload` headers.
The digest covers exactly the body bytes sent; the timestamp is UTC to the
second. Each call generates a fresh random 16-byte nonce. Writes also carry
`X-AWEB-CSRF`; the browser supplies Origin. Fetch omits cookies, refuses
redirects, uses no-store and sends no referrer.

`csrfToken()` supplies the current token only to the host's renderer adapter;
it returns null before connection, after expiry or after clearing. The host
must never put it into a page snapshot. An expired session requires explicit
renewal. The secret is retained only in memory for that exchange; a reload
requires reopening the original link. Nothing is persisted in browser storage.

Call `transport.clear()` alongside `renderer.clear()` before changing actor or
authority, and on host teardown. Clearing is terminal: it drops the secret and
session, aborts fetches, and fences continuations after cryptographic and
network awaits. Create another client for another link. The host must still fence its entire
adapter callback, including `response.json()` after `request()` returns. The
client cannot undo an operation already admitted by the server.

There are no automatic request retries, writes, session renewals or decision
answers. If a response is lost, the host reconciles or explicitly retries with
the same action idempotency key and serialized body; the transport then signs
with a fresh nonce. Link sessions remain anonymous capability holders and never
provide member or passkey approval evidence. The N5 server still checks nonce,
Origin/CSRF, link scope, lifecycle and current creator authority on every use.

Invalid input raises an error with `code: request_invalid`; missing fragments
use `link_unavailable`, malformed exchange receipts use `session_invalid`, and
unconnected/expired sessions use `session_expired`. Authority teardown uses
`client_cleared`, renewal invalidation uses `session_changed`. Exchange refusals
preserve N5's `detail.code` and HTTP `status`. A malformed refusal uses
`exchange_refused` with its status; malformed successful receipts use
`session_invalid`. Other network errors propagate without automatic retry.

## Focused verification

From `naapp-lib/renderer`, run:

```sh
node build.mjs --check
npx playwright test tests/link-client.spec.mjs
```

The browser imports the packaged module and executes the root
[`link-request-v1.json`](vectors/link-request-v1.json) signing cases with
WebCrypto, comparing exact canonical payload headers, signatures and signing
bytes. The consumer also pins malformed payload fields that a parsed value can
represent. Raw-byte verifier refusals and lexical number distinctions remain
server checks, not browser parsing claims.

A separate loopback fixture serves the same module and verifies its requests
with the real `aweb_naapp.runtime.link_requests.verify_link_request_bytes` and
canonical Ed25519 key parser. It exercises mounted reads/queries, UTF-8 writes,
fresh retry nonces, body snapshots, cookie omission, redirect refusal, expiry,
renewal and clearing. Error probes use the production N5 `refusal_response`
serializer and assert codes/status without a session or automatic retry. This
is transport conformance; application authorization, store projections and
final effects require their owners' real integration journeys.
