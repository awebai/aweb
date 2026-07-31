# App manifest v1

Status: **current experimental public contract**. Owner: the aweb OSS CLI
extension surface. The shipped interpreter and validator live in
`cli/go/internal/appmanifest/`; `cli/go/cmd/aw/plugin.go` is the current CLI
consumer. Byte-level interpretation authority lives in
`cli/go/internal/conformance/vectors/app-manifest-interpretation-v1.json`, and
digest-pinned manifest snapshots live under `test-vectors/app-manifests/`.

The schema is usable by independent consumers, but manifest-driven hosted MCP
composition is not an aweb OSS feature or default product promise. A hosted
operator may implement another consumer only by matching the same vectors.

## Purpose

One declaration describes an app's CLI verbs and HTTP mapping. The shipped
consumer is the generic `aw <app>` dispatcher over `aw id request --team-auth`.
Other public or hosted consumers may interpret the same declaration, but they
must match the conformance vectors rather than inventing a second mapping.

Two hard rules: **parameter placement is explicit, never inferred**, and paths
are relative so the consumer builds the absolute target from the installed app
origin. An app manifest is **not** an A2A Agent Card; Agent Card discovery and
AWID publication are governed by [`a2a.md`](a2a.md) and
[`a2a-awid-publication-contract.md`](a2a-awid-publication-contract.md).

## Top-level structure

```jsonc
{
  "manifest_version": 1,
  "app": {
    "id": "folio",                       // verb namespace: `aw folio ...`; reserved built-in names/aliases are rejected
    "version": "1.x",
    "origin": "https://folio.aweb.ai",   // base URL; every request target = origin + tool.path
    "llms_txt": "/llms.txt",
    "skills": "/skills/"
  },
  "tools": [ /* tool objects */ ],
  "event_emitters": [
    { "kid": "emit-2026-06", "did_key": "did:key:z6Mk..." }
  ]
}
```

**Compatibility.** `manifest_version` is the **contract version the consumer
interprets** (distinct from `app.version`, the app's own release). A consumer
MUST reject a manifest whose `manifest_version` it does not support rather than
best-effort parse it. v1 consumers support `manifest_version: 1`.

The strict shipped CLI model accepts only top-level `manifest_version`, `app`,
`tools`, and optional `event_emitters`. It does **not** accept an `events` array.
The experimental server install API separately accepts event declarations; see
[`app-events.md`](app-events.md). Do not put `events` into a v1 CLI manifest and
expect strict decoding to succeed.

## Manifest discovery

An app serves its manifest at a **well-known path on its origin**:
`<app.origin>/.well-known/aweb-app.json` (RFC 8615; parallels A2A's
`/.well-known/agent-card.json` — kept **distinct** on purpose, reinforcing the
§3.2 guardrail that a manifest is *not* an Agent Card). Manifest consumers fetch it from there.

Discovery is an **unauthenticated public GET** — the manifest is public metadata
describing the app's verb surface (like `llms.txt`, an OpenAPI document, or an
A2A agent-card; folio already serves `llms.txt`/`skills` no-auth). **Team-auth
applies only to the verb *calls* the manifest describes, never to fetching it.**

Consumers fetch at **install/update time** and store the manifest **locally with
provenance** (origin, `manifest_version`, app version, byte digest); dispatch
reads the local copy — it is **not** a per-call fetch. `aw plugin update`
re-fetches.

For portable registry-backed manifests, `app.origin` is an `http` or `https`
origin with no userinfo, path, query, or fragment. The CLI interpreter currently
accepts a base path and discards an origin query/fragment, while the server
registry rejects those shapes. Do not rely on that CLI-only tolerance; the
origin-only subset is the interoperable contract.

The experimental aweb app registry records the origin plus a digest; see
[`app-registry.md`](app-registry.md). The registry does not serve canonical
manifest bytes and currently does not fetch or independently verify them.
Installers and consumers must hash the exact bytes they fetched before trusting
a recorded digest. Body caching never overrides digest verification.

## Tool object

```jsonc
{
  "name": "create",                      // the verb: `aw folio create`
  "description": "Create a document.",
  "method": "POST",                      // enum: GET|POST|PUT|PATCH|DELETE (v1)
  "path": "/v1/documents",               // RELATIVE; {placeholders} bind to in:path params
  "input_schema": { /* JSON Schema of the args */ },
  "params": [                            // EXPLICIT placement for every input field
    { "name": "slug",  "in": "body" },
    { "name": "title", "in": "body" },
    { "name": "body",  "in": "body" }
  ],
  "body": { "mode": "json" },            // json | raw  (multipart deferred — no current app needs it)
  "scopes": ["folio:write"],             // scopes required by this operation
  "mutation": true                       // classifies the operation as state-changing
}
```

### Field rules

- **`method`** — enum `GET|POST|PUT|PATCH|DELETE` for v1.
- **`path`** — **relative only**. Each `{name}` placeholder must have a matching
  param with `"in":"path"`. A path carrying a scheme/host is **rejected at
  validation** (a host-injecting manifest would redirect a signed, authenticated
  request — see Security).
- **`params[].in`** — one of `path | query | body`, **required for every field**
  in `input_schema`. Consumers **never infer** placement.
- **`body.mode`**:
  - `json` (default) — `in:body` params assembled into **canonical JSON**
    (mandatory; see the mapping section — it lands in the signed `body_sha256`).
  - `raw` — exactly one param carries the raw request body; declare it with
    `body.raw_param` and an explicit `body.content_type` (e.g. folio
    version-append: `raw_param: "body"`, `content_type: "text/markdown; charset=utf-8"`).
    Other params may still be `in:path`/`in:query`.
  - *(multipart deferred to a later version; no current app needs it.)*
- **`scopes`** — scopes the app requires. The registry records team grants. The
  shipped CLI carries team authentication but does not itself turn this field
  into a hosted entitlement system.
- **`mutation`** — `true` when a successful call changes app state; false for
  reads, failed validation, and idempotent no-op retries. Consumers may use this
  classification for policy or metering, but aweb OSS does not promise a bundled
  billing system.

## Event emitters

`event_emitters` declares app-owned Ed25519 `did:key` emit keys that may sign
experimental app-emitted events for an installed app. This is the currently
shipped app-event credential, not an AWID identity or team certificate. The app
holds the private key; the manifest and registry carry only the public key.
See [`app-events.md`](app-events.md).

```jsonc
{
  "event_emitters": [
    {
      "kid": "emit-2026-06",          // app-owned key id; unique within this manifest
      "did_key": "did:key:z6Mk..."    // public emit key; private key stays with the app
    }
  ]
}
```

Emit credentials use the shared app-emit conformance vectors in
`cli/go/internal/conformance/vectors/app-emit-credential-v1.json`. The signed
payload binds `team_id`, `app_id`, `kid`, `did_key`, `aud`, `method`, `path`,
`body_sha256`, and `timestamp`; request headers carry the same app/team/key
identity (`Authorization: AWEB-App DIDKey ...`, `X-AWEB-App-ID`,
`X-AWEB-App-Key-ID`, `X-AWEB-Team-ID`, `X-AWEB-Timestamp`,
`X-AWEB-Signed-Payload`). Verifiers must accept only active `(kid, did_key)`
pairs for the installed app and team.

## Verb → HTTP mapping (the precise contract the dispatcher + conformance suite key off)

Given `(tool, args)`:

1. **Target** = `app.origin` + `tool.path`, substituting `{placeholders}` from
   `in:path` params, each **percent-encoded** (RFC 3986). **Reject** any
   `tool.path` that is not relative — absolute URL, leading `//host`, a scheme,
   or path-traversal (`..`) → validation error.
2. **Query** = `in:query` params, **canonically encoded — this lands in the
   SIGNED path.** `aw id request` signs `path` *including* the raw query
   (`cli/go/cmd/aw/id_request.go`), so every consumer MUST encode identically
   or the signed path diverges and the verifier rejects. Hard contract: RFC 3986
   percent-encoding; arrays → repeated keys (`k=v1&k=v2`); order = `params[]`
   declaration order. Omitted optional fields are absent, not empty.
3. **Body** = per `body.mode`.
   - `json` → **first coerce** each `in:body` value to its `input_schema` type
     (CLI flags arrive as argv **strings**, while other consumers may receive
     typed JSON; all must converge to the SAME typed value before serializing,
     e.g. `ttl_seconds` → integer `3600`, not string `"3600"`; `editable` →
     boolean). The coerced value is what gets serialized and signed. Then
     assemble into **canonical JSON — mandatory**: sorted keys, no insignificant
     whitespace, HTML-escaping **off** (`SetEscapeHTML(false)`), matching the
     existing `awid/signing.go` `CanonicalJSON` / `CanonicalJSONValue`
     convention. The v2 envelope signs `body_sha256` over the *exact* body bytes,
     so independent consumers must serialize **byte-identically** or they
     produce different signatures. **v1 number rule:** integers are portable;
     floats are not pinned across runtimes — avoid float body
     fields in v1 (a later version pins float canonicalization if needed).
   - `raw` → the `raw_param` bytes with `content_type`, written via
     `--body-file` (not argv — avoids length/binary issues).
4. **Content-Type** is set **explicitly by the mapping in both modes**
   (`json` → `application/json`; `raw` → `body.content_type`). Do **not** rely on
   a consumer's implicit default; independent consumers can otherwise diverge.
   Content-Type is not in the signed payload, but pinning it keeps the two
   consumers byte-identical.
5. The dispatcher invokes `aw id request --team-auth <method> <target?query>`
   (`--body` for json / `--body-file` for raw, `--header Content-Type: …`), which
   produces the v2 envelope (`aud`+`method`+`path`+`team_id`+`body_sha256`).

The app-manifest interpretation vector asserts the **interpreted request spec
before signing**: `(manifest, verb, args) → exact (method, absolute URL, raw
path+query, headers/content-type, body bytes, body_sha256, mutation flag)`. It
does **not** assert dynamic authorization, timestamp, or signature bytes; those
stay in the team-auth vectors. Every consumer must produce a byte-identical
interpreted spec.

## CLI binding (manifest → argv)

HTTP placement (`params[].in`) and CLI surface are **orthogonal** and both must
be specified — the dispatcher must not infer either. v1 binding rule:

- Every `input_schema` field is a **named flag**: `--<field> <value>`. **No
  positional inference** (incl. from path placeholders) unless a future contract
  version adds an explicit positional list and conformance-tests it.
- The `raw`-mode body param is **not** a flag — it comes from `--body-file
  <path>` or stdin (e.g. `aw folio append --slug pitch --body-file pitch.md`).
- Flags map to fields regardless of HTTP placement; the dispatcher then routes
  each field to path/query/body per `params[].in`.

## Response handling (v1)

Deliberately boring: the dispatcher **passes the upstream response through
verbatim** (JSON or raw bytes) to stdout, with the upstream status reflected in
the exit code. **No output selection/transformation in v1.** The folio proof
A manifest-driven workflow should work end-to-end without requiring an output
transformation hidden outside the manifest contract.
(A tiny output selector is a possible later manifest version; not v1.)

## Worked example — folio (every current cert-authed verb)

Grounded in the public example app at `naapp/folio/src/folio/api.py`:

| verb | method | path | body | mutation |
|---|---|---|---|---|
| `create` | POST | `/v1/documents` | json `{slug,title, body\|template}` | ✓ |
| `list` | GET | `/v1/documents` | — | ✗ |
| `show` | GET | `/v1/documents/{slug}` | — | ✗ |
| `versions` | GET | `/v1/documents/{slug}/versions` | — | ✗ |
| `append` | POST | `/v1/documents/{slug}/versions` | **raw** (UTF-8 markdown) | ✓ |
| `append-template` | POST | `/v1/documents/{slug}/versions/template` | json | ✓ |
| `present` | POST | `/v1/present` | json `{slug,version?,ttl_seconds?,editable?}` | ✓ |
| `revoke` | POST | `/v1/present/{token}/revoke` | — (token in path) | ✓ |
| `theme-get` | GET | `/v1/theme` | — | ✗ |
| `theme-set` | PUT | `/v1/theme` | json `{tokens,...}` | ✓ |
| `asset-image` | POST | `/v1/assets` | json (base64 image) | ✓ |
| `asset-video` | POST | `/v1/assets/video/direct-upload` | json | ✓ |
| `asset-get` | GET | `/v1/assets/{asset_id}` | — | ✗ |
| `billing` | GET | `/v1/billing` | — | ✗ |

Note `append` is the one **raw**-body verb; everything else folio exposes is
`json` or bodiless. Folio's **public, no-auth** endpoints (`/present/{token}`
and its `/state`/`/edit`/`/preview`, `/llms.txt`, `/skills/`, `/health`) are
**not** verbs — the manifest declares only cert-authed app operations.

## Security invariants

- **Relative-path only.** Reject any `tool.path` with a scheme/host at validation.
- The dispatcher derives `aud`+`path` from the absolute target *it* constructs
  from the granted origin; a manifest cannot override host/scheme.
- Reserved built-in command **names and aliases** cannot be an `app.id` or a verb
  (install-time rejection).

### Parsing and size bounds (fail closed)

- **Single JSON document.** A manifest (and a json-mode `--body-file`) must be
  exactly one JSON document followed only by optional whitespace and EOF. A
  valid object followed by a second document or trailing bytes is rejected — no
  silent acceptance of the first of several documents.
- **Unknown fields rejected (manifest).** Manifest decoding rejects unknown
  object fields at every modeled level (`manifest_version`/`app`/`tools[]`/
  `body`/`event_emitters[]`), so a misspelled security-sensitive field (e.g.
  `auht` for `auth`) fails closed instead of silently defaulting. Arbitrary
  keys inside `input_schema` (a free-form JSON Schema) are unaffected.
- **Declared maxima are enforced by reading one extra byte.** Oversize input is
  rejected with a clear error; no truncated artifact is ever installed, renamed,
  hashed as provenance, or executed. Defaults: manifest document 10 MiB, plugin
  executable 100 MiB, manifest-tool HTTP response body 10 MiB, `--body-file` /
  stdin request body 10 MiB. The provenance digest covers the complete accepted
  bytes.
- **Atomic install.** A failed install or oversize update leaves the previous
  executable intact and removes the temporary file; the executable is written to
  a `.tmp` opened `O_EXCL` and renamed into place only after full, in-bounds
  receipt.

## Explicitly NOT in this schema

- **A2A Agent Card / publication semantics** — separate contract; no card
  skills, JSON-RPC bindings, or publication routes here.
- **Auth method (default)** — fixed: v2 team-auth (`aw id request --team-auth`
  for the CLI). This is the default for every tool.
  The one per-tool override is `auth` (below); there is no other per-tool auth
  configuration.

## Per-tool `auth` field

Each `tools[]` entry MAY carry an optional `auth` field. The shipped v1 parser
accepts exactly these wire shapes:

- **absent** — the default: the request is signed with the caller's v2 team-auth
  identity;
- **`"none"`** — a public tool: the request is sent **unsigned**, with no
  signing identity resolved. This lets a zero-identity caller browse a public
  catalog (for example, `aw library list-blueprints`).

Hard rules a consumer MUST enforce identically:

- `auth: "none"` is valid only on a **non-mutation** tool. A mutation marked
  `auth: "none"` is rejected.
- Every other explicit value is rejected. In particular, explicit
  `auth: "team-cert"` is **not** accepted by the current parser; team-cert is
  represented by omitting the field.
- A consumer must send `auth: "none"` tools unsigned and tools with an absent
  field signed. Reversing that decision is a conformance divergence.

aw implements this in `internal/appmanifest` (`normalizeToolAuth`) and the
plugin dispatch (signed vs unsigned branch). The live `library` manifest uses
it: `list-blueprints`, `get-blueprint`, `get-profile` are `auth: "none"`; every mutation
omits `auth` and is signed.

## Future manifest versions (backlog — not v1)

Deferred consistently; capture so they aren't lost. None block v1.

- **Cross-field param constraints** (e.g. `oneOf` / mutual-exclusion). folio's
  `create` accepts mutually-exclusive `body | template` (exactly-one, enforced
  server-side as 422); the v1 manifest declares both fields but **cannot express
  the exactly-one-of constraint**, so it's invisible to a consumer reading the
  manifest. v1 relies on server enforcement (correct today). A later version
  could carry a small constraint grammar over params. *(Flagged by folio at real
  usage, 2026-06-17.)*
- **`multipart` body mode** (no current app needs it).
- **Float body fields** (pin Go↔Python float canonicalization; v1 forbids them).
- **Output selectors / streaming responses** (v1 is verbatim passthrough).

## Compatibility and change control

`manifest_version: 1` is frozen for the fields and mapping rules above. Additive
application releases use `app.version`; a breaking interpretation change needs
a new `manifest_version` and new conformance fixtures. Streaming responses,
multipart bodies, float canonicalization, and output selectors remain outside
v1 until source, vectors, and this contract change together.
