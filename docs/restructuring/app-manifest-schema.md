# App manifest schema (m1.1) — DRAFT for review

Status: **frozen v1** for `default-aaai.1` — dispatch-consumer **+1** (cli/ team,
`default-aaai.2`) and **consultant-validated**. Grounded in folio's real API
(`folio/src/folio/api.py`). Pairs with the shared conformance suite
(`default-aaai.4`). Part of SoT §7. (Folio verb *naming* is a separate folio-team
call, brokered via the atext coordinator; it does not change this contract.)

## Purpose

One declaration per app that **three consumers interpret identically**:

1. the hosted gateway's MCP tool composition (§6.5),
2. the `aw <app>` CLI verbs — a generic dispatcher over the existing
   `aw id request --team-auth` signed-request backend (§10),
3. the aweb.ai hub listing.

The manifest is a **core contract** (CLI and gateway are co-equal consumers).
Two hard rules: **param placement is explicit, never inferred**, and **paths are
relative** (the dispatcher builds the absolute target from the granted app
origin). It is **not** an A2A Agent Card — Agent Card / publication semantics are
a separate contract (SoT §3.2) and must not appear here.

## Top-level structure

```jsonc
{
  "manifest_version": 1,
  "app": {
    "id": "folio",                       // verb namespace: `aw folio ...`; reserved built-in names/aliases rejected at install (cli m2.1)
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

## Manifest discovery

An app serves its manifest at a **well-known path on its origin**:
`<app.origin>/.well-known/aweb-app.json` (RFC 8615; parallels A2A's
`/.well-known/agent-card.json` — kept **distinct** on purpose, reinforcing the
§3.2 guardrail that a manifest is *not* an Agent Card). The dispatcher and the
gateway fetch it from there.

Discovery is an **unauthenticated public GET** — the manifest is public metadata
describing the app's verb surface (like `llms.txt`, an OpenAPI document, or an
A2A agent-card; folio already serves `llms.txt`/`skills` no-auth). **Team-auth
applies only to the verb *calls* the manifest describes, never to fetching it.**

Consumers fetch at **install/update time** and store the manifest **locally with
provenance** (origin, `manifest_version`, app version, byte digest); dispatch
reads the local copy — it is **not** a per-call fetch. `aw plugin update`
re-fetches.

The core **app registry** (SoT §3) later records this URL **plus a
digest** for trust/discovery — mirroring the AWID A2A publication contract
(the authoritative fact is URL + digest, not the cached body; body caching never
overrides digest verification). For v1 and the folio proof, the dispatcher
fetches the well-known path directly; registry-recorded discovery is part of the
core app-registry work (SoT §12 m3). *(Freeze-completeness addition flagged by
the folio team — the original freeze omitted the manifest's own location.)*

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
  "scopes": ["folio:write"],             // grant scopes the gateway checks against app grants
  "mutation": true                       // true iff a successful call is a hosted state change (SoT §9)
}
```

### Field rules

- **`method`** — enum `GET|POST|PUT|PATCH|DELETE` for v1.
- **`path`** — **relative only**. Each `{name}` placeholder must have a matching
  param with `"in":"path"`. A path carrying a scheme/host is **rejected at
  validation** (a host-injecting manifest would redirect a signed, authenticated
  request — see Security).
- **`params[].in`** — one of `path | query | body`, **required for every field**
  in `input_schema`. The dispatcher and gateway **never infer** placement.
- **`body.mode`**:
  - `json` (default) — `in:body` params assembled into **canonical JSON**
    (mandatory; see the mapping section — it lands in the signed `body_sha256`).
  - `raw` — exactly one param carries the raw request body; declare it with
    `body.raw_param` and an explicit `body.content_type` (e.g. folio
    version-append: `raw_param: "body"`, `content_type: "text/markdown; charset=utf-8"`).
    Other params may still be `in:path`/`in:query`.
  - *(multipart deferred to a later version; no current app needs it.)*
- **`scopes`** — grant scopes the app requires; the gateway checks them against
  the team's app grants. (The CLI carries the team certificate directly.)
- **`mutation`** — `true` iff a *successful* call is a hosted state change per
  the SoT §9 mutation definition (not reads, not failed validation, not retries).
  Drives bundled-quota counting.

## Event emitters (additive m3.2 section)

`event_emitters` declares app-owned Ed25519 `did:key` emit keys that may sign
app-emitted events for an installed app. This is the first-cut m3.2 stopgap key
source, not the durable app-as-AWID-identity model (tracked separately in m3.1
follow-up / `default-aaaj.6`).

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
   (`id_request.go:303-311`), so the CLI and the gateway MUST encode identically
   or the signed path diverges and the verifier rejects. Hard contract: RFC 3986
   percent-encoding; arrays → repeated keys (`k=v1&k=v2`); order = `params[]`
   declaration order. Omitted optional fields are absent, not empty.
3. **Body** = per `body.mode`.
   - `json` → **first coerce** each `in:body` value to its `input_schema` type
     (CLI flags arrive as argv **strings**; the gateway gets already-typed JSON
     from MCP — both must converge to the SAME typed value before serializing,
     e.g. `ttl_seconds` → integer `3600`, not string `"3600"`; `editable` →
     boolean). The coerced value is what gets serialized and signed. Then
     assemble into **canonical JSON — mandatory**: sorted keys, no insignificant
     whitespace, HTML-escaping **off** (`SetEscapeHTML(false)`), matching the
     existing `awid/signing.go` `CanonicalJSON` / `CanonicalJSONValue`
     convention. The v2 envelope signs `body_sha256` over the *exact* body bytes,
     so Go (CLI) and Python (gateway) must serialize **byte-identically** or they
     produce different signatures. **v1 number rule:** integers are byte-identical
     Go↔Python; **floats are not** (strconv vs Python repr) — avoid float body
     fields in v1 (a later version pins float canonicalization if needed).
   - `raw` → the `raw_param` bytes with `content_type`, written via
     `--body-file` (not argv — avoids length/binary issues).
4. **Content-Type** is set **explicitly by the mapping in both modes**
   (`json` → `application/json`; `raw` → `body.content_type`). Do **not** rely on
   any consumer's implicit default (`aw id request` defaults to JSON only when no
   header is set — `id_request.go:170-171` — which the gateway won't replicate).
   Content-Type is not in the signed payload, but pinning it keeps the two
   consumers byte-identical.
5. The dispatcher invokes `aw id request --team-auth <method> <target?query>`
   (`--body` for json / `--body-file` for raw, `--header Content-Type: …`), which
   produces the v2 envelope (`aud`+`method`+`path`+`team_id`+`body_sha256`).

⇒ A conformance vector (`default-aaai.4`) asserts the **interpreted request spec
before signing**: `(manifest, verb, args) → exact (method, absolute URL, raw
path+query, headers/content-type, body bytes, body_sha256, mutation flag)`. It
does **not** assert the dynamic Authorization/timestamp/signature bytes — those
stay in the existing team-auth crypto tests. CLI dispatcher and gateway must
produce **byte-identical** interpreted specs.

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
(`default-aaai.3`) must work end-to-end **without** external `jq`/shell glue — if
it needs that, the gap is in the dispatcher/manifest, not hidden in the test.
(A tiny output selector is a possible later manifest version; not v1.)

## Worked example — folio (every current cert-authed verb)

Grounded in `folio/src/folio/api.py` (verified body shapes):

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

## Security invariants (encoded as conformance vectors — `default-aaai.4`)

- **Relative-path only.** Reject any `tool.path` with a scheme/host at validation.
- The dispatcher derives `aud`+`path` from the absolute target *it* constructs
  from the granted origin; a manifest cannot override host/scheme.
- Reserved built-in command **names and aliases** cannot be an `app.id` or a verb
  (install-time rejection; cli `default-aaai.2`).

### Parsing and size bounds (fail-closed; `default-aajc.4`)

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

- **A2A Agent Card / publication semantics** (SoT §3.2) — separate contract; no
  card skills, JSON-RPC bindings, or publication routes here.
- **Auth method (default)** — fixed: v2 team-auth (`aw id request --team-auth`
  for CLI; gateway-signed for hosted MCP). This is the default for every tool.
  The one per-tool override is `auth` (below); there is no other per-tool auth
  configuration.

## Per-tool `auth` field

Each `tools[]` entry MAY carry an optional `auth` field. It is the only per-tool
auth control, and it has exactly two values:

- **absent / `"team-cert"`** — the default: the request is signed with the
  caller's v2 team-auth identity (as above).
- **`"none"`** — a public tool: the request is sent **unsigned**, with no
  signing identity resolved. This is what lets a zero-identity caller browse a
  public catalog (e.g. `aw library list-blueprints`).

Hard rules a consumer MUST enforce identically:

- `auth: "none"` is only valid on a **non-mutation** tool. A mutation marked
  `auth: "none"` is a manifest error and MUST be rejected at validation.
- Any `auth` value other than `"none"` or `"team-cert"` is rejected.
- A consumer interpreting the manifest MUST send `auth: "none"` tools unsigned
  and all other tools signed. Treating an `auth: "none"` tool as signed (or
  vice-versa) is a conformance divergence.

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

## Open questions for reviewers

1. **cli (dispatch):** is `body.raw_param` + `body.content_type` the right way to
   express the raw-body case, or do you want a different shape for the
   verb→`--body-file`/`--body` wiring?
2. **cli:** query-param encoding edge cases (arrays, repeated keys) — pin in the
   conformance vectors?
3. **folio:** confirm the verb names above are the ones you want surfaced as
   `aw folio <verb>` (naming is product-facing).
4. **general:** response handling — *resolved* per consultant pass: v1 is
   verbatim passthrough (above). Streaming/SSE (none in folio today) is deferred
   to a later manifest version. Flagging only if a v1 app needs it.

*(Validation 2026-06-16. **Consultant** (architecture): slice + sequencing
confirmed; schema-level AC additions — explicit body mode, CLI binding, response
handling, `manifest_version` rejection, exact path/query encoding — folded; their
m2.1/m2.2/m1.2 AC additions relayed to the cli/ team. **cli/ dispatch-consumer
review**: F1 mandatory canonical JSON body, F2 canonical query encoding in the
signed path, explicit Content-Type both modes, and type coercion of `in:body`
values to their `input_schema` type before serialization (+ the v1 no-float-body
rule) — all folded; **+1 to freeze**. Frozen as v1.)*
