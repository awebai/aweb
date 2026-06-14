# atext Source of Truth

`atext` is the **reference BYOT agent-first application**: the smallest
non-trivial service where agents authenticate by presenting an AWID team
certificate — no accounts, no passwords, no signup. A team's agents (and the
people they work with) co-author durable shared documents, and any member can
mint a unique, revocable, no-login link that **presents** a specific version of
a document to an outside audience. It is deliberately small: plain-text
documents, append-only versions, team-certificate auth, capability-scoped
presentation, one team-level subscription. Anything more complex must earn its
way in from use.

## Why this app

The reference app has one job: prove the BYOT promise end to end with the
least possible domain noise. Shared team text fits because:

- the domain is minimal but real — agent teams genuinely need durable shared
  text (handoffs, notes, drafts, a pitch the team is polishing) that outlives
  any single workspace and isn't a git repo;
- every write is attributed to a verified member identity, so the app
  exercises the full auth texture: per-request signatures, certificate
  verification, revocation, team scoping;
- presenting a document to an outsider via a capability link exercises the
  second half of the story — a public, no-login surface that leaks nothing
  about the team and can be revoked — without inventing accounts for the
  audience;
- "one member subscribes, all members use it" maps exactly onto team-level
  billing — the second moment the human appears in an agent-first app, to pay;
- nothing in it duplicates aweb itself (a task board would) and nothing in
  it adds infrastructure noise (file storage would).

Rejected alternatives: URL shortener (trivial, no identity texture), task
board (duplicates aweb coordination), file/blob store (storage complexity
swamps the auth lesson).

## Where the human appears

atext inverts the usual app: the **agent is the user**. There is no signup
button because the agent is already signed in — it holds a team certificate.
The human shows up in exactly two brief, no-login browser moments, never as an
account:

- **To pay.** One member subscribes the team — the agent hands its human a
  payment link, the human pays once in the browser, and every member, current
  and future, is covered. The human never gets an atext login; Stripe collects
  the email.
- **As the audience.** When the team wants to show a document to someone
  outside it — an investor, a client, a partner — a member mints a present
  link and hands over the URL. The audience opens it in a browser, sees the
  document rendered in the team's brand, and never logs in.

That is the whole human-facing surface of an agent-first app: the human pays,
and the human is shown things — both as fleeting browser visits, never as a
seat in a dashboard.

## Product contract

A team has documents. A document is UTF-8 text (markdown) plus append-only
versions; each version records which authenticated agent created it.

A team can **present** a document: mint an opaque, expiring, revocable
capability token bound to a specific document version. The token resolves,
with no authentication, to a server-rendered read-only page of that version.
Presentation is the only way document content leaves the team boundary, and it
is always explicit, scoped to one version, and revocable.

atext does not provide rich-text editing, operational transform, CRDT sync,
branches, inline comments, or document-level ACLs. The permission boundaries
are exactly two: **AWID team membership** (to author and to mint) and the
**capability token** (for the audience).

Billing is a separate axis from permission: a single team-level subscription
entitles every member and never gates read access or version history. It is
detailed under Subscription and billing.

## Authority model

`atext` is a relying party. It supports Bring Your Own Identity and Team
(BYOIDT/BYOT) and, by the same mechanism, hosted aweb teams whose members
hold team certificates:

- AWID is authoritative for namespaces, team public keys, team
  certificates, and certificate revocation.
- The team controller (customer-held for BYOT, cloud-held for hosted teams)
  signs team certificates. `atext` never receives or stores
  namespace-controller or team-controller private keys.
- Agents present their own identity signature plus a team certificate on
  every team-scoped request.
- `atext` verifies the request locally against cached AWID facts and fails
  closed when verification is indeterminate.
- Stripe is authoritative for payment state; `atext` stores only the
  subscription projection.

The service may cache public AWID facts for performance. The cache is not
product authority; AWID remains the source of truth.

## Authentication envelope

Every team-scoped endpoint requires the **request-bound v2 team-auth
envelope** — the same contract `aweb`/AC verify and `aw id request
--team-auth` produces (CLI >= 1.26.17). This envelope binds the signature to
the specific request so a captured signature cannot be replayed against a
different endpoint, method, or host. `atext` is the canonical third-party
relying party for it.

Headers on every team-scoped request:

```http
Authorization: DIDKey <did:key:z6Mk...> <base64url-no-padding-ed25519-signature>
X-AWEB-Timestamp: <RFC3339 UTC timestamp>
X-AWID-Team-Certificate: <base64-standard-json-team-certificate>
X-AWEB-Signed-Payload: <base64url-no-padding canonical-JSON of the signed payload>
```

The signed payload (the exact bytes carried, canonically encoded, in
`X-AWEB-Signed-Payload`) is canonical JSON with these fields:

```json
{"aud":"https://<atext-host>","body_sha256":"<sha256 hex of request body>","method":"<UPPER>","path":"<path?query>","team_id":"<team>:<namespace>","timestamp":"<RFC3339 UTC timestamp>","v":2}
```

The Ed25519 signature is computed over the raw bytes of the decoded
`X-AWEB-Signed-Payload`, not over a payload the server reconstructs. The
server then independently validates every claim against the actual request,
so a valid signature is necessary but not sufficient.

Verification steps:

1. Require `X-AWEB-Signed-Payload`; decode it (base64url, no padding) and
   require it to be **canonical** (`canonical_json(parsed) == decoded
   bytes`) — reject otherwise.
2. Require `v == 2`. Reject other/absent versions (`atext` does not accept
   the legacy compact envelope; its only client speaks v2).
3. Parse the DIDKey auth header and `X-AWEB-Timestamp`; reject timestamps
   outside the skew window (default 300s); require the signed `timestamp`
   to equal the header.
4. Compute `body_sha256` from the exact request bytes; require the signed
   `body_sha256` to match.
5. Require the signed `method`, `path` (raw on-the-wire path + query), and
   `team_id` to equal this request's, and the signed `aud` to canonicalize
   to `atext`'s own configured public origin. Mismatch on any field fails
   closed with 401 — this is the request-binding that prevents replay.
6. Verify the DIDKey signature over the decoded `X-AWEB-Signed-Payload`
   bytes.
7. Decode the team certificate; require `certificate.member_did_key ==
   request.did_key`.
8. Resolve the certificate's `team_id` to the team public key from AWID
   (cached); verify the certificate signature against the AWID-resolved team
   key, never against the `team_did_key` field by itself.
9. Check `certificate_id` against AWID revocation facts (cached).
10. Build the request principal from the verified certificate.

If AWID is unavailable and no unexpired cache entry exists, the request
fails closed with 503/401. Never fall back to trusting a presented
certificate without an AWID-resolved team key. `atext`'s configured public
origin must equal the host clients reach it at (the `aud` they sign); a
misconfigured origin fails every v2 request closed rather than silently
accepting.

The reference verifier for this envelope is `aweb.team_auth_envelope`
(server-side) — `atext/auth.py` implements the same contract independently
so the relying-party path is self-contained and copyable.

## Presentation links

A team member presents a document by minting a **capability link** — the
second relying-party surface after team-auth, and the only public one.

- **Mint** (cert-auth): `POST /v1/present` with `{slug, version?,
  ttl_seconds?, template?, strict?}`. atext verifies the document's `team_id
  == principal.team_id` **before** minting — a member cannot mint a link for
  another team's document (404, no existence signal). It records an opaque
  random `token`, the `document_id`, the pinned `version_number`, an
  `expires_at`, and the minting identity, and returns `{token, url,
  expires_at}`.
- **Pinned by default**: the link freezes the version at mint time, so the
  audience sees exactly what was sent. Following latest is a possible later
  option, never the default.
- **Revoke** (cert-auth): `POST /v1/present/{token}/revoke` — only the owning
  team can revoke; the link dies immediately.
- **Resolve** (public, no auth): `GET /present/{token}` returns a
  **server-rendered HTML page** of the pinned version, styled by the team's
  theme. Unknown, expired, or revoked tokens return 404 with no team,
  document, creator, version, or existence signal — the same opaque-failure
  discipline as team-auth.

The capability token is the entire authority for the audience: holding the
URL is the permission, the URL carries no identity, and revocation or expiry
ends access with no account to disable.

## Themes and templates

Presentation is branded, optional, and safe by construction. Because
`/present/{token}` is public and unauthenticated, every rendering input is
**declarative data atext renders server-side** — never agent-authored HTML or
JavaScript.

**Theme (v1).** A team has an optional theme: brand tokens (colors, fonts), a
logo uploaded as a team asset, and optional header/footer text. `PUT
/v1/theme` sets it (cert-auth, team-scoped); `GET /v1/theme` reads it. The
present page renders the document's markdown into a content region wrapped in
the team's theme. Any markdown fits any theme — the theme only wraps and
styles — so there is no "does the content fit" failure mode. No theme → a
clean default style.

**Templates (designed-in, deferred).** A template adds structure: a
declarative layout with named slots (e.g. cover, sections, metrics, ask)
bound to content and rendered by atext's own renderer. This adopts A2UI's
*idea* — declarative, data-bound layout that agents can generate as JSON — as
a small presentation-specific schema atext owns and renders, **not** the
CopilotKit A2UI catalog or renderer. A template publishes a JSON Schema for
its slots plus a worked example (`GET /v1/templates/{name}`); a document opts
in by naming a template and providing matching content; atext validates at
mint/render time and returns precise errors, or — minting `strict:false` —
falls back to the themed-markdown render. Templates are therefore **never
mandatory**: no template → themed markdown; mismatch → fallback; they only
ever upgrade a presentation, never block it. Templates start as a few
**built-in layouts** the team themes; letting teams author their **own**
declarative templates is an attractive future possibility, gated on a careful
safety design before it is scoped. Either way templates stay declarative and
server-rendered, never raw HTML/JS.

## Subscription and billing

The claweb pattern, team-shaped: **no human accounts, no passwords, no
OAuth, no sessions.** The human appears exactly once here — to pay (the other
appearance is as the audience of a present link).

Scope split: **v1 ships the caps and the read-only billing status; the
Stripe integration (checkout, portal, webhook) is v2.** Caps are enforced
from day one so no team is ever grandfathered into uncapped usage; in v1
the structured 402 names the limit and states that subscriptions are not
yet available. When v2 lands, the same 402 starts naming the checkout
command and paying lifts the caps — no client change.

- The subscription unit is the **team**. One active subscription covers
  every member of that team, current and future.
- **Free tier** (v1): per-team caps enforced server-side —
  `FREE_MAX_DOCUMENTS` (default 3) and `FREE_MAX_VERSIONS_PER_DOC`
  (default 50). Caps return a structured 402 naming the limit.
- **Checkout** (v2): any verified member requests it.
  `POST /v1/billing/checkout` (cert-auth) creates a Stripe Checkout Session
  for that team and returns the URL. The agent hands the URL to its human
  ("here is the payment link"); the human pays in the browser. The Stripe
  customer email is whatever the human enters at checkout — `atext` never
  collects it.
- **Activation** (v2): the Stripe webhook (`checkout.session.completed`,
  `customer.subscription.updated|deleted`) flips the team's subscription
  projection. All members are covered on the next request; no client change.
- **Management**: `POST /v1/billing/portal` (v2, cert-auth) returns a
  Stripe customer-portal link for the paying human; `GET /v1/billing` (v1)
  returns the team's tier, caps, and current usage to any member.
- Webhook handlers verify the Stripe signature, are idempotent by event id,
  and tolerate replay.

Cancellation downgrades the team to the free tier; data is never deleted by
billing state. Over-cap teams keep read access and version history.

## Client: `aw id request --team-auth`

atext ships **no client code**. The `aw` CLI every agent already has is the
client: `aw id request` makes a DIDKey-signed HTTP request with the local
identity key, and `--team-auth` attaches the active team certificate and
produces the request-bound v2 envelope above (`X-AWEB-Signed-Payload` over
`{v:2, aud, method, path, team_id, body_sha256, timestamp}`). Having a valid
certificate IS being signed in, and the client is already installed.
Requires `aw >= 1.26.17`, which emits the `v:2` marker (verified live
against the hosted gateway 2026-06-12; 1.26.16 omits it and fails closed).

```bash
# create a document
aw id request POST https://<atext-host>/v1/documents \
  --team-auth --body '{"slug":"pitch","title":"Pitch","body":"..."}'

# append a version (raw UTF-8 body)
aw id request POST https://<atext-host>/v1/documents/pitch/versions \
  --team-auth --body-file pitch.md

# set the team's presentation theme (brand colors, logo)
aw id request PUT https://<atext-host>/v1/theme \
  --team-auth --body '{"tokens":{"primary":"#0b1020","accent":"#7c5cff"}}'

# present the current version to an outsider; hand the url to your human
aw id request POST https://<atext-host>/v1/present \
  --team-auth --body '{"slug":"pitch","ttl_seconds":604800}'
#   -> {"token":"...","url":"https://<atext-host>/present/<token>","expires_at":"..."}

# revoke the link when the round closes
aw id request POST https://<atext-host>/v1/present/<token>/revoke --team-auth

# billing (v2): print the Stripe payment link for your human
aw id request POST https://<atext-host>/v1/billing/checkout --team-auth
```

- Errors are structured server codes; a 402 names the cap and the checkout
  call.
- A thin `atx` wrapper is explicitly deferred: it may be added later as
  sugar only if real usage demands it, and it would shell out to or share
  state with `aw`, never duplicate signing.

This is the heart of the reference story: **a third-party BYOT service
ships only a server.** The copyable relying-party pair is `atext/auth.py`
(verify) and `aw id request --team-auth` (call). A service README
documents endpoints and example `aw id request` lines, nothing else.

## Site

A Hugo static site is the public face: a landing page telling the BYOT
story (certificate in, authenticated request out, the human appears only to
pay and to view a presented document, never as an account) and the
tutorial/recipes as
docs pages sourced from the README. Clean, minimal, text-first, with a quirky
voice: the site's job is to make the point that agent-first apps are possible
now. It leans into the inversion — the agent is the user; there is no signup
button because your agent is already signed in; the human appears the way they
appear in the product: once to pay, and as the audience of a presented
document. The quirk
lives in the copy and small touches, never at the cost of clarity; the recipes
stay copy-paste exact.

It is served at `https://atext.ai`, from the same origin as the API: the
site at `/`, the API under `/v1/*`, presented documents under `/present/*`.
One host, one certificate, one deploy; the v2 envelope's `aud` binding is
unaffected because paths differ. The landing is static files; the present
pages are server-rendered read-only HTML (no client framework). Source lives
under `site/`; the build is a make target. A plain-text twin of the landing
ships at `/llms.txt` for agents that fetch instead of browse.

## Model repo

atext is also the model repo for agent teams building their own
agent-first app. Two artifact sets serve that audience:
`docs/agent-first.md` — the pattern (what you don't build, what you do)
plus a repo map saying which files to copy verbatim, which to adapt,
and which are domain noise to replace — and `skills/` — three skills
(`agent-first-app`, `team-cert-verification`, `byot-e2e-validation`)
with trigger-rich descriptions so an agent team loads the judgment at
the moment it would otherwise make the classic mistakes. The present +
theme surface is the second copyable lesson (capability-scoped public
sharing without accounts). Code and e2e tests remain the ground truth; the
prose stays thin and points at them.

## Canonical repo and provenance

atext lives in `github.com/awebai/atext` — its own history, rooted in the
BYOT scaffold. The spine was proven live during the London generative-UI
hackathon inside a separate, forked vehicle (a CopilotKit example fork)
deployed at atext.ai; that vehicle's generative-UI layer — CopilotKit + A2UI
rendering, a LinkUp `/v1/search` endpoint, a LangGraph concierge — was the
hackathon theme, not BYOT, and is dropped. The genuinely evolved spine bits —
the cross-team isolation e2e proof, the Neon/PgBouncer-safe database config,
and the container deploy wiring — are ported back into this repo, which
becomes the single canonical home and the deploy source for atext.ai.
Presentation is server-rendered here; no CopilotKit, no A2UI renderer, no
client framework on the public page. The hackathon repo is archived once
atext.ai serves from this one.

## Data model

### Team

- `team_id`: canonical AWID team id, `<name>:<namespace>`.
- `team_did_key`: AWID-resolved team public key used to verify certs.
- `first_seen_at`, `last_seen_at`.

### Subscription

One row per team:

- `team_id` (unique), `tier` (`free` | `active` | `past_due`),
- `stripe_customer_id`, `stripe_subscription_id` (nullable),
- `current_period_end`, `updated_at`,
- `last_event_id` (webhook idempotency).

### Agent

Scoped by `(team_id, did_key, alias)`:

- `did_key`: request signing identity.
- `did_aw`: stable identity when present.
- `address`: certificate-selected sender address when present.
- `alias`: team-local alias from the certificate.
- `latest_certificate_id`: latest observed cert id.
- `first_seen_at`, `last_seen_at`.

The same `did_aw` may appear in multiple teams. Do not collapse agent rows
by `did_aw` globally.

### Document

- `document_id`: UUID; `team_id`: owner team; `slug` (unique per team);
  `title`; `created_by_did_key`, optional `created_by_did_aw`,
  `created_by_alias`; timestamps.

### Document version

- `version_id`, `document_id`, `version_number` (monotonic per document),
  `body` (UTF-8 markdown), creator identity fields (`did_key`, optional
  `did_aw`, address, alias, certificate id), `created_at`.

Versions are append-only. Fixes are new versions.

### Presentation link

One row per minted link:

- `token` (PK, opaque random), `document_id`, `version_number` (the pinned
  version),
- `expires_at`, `revoked_at` (nullable), `created_at`,
- minting identity (`did_key`, optional `did_aw`, alias, certificate id),
- FK `(document_id, version_number)` → document version; team ownership is
  derived through the document, never stored on the link or trusted from the
  request body.

### Theme

One row per team:

- `team_id` (unique), `tokens` (JSON: colors, fonts), `logo_asset_id`
  (nullable), `header`, `footer` (nullable), `updated_at`.

Template storage is deferred with the template layer.

## API shape

Team-scoped (cert-auth):

- `POST /v1/documents` — create a document with initial body.
- `GET /v1/documents` — list documents for the authenticated team.
- `GET /v1/documents/{slug}` — fetch current version.
- `GET /v1/documents/{slug}/versions` — list version metadata.
- `POST /v1/documents/{slug}/versions` — append a new text version. The
  request body is the raw UTF-8 text of the new version, not JSON (so
  `--body-file notes.md` appends the file as-is); invalid UTF-8 is
  rejected. Document creation stays JSON because it carries slug and title.
- `POST /v1/present` — mint a capability link for a document version.
- `POST /v1/present/{token}/revoke` — revoke a link the team owns.
- `GET /v1/theme` / `PUT /v1/theme` — read/set the team's presentation theme.
- `GET /v1/billing` — subscription status, caps, usage.
- `POST /v1/billing/checkout` — Stripe Checkout URL for this team (v2).
- `POST /v1/billing/portal` — Stripe portal URL for this team (v2).

Unauthenticated:

- `GET /present/{token}` — server-rendered HTML of the pinned version,
  themed; unknown/expired/revoked → 404 with no team/document/version/creator
  or existence signal.
- `POST /v1/stripe/webhook` — Stripe-signature-verified events (v2).
- `/live`, `/ready`, `/health` — ops.

All team routes are scoped to the authenticated certificate's `team_id`. A
request must not name another team in the body and bypass this scope.
Minting must verify document ownership against the principal's `team_id`
before issuing a token.

## Validation strategy

The point of the reference app is that the auth actually works, proven the
hard way:

1. **Unit/interop**: verify the v2 envelope implementation against
   `aweb.team_auth_envelope` and the aweb repo's signing/certificate test
   vectors (`aweb/test-vectors/`) so atext and aweb agree byte-for-byte on
   canonical JSON, the request-binding fields, and signatures. Include the
   replay negatives the live proof exercised: a signature minted for one
   path/method/host must fail against another.
2. **E2E, no mocks**: docker-compose with a local awid-service + postgres;
   create a real namespace, team, controller, member certs with `aw id`;
   exercise every endpoint with real signatures, including revocation
   (revoke a cert, watch the request fail) and fail-closed (stop awid,
   watch 503 after cache expiry).
3. **Present + isolation e2e** (two real teams A and B):
   - B mints a present link for A's document slug/id → 404, no existence
     signal.
   - A request naming another team in the body lands in the caller's team
     (body team ignored).
   - public `GET /present/{token}` returns only the bound version's rendered
     page — no team, document id, creator, version, or existence fields;
     bogus/expired/revoked → 404.
   - revoke kills the link immediately; the pinned version is stable across
     later appends to the document.
4. **Theme**: a themed present page applies the team's tokens/logo; no theme →
   clean default; (template-fallback test lands with the template milestone).
5. **Billing**: v1 cap enforcement and the structured 402 without Stripe; v2
   Stripe test mode — checkout → webhook → caps lift, cancellation → caps
   return, with genuinely HMAC-signed webhook events (no stripe-mock).
6. **Hosted-team probe**: an agent from a real hosted aweb team calls
   atext with `aw id request --team-auth` — validates the "any aweb team
   can use a cert-auth app" claim end to end. If anything in the hosted
   chain falls short (e.g. revocation projection), raise it as an
   aweb-cloud finding, never paper over it.
7. **Customer-shaped probe before any public mention**: fresh directory,
   released `aw` only, the documented `aw id request` lines verbatim,
   including minting a present link and opening it in a browser.

TDD for every feature; tests that exercise mocked behavior instead of real
crypto/services are not acceptable in the e2e layer.

## Milestones

- **M1 — canonical spine**: port the cross-team isolation e2e, the
  Neon/PgBouncer-safe database config, and the container deploy wiring into
  this repo from the hackathon vehicle; keep the free-tier caps and billing
  status; drop the artifacts/search/A2UI surface. Exit: revocation, fail-closed,
  path/method/aud-mismatch replay, and cross-team isolation negatives all
  green against local awid e2e.
- **M2 — present**: document-bound capability links — mint (ownership-checked),
  server-rendered resolve, pin-by-default, revoke, public-leaks-nothing.
  Exit: present + isolation e2e (milestone-3 above) green; a minted link
  renders read-only with no login.
- **M3 — theme**: team brand tokens + logo applied to the present page;
  `GET`/`PUT /v1/theme`; optional, with a clean default when unset. Exit:
  themed render verified; no-theme default verified.
- **M4 — deploy + hosted-team validation**: atext.ai served from this repo
  (re-pointed off the hackathon vehicle, container on Render + Hugo landing);
  hosted-team probe recorded; the hackathon repo archived.
- **M5 (deferred) — templates**: atext's own declarative layout schema, one
  built-in structured layout, schema-validated slots with themed-markdown
  fallback, `GET /v1/templates/{name}` publishing schema + example.

V2 — Stripe billing: checkout, portal, webhook, the billing recipes, and the
402 naming the checkout command. Exit: Stripe test-mode e2e green; 402 → pay →
200 demonstrated. This is the model-repo lesson on how an agent-first app
bills, so it ships as a clean, copyable track even though it is deferred past
the present/theme showcase.

V2 implementation contract (modeled on claweb, the reference agent-first
payment system, team-shaped):

- Checkout Sessions carry the canonical `team_id` in `client_reference_id`;
  Stripe collects the payer email at checkout — atext never does.
- Webhook signature verification per Stripe's scheme (HMAC-SHA256 over
  `timestamp.payload`), 300s replay tolerance; handled events:
  `checkout.session.completed`, `customer.subscription.updated`,
  `customer.subscription.deleted`. Idempotency by event id (`last_event_id`
  on the subscription row, per the data model).
- Status mapping: Stripe `active`/`trialing` → `active`; `past_due` →
  `past_due`; `canceled`/subscription deleted → `free`. Billing state never
  deletes data.
- Config: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`,
  `ATEXT_STRIPE_PRICE_ID`. When unset, billing endpoints return the v1 "not
  yet available" behavior — the service runs fine without Stripe (claweb's
  graceful-disable pattern).
- The structured 402 names the checkout recipe when billing is configured and
  keeps the v1 wording when it is not.
- Tests: unit/integration with constructed, genuinely HMAC-signed webhook
  events (real signature verification, no network, no stripe-mock) covering
  activation, replay idempotency, past_due, and terminal cancellation; plus a
  scripted Stripe test-mode probe — real checkout link, human pays with a test
  card, caps lift — before v2 is called done.

Build note: this is a good candidate for a blueprint-created team to build
(dogfood: the team that builds the BYOT example is itself created from a
blueprint).

## Non-goals

- No OAuth, API-key, password, or dashboard-auth write path.
- No accounts for the presentation audience — the capability token is the
  only authority.
- No human accounts, per-seat billing, metered billing, or invoices beyond
  what Stripe's portal provides — one flat team-level subscription, and
  billing state never deletes data or gates read access.
- No hosted-controller authority inside atext. Hosted providers can proxy
  only if they sign as the agent identity and present a valid team
  certificate.
- No document-level ACLs beyond team membership and the capability link; no
  cross-team documents.
- No agent-authored HTML/JS on the public page; all presentation inputs are
  declarative data atext renders.
- No CopilotKit/A2UI renderer or client framework on the public page —
  presentation is server-rendered.
- No E2E encryption claim. Text stored in `atext` is server-readable unless
  a future client-side encryption layer is explicitly designed.

## Hosted teams are first-class callers

Direction confirmed by Juan (2026-06-12): hosted aweb teams must be able to
present their certificates to third-party apps, not only BYOT teams.

Evidence this already works: hosted teams are real AWID teams in the public
registry — `GET api.awid.ai/v1/namespaces/<ns>/teams/<name>` returns the
`team_did_key` for a dashboard-created hosted team, and hosted members hold
certificates in `.aw/team-certs/`. The difference from BYOT is only who holds
the controller key that signed the cert (cloud vs customer); the verification
path atext implements is identical. M1's e2e and M4's live probe prove the
full chain (cert signature against registry key, revocation listing). Any gap
found (e.g. hosted revocations not projected to the public registry) is an
aweb-cloud work item to file, not something atext works around.

## Open questions (for Juan)

1. **Team-authored templates (future)**: built-in layouts are decided for the
   template milestone; letting teams author their own declarative templates is
   attractive but needs a careful safety design (still declarative, sandboxed,
   server-rendered, never raw HTML/JS) before it is scoped.
2. **Present-link prettiness**: links resolve on the app origin under
   `/present/<token>`; routing them under a tidier path is a later polish.
3. **Pricing**: one tier ("team"), placeholder `$20/team/month` (coordinator's
   working value — Juan revisits before launch). Tests and e2e run with
   synthetic Stripe config; only the human-pays test-mode probe needs real
   test keys.

Decided (2026-06-14): billing stays in the showcase — caps in v1, Stripe in
v2 — because "how to build an agent-first app that bills" is a core model-repo
lesson; it was pulled only for the hackathon submission. The canonical repo is
`github.com/awebai/atext`; the hackathon vehicle is archived after re-point.
Presentation is document-bound, server-rendered, themed, pinned-by-default;
A2UI's idea is adopted as atext's own declarative template schema, its
machinery is not. Templates start as built-in layouts the team themes;
team-authored templates are a future maybe, gated on a safety design (Juan,
2026-06-14). The hosted instance lives at `https://atext.ai` (Juan,
2026-06-12).

## Implementation notes

- Use `pgdbm` migrations with module name `atext`; deployed migrations are
  immutable — recovery is a new forward migration.
- Keep auth code small and explicit; interop tests against aweb's
  certificate vectors before adding features.
- Server-side present rendering uses a sanitizing markdown renderer; the
  public page embeds no untrusted HTML.
- Python 3.12, FastAPI, httpx, stripe; `uv` for everything. Neon Postgres via
  a PgBouncer-safe pool config.
