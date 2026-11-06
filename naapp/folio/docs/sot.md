# folio Source of Truth

> `folio.aweb.ai` — the agent-first document & presentation **service** on the
> aweb protocol. Private. Built on the atext spine (see
> [`docs/spine-sot.md`](spine-sot.md), the inherited reference contract).

## What this is

`folio` is where a team's agents author branded, versioned documents — from a
memo to an investor pitch — embed images and video, and hand a human a single
no-login link that renders the document, optionally full-screen.

It is the genuinely-useful, productized sibling of **atext**. Where atext
exists to *teach* the BYOT pattern (the minimal public reference), **folio
exists to be *used*** — by real teams, including us, for real pitches.

## Relationship to atext (the spine)

`folio` is seeded from atext and inherits its spine wholesale — do not
re-derive it; the inherited contract lives in [`docs/spine-sot.md`](spine-sot.md):

- AWID team-certificate auth (the request-bound v2 envelope).
- Team-isolated, append-only versioned documents.
- Document-bound present links (opaque capability token, server-rendered,
  version-pinned, revocable, leaks nothing).
- Themes (validated color/font tokens).

atext stays the **public, minimal reference**; `folio` is a **private** repo
that extends the spine.

**Auth-spine rule (hard invariant).** The authentication/verification code
(`auth.py`) and the team-isolation invariants MUST track atext exactly — they
are security-critical and must never diverge silently. The spine's auth +
isolation are a frozen shared contract: if they change, they change in atext
first (the reference), then flow here. (Open: eventually extract the spine as a
shared dependency so this is enforced by packaging, not discipline.)

## What `folio` adds (the product surface)

Everything atext deliberately refuses — because it would bloat the reference —
earns its place here.

### 1. Media — images and video

- **Images:** agents upload images and embed them in documents
  (`![alt](…)`). Stored as team-scoped assets, served from our origin,
  raster + safe-type allowlist (no SVG / active content), magic-byte
  validated — the atext logo-asset discipline, generalized.
- **Video:** agents upload video and embed it. Video does NOT fit Postgres
  BYTEA — it uses **Cloudflare Stream** (upload → transcode to adaptive HLS →
  CDN delivery → player + signed playback tokens). We store the Stream UID on
  the asset record and embed the player as a trusted first-party element
  behind the capability link. This is the one piece of real infrastructure
  `folio` takes on that atext refuses by design.
- Media renders inside the present page (themed), behind the same public
  capability link.

### 2. Layout & presentation modes (the UX pass, productized)

- The theme controls how content uses the viewport:
  - **document** mode — readable measure (~65ch column), the reading default;
  - **presentation** mode — wide / near-full-bleed, large type, for showing
    to an audience;
  - a `measure` control (narrow/default/wide) and `color_scheme`
    (light/dark/auto).
- **Full-screen** presentations — a minimal, fixed, server-controlled,
  CSP-nonce-gated fullscreen control on presentation pages only; document
  mode stays 100% script-free.
- Print/PDF stylesheet; WCAG contrast validation on theme colors;
  `noindex` on present pages.

### 3. Declarative templates (atext's deferred feature, shipped here)

- atext's own declarative layout schema (cover / sections / metrics / ask):
  built-in layouts the team themes, schema-validated slots, themed-markdown
  fallback. Built-in layouts first; team-authored declarative templates a
  future safety-gated maybe. This is where templates actually ship — not in
  the minimal reference.

### 4. Current agent usage — generic `aw id request --team-auth`

Current folio usage is the generic AWID-authenticated request path documented in
`README.md`, `/llms.txt`, and `/skills/`:

```
aw id request POST "$FOLIO_ORIGIN/v1/documents" --team-auth --raw --body-file create.json
aw id request POST "$FOLIO_ORIGIN/v1/documents/<slug>/versions" --team-auth --raw --body-file body.md
aw id request POST "$FOLIO_ORIGIN/v1/assets" --team-auth --raw --body-file image-upload.json
aw id request POST "$FOLIO_ORIGIN/v1/assets/video/direct-upload" --team-auth --raw --body-file video-upload.json
aw id request PUT "$FOLIO_ORIGIN/v1/theme" --team-auth --raw --body-file theme.json
aw id request POST "$FOLIO_ORIGIN/v1/present" --team-auth --raw --body-file present.json
aw id request POST "$FOLIO_ORIGIN/v1/present/<token>/revoke" --team-auth --raw
```

`aw folio ...` verbs are **not** current product surface. They are deferred to a
future aw plugin track because folio is a private repo and a Python console
script is not distributable as an aw-native verb. The plan is
[`docs/aw-plugin-brief.md`](aw-plugin-brief.md): add an `aw` external-binary
plugin mechanism, then ship `aw-folio` separately as the reference anapp plugin.
Until that lands, agents use `aw id request --team-auth` plus folio's skills and
`/llms.txt`.

### 5. Surfaces (human + agent)

- `folio.aweb.ai` hosts the **human landing/explanation**, the **agent docs**
  (llms.txt + skills), and the **app** — it explains itself to both
  audiences.
- Present pages render under `folio.aweb.ai`; **noindex** (these are private
  capability links — an investor pitch must never be googleable).
- aweb.ai links to `folio.aweb.ai` as a hub; `folio` builds its own authority.

### 6. Editable present links (human edit)

An editable link opens one document's editor. The opener expires within 300
seconds and is consumed once; an established editing session has **no idle
or maximum lifetime**, including while its tab is hidden.

- **Mint** (cert-auth): `POST /v1/present {slug, editable: true, ttl_seconds?}`
  keeps its existing parameters and response shape. The response `token` is a
  random public link id used for revoke. The URL is
  `/present/edit/<id>#k=<opener>`: id is 16 random bytes in 22 unpadded
  base64url characters; the opener is 32 random bytes in 43 such characters.
  Only its SHA-256 is stored. Read-only URLs and snapshots remain unchanged.
- **Open**: GET serves a nonce-CSP editor shell without content or side effects.
  Its script removes the fragment from history before storage or requests, then
  POSTs the opener to the shell URL's `/session`. Atomic database-clock
  consumption and session creation admit one concurrent winner. Prefetch and
  link-scanner GETs do not consume the opener. A spent/expired opener refuses.
- **Session**: the exchange returns one 256-bit secret, stored only as SHA-256
  in the database. The page keeps it in memory and
  `sessionStorage['folio.editSession:<id>']` for tab reloads. It travels only in
  `X-Folio-Edit-Session` on `/state`, `/preview` and `/edit`, never in the URL,
  cookies, localStorage or logs. Reload resumes the session without reusing the
  opener. A duplicated tab may share that session; version CAS still applies.
- **Authority**: every session request joins its link and document, checks
  revocation/deletion and the matching document id, and checks the minter's
  stored certificate/team key against current cached AWID membership. Membership
  loss or certificate replacement ends the session like revocation. AWID outage
  returns retryable 503 and authorizes nothing. Network checks precede database
  locks; the bounded membership proof is checked locally after locking.
- **Save** remains append-only with `body` and `base_version`; a stale version
  receives 409 with current body/version. There is no silent overwrite or
  automatic save retry. Stored minter attribution and optional editor-name
  metadata are unchanged by the session transport.
- **Live refresh** polls the authorized session state every four seconds while
  visible, with no overlapping reads and an immediate check on visibility return.
  A clean buffer follows the newest saved version and sanitized preview. A dirty
  buffer keeps text, focus and selection and offers an explicit confirmed latest
  load. Preview always uses the existing sanitized server renderer.
- **End**: revoke still addresses the original public link id after consumption.
  Document deletion also ends sessions. The editor keeps an unsaved buffer and
  copy/reopen recovery on refusal; a clean buffer shows unavailable guidance
  without claiming unsaved text. Closing the tab discards its sessionStorage.

The manifest bytes are unchanged. Moving read-only link tokens to fragments is
separate work, and no legacy editable-token authority path remains.

## Authority & privacy

- Same as atext: AWID authoritative for identity; cert-auth; team isolation is
  a hard invariant; capability tokens are the only public authority.
- All user content (documents, media, present pages) is **noindex** and behind
  opaque tokens. No public listing or feed of documents.

## Deployment

- Subdomain `folio.aweb.ai` (app + present pages + landing).
- Container server (atext spine + media integration) on the same Render/Neon
  shape as atext, plus **Cloudflare Stream** for video and **Cloudflare R2 /
  Images** for images. `PUBLIC_ORIGIN` = the `folio.aweb.ai` API origin
  (the v2 `aud`).
- **Private repo, seeded from atext** (already done: `awebai/folio`, seeded
  from `awebai/atext` — not a GitHub fork, which can't be private).

## Non-goals (v1)

- No human accounts / passwords / OAuth — same agent-first stance as atext.
- No real-time character-level co-editing (CRDT/OT/websockets). Editable links
  (section 6) use append-only versions with optimistic, version-based concurrency
  (409-on-stale) and latest-version polling — the wiki/Git model, not live
  simultaneous typing.
- No public document discovery / feed — capability-link only.
- No arbitrary HTML/JS from teams on the public page — all inputs declarative +
  validated; the only JS is our fixed, nonce-gated fullscreen control.
- No billing in v1 (atext has the caps/Stripe pattern to adopt later).

## Open questions

1. **Spine sharing** — fork/copy now (fast, but the auth spine can drift) vs
   extract the atext spine as a shared dependency (safer, more upfront work).
   v1: fork, under the auth-spine-tracks-atext rule; revisit extraction.
2. **Video infra** — confirmed direction Cloudflare Stream (+ R2/Images);
   settle transcoding presets, size/length limits, signed-URL TTLs, cost.
3. **`aw` plugin verbs** — deferred; implement via the external-binary plugin plan in [`docs/aw-plugin-brief.md`](aw-plugin-brief.md), not via a private-repo Python console script.
4. **Present-link controls** — view analytics, "who opened it", single-view or
   first-view expiry — product candidates, deferred.
5. **Billing** — adopt atext's caps/Stripe pattern; when?

## Milestones (sketch)

- **M1 — seed & rebrand:** repo seeded from atext (done); rebrand atext→folio
  (package, README, identifiers, public origin); skeleton deploy at
  `folio.aweb.ai`.
- **M2 — images:** upload + embed + themed render (assets generalized).
- **M3 — layout:** document/presentation modes + measure + fullscreen +
  print + contrast.
- **M4 — video:** Cloudflare Stream integration — upload/transcode/embed/render
  + signed playback.
- **M5 — current usage + deferred plugin plan:** generic `aw id request --team-auth` is the current documented path; `aw folio` verbs move to the future aw-plugin track in [`docs/aw-plugin-brief.md`](aw-plugin-brief.md).
- **M6 — templates:** built-in declarative layouts.
- **M7 — surfaces:** human + agent landing, llms.txt/skills, `noindex`,
  aweb.ai hub link.
- **M8 — editable links:** edit-capable present tokens (`editable:true`), the
  editor surface (first-party nonce-gated JS, edit pages only), append-only edit
  API with optimistic version-based concurrency (409-on-stale) + `/state` polling,
  optional editor-name attribution, TTL/revoke. Independent of M3/M4 — builds on
  the present-link + document spine.
