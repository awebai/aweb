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

### 4. First-class `aw` CLI verbs

So agents stop hand-rolling `aw id request … --raw --body`:

```
aw folio create <slug> --title … --body-file …
aw folio version <slug> --body-file …
aw folio theme set … / aw folio theme logo <file>
aw folio upload <file>            # image/video -> asset id
aw folio show <slug> [--ttl 1d]   # mint + return (and optionally open) the link
aw folio revoke <token>
```

(Open: built-in subcommands vs a plugin/registry model — leaning plugin so a
service ships its endpoints and its verbs together, keeping the core CLI lean.)

### 5. Surfaces (human + agent)

- `folio.aweb.ai` hosts the **human landing/explanation**, the **agent docs**
  (llms.txt + skills), and the **app** — it explains itself to both
  audiences.
- Present pages render under `folio.aweb.ai`; **noindex** (these are private
  capability links — an investor pitch must never be googleable).
- aweb.ai links to `folio.aweb.ai` as a hub; `folio` builds its own authority.

### 6. Editable present links (human edit)

An agent can mint an **editable** present link so its human can edit the document
— a write-capable capability link, distinct from the read-only present link.

- **Mint** (cert-auth): `POST /v1/present {slug, editable: true, ttl_seconds?}` →
  an edit-capable token. Read links omit `editable`. The capability lives in the
  token (server-authoritative); a read token cannot be escalated to edit via a URL
  arg.
- **Surface**: `GET /present/<token>` renders the **editor** if the token is
  edit-capable (with a view/preview toggle), else the read-only rendered page.
  Same URL, capability-driven.
- **Editing is append-only.** A save appends a new document version (the spine is
  append-only) — history is preserved; an edit can never destroy prior versions.
- **Concurrency — optimistic, version-based (NOT real-time co-editing).** The
  editor loads with the current `version_number`. On save
  (`POST /present/<token>/edit {body, base_version}`) the server requires
  `base_version == latest`; if stale → **409**, returning the latest body+version
  for the human to reconcile; else it appends and returns the new version. No
  silent overwrite.
- **Seeing the latest** — the editor polls `GET /present/<token>/state` (latest
  version_number) every few seconds; a newer version surfaces a "reload" prompt
  (warned if there are unsaved edits). Several humans on several machines each edit
  via their own link, save deliberately, and all converge on the latest version.
- **Attribution** — the editor optionally captures a display name ("editing as
  ___"); the appended version records it as a human-via-link edit. No login or
  identity — just a label, consistent with the no-accounts stance.
- **Editor UI** — a minimal first-party editor (markdown textarea + live preview +
  Save + conflict/refresh), served as our own nonce-gated JS **only on
  edit-capable pages**; read pages stay minimal. The edit API enforces the token
  capability server-side; never trust the client.
- **Trust + limits** — an edit token is scoped write to ONE document, agent-minted
  (the agent explicitly allows its human to edit), TTL-bound, revocable. Rendered
  content stays sanitized. Edit rate-limiting is a follow-up.

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
3. **`aw` verbs** — built-in vs plugin/registry.
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
- **M5 — CLI:** `aw folio` verbs.
- **M6 — templates:** built-in declarative layouts.
- **M7 — surfaces:** human + agent landing, llms.txt/skills, `noindex`,
  aweb.ai hub link.
- **M8 — editable links:** edit-capable present tokens (`editable:true`), the
  editor surface (first-party nonce-gated JS, edit pages only), append-only edit
  API with optimistic version-based concurrency (409-on-stale) + `/state` polling,
  optional editor-name attribution, TTL/revoke. Independent of M3/M4 — builds on
  the present-link + document spine.
