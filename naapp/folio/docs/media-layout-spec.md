# folio media layout primitives — implementation spec

> Implemented as part of **M3 (layout)**, in `src/folio/presentation.py`. Interacts
> with M2 (images) and M4 (video). HARD RULE: everything on the public present page
> is declarative data we render server-side — the agent picks from a FIXED,
> ALLOWLISTED vocabulary mapped to fixed server-controlled CSS classes; never
> arbitrary HTML/CSS/float/style.
>
> **VIDEO SUPERSEDED BY M4.** The `:::video` directive and its agent-supplied
> `cloudflarestream.com/.../iframe` URL described below were NOT implemented. M4
> shipped a stronger model: video is an uploaded asset referenced like an image
> (`![alt](/assets/<video-uuid>)`); the server resolves it to a Cloudflare Stream
> playback URL and injects a fixed, sandboxed `<figure class="folio-video"><iframe
> sandbox=…></iframe></figure>` **after** nh3. `iframe` is deliberately **not** in
> the nh3 allowlist, so callers can never author an iframe or supply a stream URL.
> See `_replace_video_markdown` / `_video_iframe_html` in `presentation.py`. M3
> implements only the **image** vocabulary (`:::media`, `:::gallery`, bare-image
> auto-wrap); the video parts below are retained for history only.

## A. Vocabulary

**Placement** (5): `block` (default, centered in column) · `wrap-left` / `wrap-right`
(float, text flows; images only) · `full-width` (spans content column) ·
`full-bleed` (breaks past the readable column toward the edges; best in
presentation mode).

**Size** (applies to `block` / `wrap-*` only; `full-width`/`full-bleed` ignore it):
`w-quarter` · `w-third` · `w-half` · `w-two-thirds`. (Use word class names — NOT
`w-1/2` — so CSS selectors need no slash-escaping; the preprocessor controls the
emitted class regardless of what the agent typed.)

**Gallery**: `gallery-2` · `gallery-3` (equal-width grid, reflows).

**Caption + alt are SEPARATE fields** (a11y): `alt` = functional screen-reader
description on `<img>`; `caption` = visible `<figcaption>` (optional). Do not derive
one from the other.

**Video**: accepts only `full-width` or `full-bleed` (wrap/size silently fall back
to `full-width`); 16:9; poster required; the Cloudflare Stream iframe is the media
element.

## B. Authoring syntax — fenced directive block

Parsed by a `_preprocess_media(body) -> str` step that runs BEFORE
`markdown.markdown()` and emits allowlisted `<figure>` HTML.

```
:::media
src: /assets/550e8400-e29b-41d4-a716-446655440000
alt: Line graph of weekly active users rising 12k->17k, Jan-Mar 2026
placement: wrap-right
size: w-third
caption: WAU growth, Q1 2026
:::

:::video
src: https://customer-abc.cloudflarestream.com/STREAM_VIDEO_ID/iframe
poster: /assets/<uuid>
placement: full-width
caption: Product walkthrough — 3 min
:::

:::gallery
placement: gallery-2
- /assets/uuid-1 "First image caption"
- /assets/uuid-2 "Second"
:::
```

**Parse + allowlist logic** (drop-silently on anything invalid):
1. `src` validated: images against `^/assets/<uuid>$`; video against
   `^https://[a-z0-9-]+\.cloudflarestream\.com/[a-z0-9]+/iframe$`. Invalid → block dropped.
2. `placement` ∈ allowlist, else default (`block` for image, `full-width` for video).
3. video placement not in {full-width, full-bleed} → falls back to full-width.
4. `size` ∈ allowlist, ignored for full-width/full-bleed.
5. `alt` and `caption` HTML-escaped (no tags).
6. Emit fixed `<figure class="folio-media folio-<placement> [folio-<size>]">…</figure>`.
   Track a flag to add `fetchpriority="high"` to the FIRST media block (LCP);
   all images get `loading="lazy"`.

**Bare images default**: a plain `![alt](/assets/<uuid>)` (no directive) is
auto-wrapped by the preprocessor into `folio-full-width` (caption from alt only if
you choose; prefer no caption for bare images). Non-asset `img` src stays as-is and
nh3 strips it.

**nh3 additions (as shipped)** — `_ALLOWED_TAGS` += `figure, figcaption, div`
(for image figures + gallery grid); **`iframe` is NOT added** — M4 injects its
trusted video iframe after sanitization, so callers can never author one.
`_ALLOWED_ATTRIBUTES`: `figure:{class}`, `div:{class}`,
`img:{src,alt,title,class,loading,width,height,fetchpriority}`. The img-src allowlist
from M2 still applies (our-origin /assets/{uuid}, team-owned). The `attribute_filter`
also strips any `class` token that is not `folio-*`, so classes carry no arbitrary
styling even when authored in raw HTML.

## C. CSS (essentials)

```css
.folio-media { margin: 1.5em 0; }
.folio-img { display:block; width:100%; height:auto; border-radius:6px; }
figcaption { font-size:.875em; color:var(--muted); margin-top:.5em; line-height:1.4; }

/* block + size: constrain + center */
.folio-block.folio-w-half { max-width:50%; margin-inline:auto; }   /* +quarter/third/two-thirds */

/* wrap/float (default width third if no size) */
.folio-wrap-left  { float:left;  width:33.33%; margin:.25em 1.5em 1em 0;  clear:left; }
.folio-wrap-right { float:right; width:33.33%; margin:.25em 0 1em 1.5em; clear:right; }
.folio-wrap-left.folio-w-half, .folio-wrap-right.folio-w-half { width:50%; } /* etc. */
/* clear floats at section boundaries */
.document-body p::after, .document-body section::after { content:""; display:table; clear:both; }

/* full-width / full-bleed */
.surface { --surface-pad: clamp(24px,5vw,56px); padding:var(--surface-pad); }
.folio-full-width .folio-img { max-height:80vh; object-fit:contain; }
.folio-full-bleed {
  margin-inline: calc(-1 * var(--surface-pad));
  width: calc(100% + 2 * var(--surface-pad)); max-width:none;
}
.folio-full-bleed .folio-img { border-radius:0; max-height:90vh; }
/* presentation mode: true viewport bleed (no surface card) */
.folio-layout-presentation .folio-full-bleed { margin-inline:calc((100% - 100vw)/2); width:100vw; }

/* video */
.folio-video-iframe { display:block; width:100%; aspect-ratio:16/9; border:none; border-radius:6px; }

/* gallery */
.folio-gallery-grid { display:grid; gap:.75em; }
.folio-gallery-2 .folio-gallery-grid { grid-template-columns:repeat(2,1fr); }
.folio-gallery-3 .folio-gallery-grid { grid-template-columns:repeat(3,1fr); }
.folio-gallery-item .folio-img { height:200px; object-fit:cover; border-radius:4px; }
```

Mark presentation mode with a `folio-layout-presentation` class on `<body>`/`<main>`.

## D. Responsive

- **≤768px**: `gallery-3` → 2-col; loosen block size caps.
- **≤480px**: `wrap-*` → block full-width (floats off); all size caps → full-width;
  galleries → 1-col; full-bleed/full-width stay.
- Wrap collapses at **480px** (at 768px the document column still fits a 1/3 float +
  ~400px of text).

## E. `@media print`

Reset floats → block, full-bleed → full-width (no 100vw overflow), drop gallery
`object-fit` height so images print whole.

## F. Agent guidance (for the docs/llms.txt)

- **full-width** = the safe default for screenshots/charts/photos.
- **wrap-*** only around paragraphs (not headings/lists/code), ≥3–4 lines of adjacent
  text, `w-third`/`w-quarter` for tight integration.
- **full-bleed** sparingly — one per major section; common in presentation, rare in
  document mode (it breaks the 65ch measure).
- **galleries**: don't mix portrait + landscape in a fixed-height grid (it crops).
- Always provide functional `alt`.

## G. Backlog (not v1)

Art-direction via `mobile-src` → `<picture>`; masonry for portrait galleries;
`max-image-bytes`/dimension limits surfaced to the agent.

## Test plan

Preprocessor tests: valid blocks emit expected HTML; invalid src dropped; invalid
placement falls back; video+wrap → full-width; gallery with bad uuids drops per item;
bare asset image auto-wraps to full-width; first media block gets fetchpriority.
Security: directive cannot emit a non-allowlisted img/iframe src or class; alt/caption
with tags are escaped; an `:::media` with an external/other-team/data: src renders nothing.
