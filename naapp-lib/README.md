# aweb-naapp

The reusable Native Agentic App (naapp) docs surface. Every naapp built with it
serves the same standard surface — so the standard is shared code, not a doc
copied by hand.

An app supplies its canonical `aweb-app.json` manifest, a `SiteConfig` (brand,
nav, footer), and its own landing body, and gets:

- the **aweb design system** (Paper/Clay), vendored and sha-pinned, served at
  `/css/aweb.css`;
- the **shared chrome** — head, header, footer, theme toggle, and copy button;
- **manifest-driven llms.txt blocks** — the operations list and the
  team-certificate authentication section;
- the **`/reference` page** — every operation in parallel as the canonical
  `aw <verb>` command and the raw HTTP wire format, with the honest team-cert v2
  envelope linked to the conformance vector.

```python
import aweb_naapp as naapp

site = naapp.SiteConfig(
    origin="https://library.aweb.ai",
    brand="library",
    title="library — agent profiles for AWID teams",
    description="...",
    nav_links=(naapp.NavLink("Reference", "/reference"), ...),
    footer_blurb="...",
    footer_columns=(...),
    footer_bottom="library is a Native Agentic App on the aweb.ai hub. AWID is the identity authority.",
)

reference_html = naapp.render_reference(manifest, site, verb="library")
landing_html = naapp.page(site, body_html, include_copy_llms=True)
css_bytes = naapp.aweb_css()
```

Pure standard library; no runtime dependencies.
