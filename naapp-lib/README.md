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

The docs surface is pure standard library. Request-time runtime code (the
team-auth verifier, approvals, passkeys) lives under `aweb_naapp.runtime` and
needs the `runtime` extra: `aweb-naapp[runtime]`.

The egress guard, `aweb_naapp.egress`, is for naapps that call an external
service with their own credential. It needs only the `egress` extra,
`aweb-naapp[egress]`, and none of the runtime. It canonicalizes and matches
outbound URLs under the contracts in `docs/vectors/egress-url-v2.json` and
`docs/vectors/egress-address-v1.json`, resolves names itself and refuses any
denied address, and sends a request only to the destination it matches,
through one pinned, verified connection. Redirects come back as responses, no proxy is read from
the environment, and a failure is classed as not sent or of unknown outcome.
