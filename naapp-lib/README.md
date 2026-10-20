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
needs the `runtime` extra: `aweb-naapp[runtime]`. Two parts the core server
shares import without it: the durable outbox, `aweb_naapp.outbox`
(`aweb-naapp[outbox]`), and the signing-key reader, `aweb_naapp.signing_key`
(`aweb-naapp[signing-key]`).

### App keys

An app names its signing keys by kid, as key files:
`<PREFIX>APP_KEY_FILES='{"<kid>": "/run/secrets/<file>"}'`. A key file holds the
32-byte Ed25519 seed as 64 hex characters, with one trailing newline allowed. It
must be a regular file of at most 1 KiB, and must not be group- or world-writable. The manifest
declares which kid signs which purpose, and the app does not start unless the
configured key is the declared one. An app with `<PREFIX>APP_EVENTS_ORIGIN` set
(https, or http on loopback) must hold its declared app-event key. That key may instead be given as
`<PREFIX>APP_EMIT_KEY_SEED_HEX` with `<PREFIX>APP_EMIT_KID`, a form that signs
app events only.

The egress guard, `aweb_naapp.egress`, is for naapps that call an external
service with their own credential. It needs only the `egress` extra,
`aweb-naapp[egress]`, and none of the runtime. It canonicalizes and matches
outbound URLs under the contracts in `docs/vectors/egress-url-v1.json` and
`docs/vectors/egress-address-v1.json`, resolves names itself and refuses any
denied address, and sends a request only to the destination it matches,
through one pinned, verified connection. Redirects come back as responses, no proxy is read from
the environment, and a failure is classed as not sent or of unknown outcome.
