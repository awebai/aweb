---
type: Decision
title: Media is served only under the capability that shows it
description: When a capability (bearer link, edit session, team-auth read) shows a page with embedded media, the bytes are served only under that same capability and the same installation-fenced check as the page, never by an id-only public route; the reference in content stays a reference that the renderer rewrites per viewer, and every byte response is no-store.
tags: [decision, security, authorization, naapps, media, capability-links]
timestamp: 2026-11-18
---

Ruled for Folio images on 2026-11-18: the security reviewer ruled an id-only
public asset route a defect (R16 finding 11.12), and the naapps coordinator
approved the design below (task aweb-adje.16.1). The rule is stated generally
because the same first implementation is natural for media in any naapp
(Folio, pages, Library).

# Decision

- **The bytes follow the capability.** Media embedded in a page reached through
  a capability (a bearer link, an edit session, a signed team-auth read) is
  served only under that same capability, through the same installation-fenced
  check as the page. Revocation, expiry and uninstall therefore reach the bytes
  at the same moment they reach the page.
- **A content reference is not an address.** The reference written in content
  (in Folio, `/assets/<uuid>` in Markdown) stays a reference. The renderer
  rewrites it per viewer to a URL scoped to the capability that viewer holds.
  Nothing serves the bare reference.
- **No caching of bytes.** Every media byte response is `no-store`.
- **Header-only sessions keep their header.** A session whose credential
  travels only in a request header fetches each media item with that header and
  shows it through a `blob:` URL. It parses the rendered HTML in an inert
  template first, so no media request leaves the page without the header.

# Rejected

- **An id-only public media route, "because the id is unguessable".**
  Revocation, expiry and uninstall never reach the bytes, and every URL ever
  shown stays live. It is also the shape that passes every test that checks only
  the page, which is why it gets built first.
- **Short-lived signed media URLs** (the pattern used for video). Revocation
  lags by the URL lifetime.
- **A second, URL-borne per-session media key, or a cookie, for a header-only
  session.** Either adds a new credential: in the DOM and access logs, or as
  ambient browser state in a deliberately cookie-free session.

# Relationship to other knowledge

This extends [a projection governs the whole query and the whole result](/aweb-expert/lessons/a-projection-governs-the-whole-query-and-result.md):
the complete returned shape of a capability is part of authorization, and that
shape includes the media the returned page embeds. A media fetch is a request
like any other under [one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md):
it is evaluated as the capability that shows it, not as an anonymous id lookup.

# Status

As of 2026-11-18 the Folio implementation is under review on an assignment
branch and has not landed; its gate runs were still pending. The Folio URL
shapes are recorded with the code in the Folio source-of-truth document
(`naapp/folio/docs/sot.md`, Images), not here.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-18; notes/folio-image-url-shape.md. Design approval by the naapps
coordinator (266b5022); the security reviewer's ruling relayed in 8c85ec00
(51df91df). Both are source-reported; the harvester did not read them.
