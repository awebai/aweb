# Open-source repository boundary

This repository is the public, MIT-licensed home of the **aweb framework**. It
contains the reusable protocol, runtime, tooling, and conformance assets needed
to build, operate, and extend aweb-compatible systems.

## What belongs here

The framework includes:

- the aweb coordination server in `server/`;
- the `aw` CLI and Go libraries in `cli/go/`;
- the shared channel protocol and maintained integrations in `channel-core/`,
  `channel/`, and `pi-extension/`;
- the AWID identity and team registry in `awid/`;
- public conformance fixtures in `test-vectors/`;
- reusable skills and resource-pack assets; and
- public documentation and engineering sources of truth in `docs/`.

These surfaces belong together because they define interoperable framework
behavior. Protocol changes, implementations, test vectors, and their normative
documentation should remain reviewable against one another.

The `agents/` tree is also retained here by explicit maintainer decision. Its
team architecture, roles, souls, and deliberately curated instance content are
engineering assets used to develop the framework. This decision was recorded
on 2026-07-24 and may be revisited; until then, contributors should treat those
assets as part of this repository rather than moving them piecemeal.

## What belongs elsewhere

Applications and business-specific systems live in separate repositories and
consume the public framework contracts. In particular:

- AC is a private application and business repository;
- Library and the maintained blueprint catalogs are public repositories; and
- Folio is a separate application repository and may remain private.

An application being public does not make it part of the framework. Separate
repositories keep application release cadence, business logic, access policy,
and product-specific dependencies independent from the reusable core.

## `.aw/` state invariant

A real `.aw/` directory is local identity and workspace state, not source. It
may contain signing or encryption keys, certificates, team selections, routes,
and other machine- or identity-specific material. The repository-wide
`.gitignore` therefore excludes `.aw/` directories.

**Contributors must preserve this invariant:** real `.aw/` state is never
tracked. The only tracked `.aw/` paths are deliberate fixtures under
`test-vectors/`; those fixtures must be synthetic and contain no real key
material, tokens, identities, or other secrets. New tests that need an
`.aw/` layout must use sanitized fixture data under `test-vectors/`; they must
not weaken or bypass the repository ignore rule.
