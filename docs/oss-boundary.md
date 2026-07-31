# Open-source repository boundary

Status: **canonical maintainer policy**.

This repository is the public, MIT-licensed home of the aweb framework. It must
contain enough implementation, protocol authority, conformance evidence, and
operator guidance to build and understand the OSS system without another
checkout.

## What belongs here

Framework material belongs in aweb when it defines or verifies reusable,
interoperable behavior shared by aweb-compatible systems. That includes:

- the coordination server in `server/`;
- the `aw` CLI and Go libraries in `cli/go/`;
- the AWID identity and team registry in `awid/`;
- channel/event protocol code and maintained runtime integrations in
  `channel-core/`, `channel/`, and `pi-extension/`;
- public protocol contracts, conformance fixtures, generated references, and
  self-hosting guidance;
- reusable skills and resource-pack assets that operate only on public
  contracts; and
- tests that keep implementations and their public authority reviewable
  together.

A framework change should be understandable from this repository's source,
tests, and documentation. Public contracts must not require a separate
application checkout or unpublished implementation note to explain their
meaning.

The `agents/` tree is retained here by explicit maintainer decision. Its team
architecture, roles, profiles, and deliberately curated instance content are
engineering assets used to develop the framework. Contributors should treat
those assets as part of this repository rather than moving them piecemeal.

## What belongs with an application owner

Application and business implementation belongs with the system that owns it.
Examples include:

- human accounts, organizations, billing, and pricing policy;
- a particular hosted dashboard or onboarding implementation;
- customer-specific workflows and business rules;
- application databases, deployment procedures, provider credentials, and
  production operations;
- app-specific UI, retention policy, integrations, and release cadence.

An application may consume aweb's public identity, team-auth, messaging, event,
app-manifest, or conformance contracts without becoming part of the framework.
An application being public does not by itself make it framework code.

The durable rule is about ownership, not visibility:

- reusable protocol/framework behavior and its normative evidence live here;
- application/business behavior lives with its application owner;
- generic hosted-operator extension points may be documented here, but one
  operator's schema, paths, deployment, or internal repository may not govern
  the OSS contract.

## Dependency direction

Framework documentation may define the public interface an application uses.
It must not depend on an application's source tree, internal file path, database
schema, private runbook, or unpublished design document.

When extracting a reusable contract from an application-specific design:

1. state the interoperable behavior in aweb;
2. anchor it to public source, tests, or conformance vectors;
3. keep operator-specific implementation details with their owner; and
4. migrate every consumer before removing or relocating the old path.

## `.aw/` state invariant

A real `.aw/` directory is local identity and workspace state, not source. It
may contain signing or encryption keys, certificates, team selections, routes,
and other machine- or identity-specific material. The repository-wide
`.gitignore` therefore excludes `.aw/` directories.

**Contributors must preserve this invariant:** real `.aw/` state is never
tracked. The only tracked `.aw/` paths are deliberate fixtures under
`test-vectors/`; those fixtures must be synthetic and contain no real key
material, tokens, identities, or other secrets. New tests that need an `.aw/`
layout must use sanitized fixture data under `test-vectors/`; they must not
weaken or bypass the repository ignore rule.
