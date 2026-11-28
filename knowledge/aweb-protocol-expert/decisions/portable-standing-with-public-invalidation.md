---
type: Decision
title: Portable standing and public invalidation have different jobs
description: Ordinary standing is portable across verifiers and scoped only to its exact facts, while the holder's request signature carries audience and action; one mandatory public feed per registry carries invalidations under random issuer-scoped dependency-version handles, never under lookup identifiers; an operation that creates authority needs fresh evidence for its exact request and consumes it once. 30-minute standing and a 30-second applied-feed bound. Operator-ruled; not implemented.
tags: [decision, awid, standing, revocation, invalidation, privacy, scale]
timestamp: 2026-11-28
---

Ruled by the operator on 2026-11-28 for the million-agent architecture
(task aweb-aeal). **Acceptance: source-reported**: the OSS coordinator relayed
the ruling in coordination mail 7127dd02, which the harvester cannot read. It
followed the source's lifetime comparison (5ac6c2dc) and its review of the
public feed against private-team reads (5f39ec1b).

**Status:** ruled architecture only. Nothing is implemented, benchmarked or
released. The ruling calls for an OSS implementation, with cutover first at
the pilot.

# Decision

- **Ordinary standing is portable.** One signed standing observation is
  reusable by every verifier and is scoped to its exact facts. It carries no
  verifier audience and no action. The holder's request signature already
  authenticates the holder to the audience and the action, and stays
  responsible for them.
- **Ordinary standing lives 30 minutes.**
- **One mandatory public invalidation feed per registry.** Verifiers apply it
  as the fast common refusal path, with a 30-second bound on an applied
  invalidation. Reading the feed grants no visibility into private rosters.
- **Feed entries carry only random handles.** Each handle is issuer-scoped and
  names one dependency version. A feed entry never carries the identifiers
  that other APIs use for lookup.
- **Creating authority needs exact-request, one-use evidence.** An operation
  that creates authority needs fresh evidence for its exact request, and it
  consumes that evidence once. Reusable standing never gates such an
  operation.
- **Grants keep their standing at the service that owns them.**
- **Accepted disclosure:** aggregate counts and timing on the feed are left
  unpadded.

# Why

- **Per-audience standing scales with the audiences.** If audience or action
  went into reusable standing, the issuer would have to sign once per verifier
  audience. That makes issuer load grow with the number of verifiers, which
  this architecture exists to stop. Keep these dimensions in the request
  signature when a future change proposes adding them to standing.
- **Expiry alone ties refresh load to the removal deadline.** With removal
  bounded only by standing lifetime, a small removal bound forces frequent
  re-signing in steady state. The feed gives a short removal bound while
  standing lives 30 minutes.
- **Lookup identifiers in the feed would publish a join key.** AWID's
  certificate status lookup needs the domain, the team and the certificate ID
  together, and every miss returns the same 404. So a reader learns nothing
  without already knowing the full key. A feed of certificate IDs would hand
  every reader part of that key and a history of changes. Random handles let a
  verifier that holds the standing still match its entry, without publishing
  the key.
- **A raw certificate UUID is the wrong invalidation key anyway.** The
  registry makes a certificate ID unique only within its team
  (`UNIQUE (team_uuid, certificate_id)` on `team_certificates`), not across
  the issuer.

# Lesson for other feeds

When an anonymous exact lookup already exists for some facts, do not assume
that publishing a feed of the same facts discloses nothing new. First check
which identifiers and associations the feed lets a new reader discover.
Identifiers that look opaque can still be enumerable or joinable, or unique
only within a smaller authority than the feed. Issuer-generated match handles
per version keep offline invalidation working. Counts, timing, and what an
earlier holder of the proof can infer are separate disclosures, to be decided
on their own. The same check applies to certificate and key status, audit
streams, change feeds and caches whose privacy depends on knowing a lookup
key.

# Kept separate

Standing freshness is not credential lifetime. Certificate and grant expiry
stays optional team policy under
[credential lifetime is optional team policy](/aweb-protocol-expert/decisions/credential-lifetime-is-optional-team-policy.md),
which this decision does not supersede. A 30-minute standing observation says
how recent the verifier's evidence is. It does not say when a credential
ends. Application-level grant decisions are a third, separate thing.

# Open

- Verifier behaviour when the feed is lost or unreachable.
- A lighter verifier profile.
- Implementation order.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-coordination,
2026-11-28; notes/portable-standing-with-public-invalidation.md and
notes/point-read-publicity-does-not-authorise-enumeration.md. The second note
was a candidate lesson about the feed design, written before the ruling. It is
recorded here as the rationale for handles and as a general lesson. The
harvester checked the per-team certificate ID uniqueness against
`awid/src/awid_service/migrations/001_registry.sql` at aweb main 9adbca101.
The status lookup's key and its single 404 are source-reported.
