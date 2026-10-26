---
type: Decision
title: One principal and one policy per request
description: Every request carries one immutable original principal through every transport and credential bridge, evaluated by one per-operation policy that defaults to deny, with an explicit intra-team role model, no credential substitution and audit emitted at the decision point; tenant repositories and row-level security wait for evidence.
tags: [decision, security, authorization, architecture, identity]
timestamp: 2026-10-20
---

The operator approved a security architecture programme on 2026-10-20 in the
form proposed by the second independent security review, choosing it over the
first audit's ordering and over a narrower plan limited to a principal object
and key separation. The OSS coordinator confirmed the approval on 2026-10-25.
This concept records the architectural decisions in that programme that apply
to the open framework; hosted specifics and the review findings behind it are
not recorded here.

# Decision

- **One immutable original principal.** A request is evaluated as the principal
  that authenticated it, across HTTP, MCP, dashboards and workers. A credential
  bridge carries the original credential class, subject, issuing tenant, scopes
  and delegation; no conversion may widen authority, so a scoped key never
  becomes indistinguishable from a member certificate or inherits its creator's
  memberships.
- **One per-operation policy, default deny.** Undeclared routes fail closed,
  enforced by a build guard rather than by review. Authentication success is
  never an early return around policy.
- **Roles and substitution.** The principal carries an explicit intra-team role
  model (owner, admin, member, agent), and one credential is never accepted in
  place of another class.
- **Audit at the decision point.** Audit is emitted from the same place the
  policy decides, so any action can be attributed afterwards.
- **Request-bound signatures everywhere.** Every client uses signatures that
  bind the request they authorize; older signing schemes are retired.

# Rejected

- **A blanket tenant-repository migration, and row-level security, as the next
  step.** Tenant isolation is designed in the keys of shared tables: every
  shared table is keyed by its tenant. A repository layer or row-level security
  comes only when a failure it would have stopped is shown. Row-level security
  is also a second authority layer to keep consistent and complicates
  schema-per-module migrations.
- **Starting service grants by splitting a read-only service credential.**
  Credential work is ordered by the authority a credential carries, highest
  first.
- **A principal object plus key separation alone.** It left out request-bound
  signing and complete audit, which the programme treats as part of the same
  design.

# Relationship to other knowledge

[Team certificates are controller-only](/aweb-protocol-expert/decisions/team-certificates-are-controller-only.md)
and [the signed request target is the external path](/aweb-protocol-expert/decisions/signed-request-target-is-the-external-path.md)
are protocol decisions inside this frame.

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-review-2` (note
`security-review-ruling-2026-10-20.md`) and seat `aweb-expert-security-audit`
(notes `preserve-original-principal-through-credential-bridges.md`,
`defer-rls-until-its-benefit-is-demonstrated.md`; security reviewer ruling
7cc13772). The operator's approval of the second review's programme is recorded
in the OSS coordinator's log for 2026-10-20 and was confirmed in f8d89364.
