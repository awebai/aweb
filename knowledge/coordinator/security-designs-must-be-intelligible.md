---
type: Decision
title: Security designs must be intelligible
description: A security design starts from the existing authority mechanisms and adds a credential type, distinction or corner-case restriction only for a concrete need those mechanisms do not meet; simplifying never drops requested scope.
timestamp: 2026-11-10
---

Directed by the operator in a coordinator session on 2026-11-10: avoid more
complexity than the problem needs, do not go overboard with corner cases, and
keep security intelligible, because a secure system has to be one people can
understand. The acceptance is source-reported (the coordinator's report of a
session instruction), not a public record.

The risk it addresses: an exploratory security question raised in review can
turn, through the coordinator, into an implementation requirement. The
coordinator has to tell a real, required boundary apart from a distinction
invented during review.

## Decision

- Route a security design from the ordinary case first: the actors, their
  ordinary credentials, the authority those credentials actually carry,
  revocation, and the operator's actions.
- Reuse existing authority mechanisms. A new credential kind, a new
  distinction between actors or an exceptional restriction needs a concrete
  unmet requirement, named; hypothetical completeness is not one.
- Meaningful checks on the ordinary path, and refusal checks, stay required.
  Intelligibility removes speculative machinery, not the controls that guard
  what the design does.

## Relation to scope

This refines how [scope belongs to the operator](scope-belongs-to-the-operator.md)
is applied; it does not supersede it. Simplification keeps the requested
outcome. It does not authorise silently dropping required behaviour, cutting
a requested feature, or ignoring an established defect; those remain the
operator's call.

## Provenance

Evidence: OKF proposal from coordinator/servers, 2026-11-10;
notes/intelligible-security.md.
