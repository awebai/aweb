---
type: Decision
title: OSS and Cloud are separate teams with separate expertise
description: No hosted-aweb expertise in the OSS souls or their knowledge; the hosted application has its own team, sources, knowledge custody and deployment scope, and contributes to OSS through assignments or cross-team pull requests.
tags: [decision, boundary, oss, cloud, roster]
timestamp: 2026-09-21
---

Decided by the operator on 2026-09-21 while the aweb team moved to
expertise-based durable souls: "do not have any expertise on hosted aweb in
aweb-oss; we will need another team in aweb-cloud."

# Decision

- The OSS team's durable souls cover only what `docs/oss-boundary.md` places in
  the framework: public identity, team, federation, messaging, event, CLI and
  runtime-integration contracts, plus OSS direction and integration judgment.
- Hosted application, accounts, organisations, billing, dashboards, production
  operation, deployment procedures and their knowledge belong to a separate
  aweb-cloud team with its own deployment root, sources and private knowledge
  base. Nothing hosted is read from, written to or referenced as a locator by an
  OSS soul.
- Cloud contributions to OSS are OSS-team assignments or cross-team pull
  requests, reviewed like any other change. Common release knowledge may cite
  public OSS contracts; hosted procedures stay with Cloud.

# Rejected

- One shared knowledge base for both areas with separate owners: it coupled the
  teams' custody and made a hosted locator part of a public soul's declaration.
- Keeping hosted facts in OSS memory "because they are useful": they go stale
  against a deployment the OSS team does not operate and cannot verify.

# Consequences

- The former coordinator's hosted notes (release topology, mount-specific
  facts, dated deployment status) were handed to Cloud custody as evidence and
  are not part of this bundle.
- Isolation is physical in classic OATS: the hosted checkout lives under its own
  deployment root, because a team scope enumerates every child repository's
  souls regardless of nested configuration.
