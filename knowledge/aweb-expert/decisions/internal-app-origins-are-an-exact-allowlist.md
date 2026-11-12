---
type: Decision
title: A self-hosted server installs internal apps only from an exact origin allowlist
description: A standalone server could not install apps on internal addresses, which the hosted product never exercised; the fix is an exact HTTPS origin allowlist (AWEB_APP_INTERNAL_ORIGINS) bounded by one network (AWEB_APP_INTERNAL_CIDR), not a network-wide switch or an injected test fetcher; own app ids and an operator install-admin owner grant are the other bring-up prerequisites found the same way.
tags: [decision, self-hosting, apps, egress, deployment]
timestamp: 2026-11-12
---

A self-hosted aweb bundle needs settings that the hosted product never
exercised, because its apps are public. Each one surfaced when a real compose
lane failed (owner-acts round-trip lane, runs 14 to 19, on a dedicated Linux
VM), not in review.

# Decision: internal app origins

The server built its manifest egress with internal destinations disabled and
had no operator setting. In a customer cluster, Secrets and Logs run on
internal addresses beside the server. So `aw plugin install <origin>` returned
502 `catalog_unavailable`, and the app never saw a request.

- **Chosen:** an exact allowlist. `AWEB_APP_INTERNAL_ORIGINS` is a JSON list of
  exact HTTPS origins, and `AWEB_APP_INTERNAL_CIDR` is the one network they
  must lie in. Both go through naapp-lib's existing internal-destination
  egress mechanism. Every other origin stays public. The settings themselves
  are documented in `docs/self-hosting-guide.md` with the change (e83bec520).
- **Rejected: a network-wide enable switch.** It would open manifest fetches
  to every internal address.
- **Rejected: injecting a test fetcher in the lane.** It would hide the very
  deployment gap the journey exists to find.

# The other bring-up prerequisites

- **Own app ids.** The naapp runtime refuses a hosted app id (for example
  `secrets`) on any origin but the hosted one. A customer deployment
  configures its own id, and owner acts name that id (run 14).
- **The operator's install-admin owner grant.** Standalone install authority
  comes only from the operator's local grant
  (`aweb install-admin grant --role owner`, documented in
  `docs/app-registry.md`). Team membership and certificate roles grant none.
  Bring-up must include the grant (run 16).

# How to apply

When a self-hosted or customer bundle is brought up, configure all three
before blaming the apps. When a lane fails on a deployment gap, fix the
deployment surface. Never paper over it in the lane. The elimination route
is the deployment's own bring-up docs and checks, so the bundle carries these
steps itself rather than relying on this note.

**Status (verified by the harvester 2026-11-12):** e83bec520 is on the
branches `agents/aweb-expert-deploy-team` and
`agents/aweb-expert-owner-acts-roundtrip`, not on main at 88fbf7b4f. The
install-admin grant is documented on main.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-12;
notes/self-hosted-bundle-prerequisites.md and
notes/server-refuses-internal-app-origins.md. The lane runs are the source's
report.
