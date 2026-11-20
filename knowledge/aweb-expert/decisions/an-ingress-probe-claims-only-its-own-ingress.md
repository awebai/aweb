---
type: Decision
title: An ingress probe claims refusal only for the deployment's own ingress
description: A team deployment declares each probe route local (log-witnessed, with forbidden and no-SNI probes) or external (registry only, default external; one verified-TLS matched 200 per address and no refusal claim), and a declaration that does not match the deployment is refused, never converted.
tags: [decision, deployment, ingress, registry, proof]
timestamp: 2026-11-13
---

Decided on 2026-11-13 under task aweb-acwd.24.10, while wiring the team
deployment bundle's admission proof. The bundle's default `registryUrl` is the
public registry, which the deployment does not run. The OATS ingress probe
required every route's backend log and sent forbidden requests, expecting a
421, to every route's addresses. For a third party's front that means
requiring a log the deployment cannot read and claiming a refusal that is not
the deployment's property.

# Decision

- Each probe route is declared. A **local** route is witnessed in its backend
  log and gets the forbidden and no-SNI probes. An **external** route gets one
  verified-TLS matched 200 per address and protocol, no coverage, forbidden or
  no-SNI probe, and its result says it is a positive control only, with no
  refusal or non-delivery claim.
- Only the registry may be external: `team.registryRoute: local | external`,
  default external, because the default `registryUrl` is the public registry.
  aweb, Secrets, Logs and the signer stay local, so the human-Host refusal
  under the signer's SNI is always proved over the real TLS ingress.
- A declaration that does not match the deployment is refused, never
  converted, in both directions:
  - external is refused when a `registry` service exists (the message names
    `team.registryRoute: local`) or when any registry address is the
    deployment's own;
  - local is refused unless the registry service exists and every registry
    address is in the declared private ingress, so a local declaration never
    reaches the public origin.

# Rejected

- Probing the third party's refusal: it is not a property of this deployment,
  and it sends junk requests to someone else's front.
- Inferring the mode from whether a `registry` service exists: a missing local
  service would silently become external, and the proof would claim less than
  the operator meant without saying so.

# Consequences

A future backend that the deployment does not run is added as a declared
external route with a positive control only; it does not reopen the probe's
refusal contract and is never probed for refusal.

# Status

As of 2026-11-13 the bundle side is on the task branch (head 0e0b93705), with
teamctl wiring tests that fail on main's code with the reported refusal and
pass after. The OATS probe side was not yet implemented.

# Acceptance

Source-reported: the contract (narrowed to the registry only) was agreed with
the OATS image owner in message bde5e029; the external default was agreed by
the aweb coordinator in 44141608 and by product in bec536f0.

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13; notes/ingress-probe-claims-only-own-ingress.md.
