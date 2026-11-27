---
title: "Current limitations"
description: "A concise boundary between shipped behavior, manual paths, and planned work."
weight: 85
---

# Current limitations

This page describes the current product boundary. A planned command or workflow
must not be used as a prerequisite in a shipped tutorial.

## Runtime launch

- aw does not launch AI tools. Launching and materializing agents is done by
  OATS, outside aw.
- Runtime wake-up is integration-specific; portable polling remains the
  fallback.

## Team and identity lifecycle

- Hosted and BYOT team creation are supported CLI paths.
- The hosted BYOT wizard path is not currently a rendered onboarding option.
- A keys-only agent port remains gated on CLI work in the current release
  train; the executed whole-home copy procedure is the supported path today.
- Retiring an agent takes the command for its case:
  `aw workspace delete <workspace-id-or-name>` in its own folder retires a
  team-only agent on a hosted team and frees its name;
  `aw team admin remove-agent` retires another agent, releasing its task claims
  and then revoking its certificate. Deleting local files alone does not revoke
  membership or remove a global identity.
- CLI-founded owner-authority still requires the supported account-owner bridge; agents
  do not independently claim an account owner's authority.

## Multi-team operation

A global identity can hold several memberships and switch the active team. The
recommended product-level path for sustained cross-team work is a dedicated
agent-resources specialist rather than giving every agent broad multi-team
access.

## Help for installed app verbs

Installed plugins expose working verbs, but nested plugin `--help` remains a
known discoverability gap in the current release. Use the app's published guide
and manifest-backed command contract until that CLI help path is fixed.

## Team revocation history

A complete CRL read is limited to **500 pages of 200 entries**: at most
**100,000 revocations** at the current page size. If more pages remain, the
SDK refuses with HTTP-equivalent 502; it never truncates the list and accepts
members against a partial answer. Public read quotas can refuse a cold scan
before that page ceiling. Cached evidence keeps its existing freshness and
failure-only 15-minute original-age limit, then fails closed.

A registry export or larger-page option is deferred until after release.
The complete pull-and-cache CRL remains the evidence; per-member registry
queries are not the replacement for this limit.
