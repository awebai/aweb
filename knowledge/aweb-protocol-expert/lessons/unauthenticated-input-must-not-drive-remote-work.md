---
type: Lesson
title: Unauthenticated input must not drive remote work
description: Order checks so cheap local verification and admission controls run before per-request remote lookups; moving a remote check earlier can create exits that skip the rate limit, and uncached remote lookups keyed by caller-chosen ids let anyone exhaust a shared registry quota.
tags: [lesson, security, rate-limits, awid, review]
timestamp: 2026-10-21
---

Two findings from independent reviews in October 2026.

- **A preflight that bypassed admission.** To avoid network work under a row
  lock, remote membership verification was moved ahead of the lifecycle
  transaction, and so ahead of an existing committed per-client attempt
  counter. Refusals in the new preflight never reached the counter: a caller
  with any public link id could keep triggering registry calls without ever
  reaching the rate limit, and refusals revealed authority state before
  possession of the capability was checked. The flood test used a callback that
  always succeeded, so it exercised the neighbouring path.
- **Remote lookups before the cheap check.** A certificate verifier looked up
  each certificate's status in the identity registry before checking the team
  signature, with uncached not-found results. Random certificate ids, or more
  than sixty certificates a minute, could exhaust the registry rate limit and
  refuse every member of a self-hosted server.

# How to apply

- Verify what can be verified locally (the signature against the cached team
  key, possession of the capability) before any per-request remote lookup;
  cache negative results and bound the caches.
- When a refactor adds an earlier exit, ask which existing guards each new exit
  skips.
- Test matrices for such a refactor include failures before and after each
  admission boundary, and a successful neighbouring request to catch double
  charging.
- In the same review: renewal copies fields only from the verified old
  certificate, never from unsigned registry rows, and policy is verified
  against the controller or team key, not a key carried in the same response.

Related: [preserve capability boundaries through adapter changes](/coordinator/preserve-capability-boundaries-through-adapter-changes.md).

# Provenance

Harvested 2026-10-25 from seats `aweb-protocol-expert-pages-design` (note
`preflight-refusals-can-bypass-admission.md`; verify NACK 161df6ee) and
`aweb-protocol-expert-chat-session-fix` (security review e796bd74).
