---
type: Lesson
title: Unauthenticated input must not drive remote work
description: Order checks so cheap local verification and admission controls run before per-request remote lookups; a remote check moved earlier must not create exits that skip existing admission controls, and lookups driven by caller-chosen input cache their negative answers.
tags: [lesson, security, rate-limits, awid, review]
timestamp: 2026-10-21
---

Two review findings in October 2026, both caught in review before release.

- **A new exit ahead of an existing guard.** To avoid network work under a row
  lock, a remote verification step was moved earlier in a request path. Its
  refusals returned before an existing admission control had counted the
  attempt, and they revealed authority state before the caller's capability was
  checked. The test for that control used a callback that always succeeded, so
  it exercised only the neighbouring path.
- **A remote lookup before the cheap check.** A verifier queried the identity
  registry for each presented credential before checking the signature it
  could verify locally, and did not cache negative answers. Caller-chosen input
  could therefore spend a shared registry quota.

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
