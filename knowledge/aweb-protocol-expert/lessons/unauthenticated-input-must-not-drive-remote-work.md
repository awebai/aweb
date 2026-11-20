---
type: Lesson
title: Unauthenticated input must not drive remote work
description: Order checks so cheap local verification and admission controls run before per-request remote lookups; a remote check moved earlier must not create exits that skip existing admission controls, lookups driven by caller-chosen input cache their negative answers, and on an anonymous signed-act route state lookups wait until the act is authenticated.
tags: [lesson, security, rate-limits, awid, review, oracle]
timestamp: 2026-11-07
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

# State lookups are not local verification

"Local checks first" means stateless checks, not every check that avoids the
network. On an anonymous route that accepts a signed act, a cheap state lookup
(does the pending row, holder or nonce exist?) placed before the registry read
of the signing key is an existence oracle: a forged act gets `403` for an
absent row and reaches the registry for a present one, where an unavailable
registry answers `503`. Making every refusal before authentication a uniform
`403` does not help, because the difference shows up in a later stage's
failure mode. The ordering was proposed in review as cost hygiene and NACKed
for this oracle (aweb-acgh.16.38, 2026-11-07); it recurs on every anonymous
signed-artifact endpoint.

The order that passed review:

1. **Stateless:** body, parse, fields, audience, vocabulary, lifetime.
2. **Authentication:** the current key of the act's own `team_id`, then the
   signature, so any `503` depends only on input the caller chose.
3. **State, for an authenticated act only:** installation, nonce, row or
   holder, contact.

Prove it with pairs in the vectors: the same forged act with and without the
row, under each registry condition, must get equal results. The fix carries
such pairs in `docs/vectors/owner-act-delivery-v1.json` (branch commit
9283451be, ACKed by the independent reviewer and the security reviewer).

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-07; notes/anonymous-route-authenticate-before-state.md.

Related: [preserve capability boundaries through adapter changes](/coordinator/preserve-capability-boundaries-through-adapter-changes.md).

# Provenance

Harvested 2026-10-25 from seats `aweb-protocol-expert-pages-design` (note
`preflight-refusals-can-bypass-admission.md`; verify NACK 161df6ee) and
`aweb-protocol-expert-chat-session-fix` (security review e796bd74).
