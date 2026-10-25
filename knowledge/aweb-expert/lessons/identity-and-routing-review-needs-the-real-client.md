---
type: Lesson
title: Identity and routing review needs the real client
description: When the server re-derives something the client signed (recipient, address, conversation), a green whole server suite is not review evidence; the real CLI journey and the federation end-to-end set must run, and the reviewer states which gate stages it did not cover.
tags: [lesson, review, identity, routing, federation, e2e]
timestamp: 2026-10-22
---

An identity-binding fix passed the whole server suite with nothing new against
main and received a code ACK. The coordinator's gate then failed in the
end-to-end journey: a continuation send was rejected because the
server-resolved recipient no longer matched the client-signed one. The next
head passed both the server suite and the journey, and failed again in
federation end-to-end tests with cross-server mail refused for a missing
route. Unit and HTTP tests construct their own signed payloads, so they never
exercise the real client's signing against the server's resolution.

# How to apply

- For a change where the server re-derives anything the client signed, the
  review evidence includes the real client in the loop, across servers.
- The coordinator's minimum reviewer set for identity or routing changes
  (2026-10-22): the whole server suite compared with main,
  `test-federation-authority-mutations`, `test-federation-harness`,
  `test-e2e`, `test-federation-e2e`, `test-a2a-gateway-e2e`, `cli-e2e` and
  `e2e-naapp`. The full gate is the candidate suite. Where whole suites run
  only in coordinator trains, the reviewer runs focused targets and names the
  gate stages it did not cover.
- An unverified raw `did:aw` claim never reaches routing or policy. An agent
  row's `did_aw` or address is a claim until it is bound to a verified key;
  routing, recipient identity and inbound policy use the verified projection,
  and a missing policy key refuses. When reviewing such a change, find every
  construction of the recipient shape (mail, chat, MCP, REST), not only the
  edited path; repeated sibling-path misses are how this class of fix fails.

Related: [verify identity selection at every process boundary](/coordinator/verify-identity-selection-at-every-boundary.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-review-2` (notes
`review-evidence-needs-e2e-journey.md` and
`raw-did-aw-claim-never-reaches-policy.md`; coordinator ea899039 and
8219f6ba, security reviewer d952ad5e). The OSS coordinator confirmed in
f8d89364 that the underlying fixes are released and the generic rule may be
published without attack detail.
