---
type: Decision
title: A team key change carries the members' new certificates
description: AWID's team key rotation carries, for every kept member, the certificate being replaced, its replacement under the new key and the member's records, and applies them in the rotation's own transaction or not at all; a registry without the field refuses, with no per-member fallback. Per-member reissue with 429 backoff was rejected because the per-IP registration limit cannot finish a large team and a 429 between revoke and register strands a member. Accepted; on a review branch, not on main.
tags: [decision, awid, teams, keys, certificates, rotation]
timestamp: 2026-11-15
---

Chosen by a team ruling on 2026-11-15, relayed by the aweb coordinator, over
per-member calls with 429 backoff; the operator approved the "Membership and
key changes" section of the architecture "Human approval and key custody" the
same day. Both are source-reported, from mail not readable here.

# Decision

- When a team's key changes, the rotate request carries, for every member the
  owner keeps: the active certificate being replaced, its replacement under the
  new key (same member, alias, did:aw, address and scope), and the member's
  custody and person records for it.
- In the rotation's own locked transaction AWID revokes each old certificate,
  registers its replacement and records the records, or it changes nothing.
- A registry that does not know the field refuses the request, and
  `aw id team rotate-key` reports the refusal. It never falls back to
  per-member calls.
- Every key-change path, a hosted key holder included, sends the members with
  the key. Certificates not named are left untouched.
- A member's client picks up its new certificate when the server refuses the
  old one with `team_key_not_current`.

# Why

- AWID limits certificate registration to 30 per hour per IP. Per-member
  reissue cannot finish a team of more than 30 members within an hour.
- One active certificate per alias forces revoke-then-register for each member.
  A 429 between the two leaves a member revoked with nothing to replace it.
- One request avoids both, and is atomic with the key itself. Its size is
  bounded by the existing rotate body limit; there is no chunking.

# Rejected

- **Per-member reissue with 429 backoff:** cannot finish within the limit, and
  is unsafe partway.
- **A per-member fallback for registries without the field:** it would bring
  back both failures.

# Status

Implemented on the review branch `agents/aweb-protocol-expert-team-key-trust-adcl3`
(registry and CLI), under correctness review and not on main at harvest time
(main at 3bb8fefab). The source reports a 40-member test under production
rate limits passing with one rotate request.

Related: [the member check compares the accepted team key with the pin](/aweb-protocol-expert/decisions/the-member-check-compares-the-accepted-key-with-the-pin.md),
which ends membership under the old key, and
[a credential refresh repoints every reader before it makes a request](/aweb-protocol-expert/lessons/a-credential-refresh-repoints-every-reader-first.md),
the client side of picking up the new certificate.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-15; notes/team-key-change-is-one-registry-transaction.md. Rate limit checked in awid's ratelimit at the branch tip 56687aa6e.
