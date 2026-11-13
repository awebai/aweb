---
type: Decision
title: OATS-spawned children are key-only local identities that aw creates
description: An agent OATS spawns gets a did:key-only local identity created by aw (aw id create --local), the local parent/child exchange, admission by the deployment root, then aw id team install-cert and aw service init; a registered child was rejected, and aw, not OATS, writes the child's key.
tags: [decision, oats, identity, aw-cli, spawn]
timestamp: 2026-11-13
---

Accepted on 2026-11-13 by OATS's lead for the spawn integration, with the
operator's side agreeing, against OATS spec v4.3.2. The acceptance is
**source-reported**: it reached the aweb-expert seat as a relay from the OATS
expert (213f0fcb, relayed as 444103f5), and no harvester could read the
record. The aweb-expert seat had recommended registered children before this
decision. At the time of writing, `aw id create --local` and `aw id team
install-cert` are not on main.

# Decision

A spawned child's identity is set up in this order:

1. `aw id create --local`: a key-only (did:key) home.
2. The parent/child exchange (`aw id parent request`, run as the child).
3. Admission by the deployment root (`aw id team admit`, writing the
   certificate to a file the caller names).
4. `aw id team install-cert`: installs the admitted certificate.
5. `aw service init`.

Only the deployment root is registered, and it has no address.

# Why aw writes the key

aw owns the home layout and the rule that identity primitives belong to aw.
If OATS wrote the key itself, it would bypass both.

# What OATS asked of the two commands

- `create --local` is resumable. A home holding exactly a key-only identity
  returns `already_exists` with the same did:key. Anything else refuses with
  a code. It makes no registry call and claims no address or membership.
- `install-cert` accepts a local-scope certificate with no did:aw.
- The refusal codes are documented. OATS retries when the registry is
  unavailable. It treats a wrong signer, a key that is not current, a revoked
  certificate, a member mismatch or `certificate_conflict` as a failed
  exchange.
- The two commands stay separate, and each is resumable.

# Rejected

**A registered child (`--no-address`)**, which was the aweb-expert seat's
earlier recommendation:

- every spawn writes to the public registry, and every retire leaves a
  registered DID behind;
- it changes the issuance step of the OATS spec (C-3a), because a registered
  child needs registered issuance, not the local parent/child exchange;
- every team policy would need `registered_agent` in its subject kinds.

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/oats-spawned-children-are-key-only-local.md. The acceptance and its
relay are the source's report. On main, `aw id parent request` exists, while
`aw id create --local` and `install-cert` do not.
