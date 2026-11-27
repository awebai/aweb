---
type: Decision
title: Check a stored identity before adopting it; do not refuse adoption
description: When the server adopts a stored stable ID that the request did not claim, it first runs the same ID-tree status check the claimed path runs; refusing to adopt an unclaimed stored ID was rejected because it changes sender attribution for every claimless client, and never-enrolled and local identities keep working unchanged.
tags: [decision, security, identity, authorization, compatibility]
timestamp: 2026-11-27
---

Chosen on 2026-11-27 by the aweb-expert seat that fixed a security review
finding. The finding: on more than one request path the server adopted an
identity's stored stable ID (`did:aw`) as the principal when the request did
not claim it. Before adopting it, the server checked only that the signing key
still bound to that ID. A key-binding check shows that the key still binds. It
does not show that the ID is still in good standing in its ID tree. So an
enrolled ID that had been revoked, or whose root had been replaced, could
leave out its claim and keep acting as itself. One existing path, the
session-grant lane, already ran the tree check on the stored ID. The fix
applied that same pattern to the other paths. The review ACK was still
pending when this was harvested, and the fix was not yet on main. Path and
field names are therefore left out here, because this repository is public.

# Decision

- **Any path that adopts a stored stable ID runs the claimed path's ID-tree
  status check first, on the verified stored binding.** This covers a stored
  member-row ID, a team certificate that carries no member ID, and a request
  that is identified only by its key. Each case is checked exactly as if the
  request had claimed that ID.
- **Never-enrolled and local identities keep working.** A global identity
  that was never enrolled in an ID tree keeps its no-chain status. A local
  identity has no stored stable ID, so no tree read happens.
- **Consequences accepted.** A claimless global identity now pays the same
  cached enrolled-ID read as a claimed one. When the ID registry is
  unavailable it gets the same 503 that the claimed path already returned.

# Rejected

- **Never adopting a stored stable ID that the request did not claim.** This
  also closes the hole, but it changes sender attribution for every claimless
  client. A never-enrolled global identity would start sending as its
  `did:key` instead of its `did:aw`. That is a contract change for released
  clients, not a fix. See
  [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).
- **Keeping the key-binding check as sufficient.** It leaves revocation and
  root replacement open to anyone who omits the claim.

# How to apply

When writing or reviewing auth code, search for principal fallbacks of the
form "the claim, else the stored value". This includes certificate fields
that may be absent. For each one, require the status check that the claimed
twin applies, and test it with an omission case from a revoked or
root-replaced ID. That omission test is the elimination route. Fix by adding
the check, and keep the never-enrolled and local cases green.

# Relationship to other knowledge

This applies
[key authority history spans every path to the key](/aweb-protocol-expert/decisions/key-authority-history-spans-every-path.md)
to stable IDs: revocation is consulted on every path that can reach the ID,
not only on the path that names it. It keeps the single principal of
[one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md)
honest. The review craft for finding these paths, which is probing each
optional claim by omission, is proposed separately as the lesson "attack each
optional identity claim by omission".

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-sec-r1, 2026-11-27;
notes/stored-did-aw-adoption-needs-tree-check.md. The source reports a test
commit that was red on four omission cases and turned green at the fix
commit, and that reverting either lane's fix brings back exactly that lane's
failures. This is source-reported: the harvester did not run the tests, and
the review ACK was pending at harvest.
