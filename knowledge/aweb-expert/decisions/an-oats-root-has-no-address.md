---
type: Decision
title: An OATS deployment root is created without an address, and its creation is resumable
description: An OATS deployment root is created with aw id create --no-address, so its own key signs its did:aw mapping and no namespace controller key sits on deployment hosts; creation writes the key before registering, so a rerun resumes a partial run instead of minting a second root.
tags: [decision, aw, identity, oats, roots, did-aw]
timestamp: 2026-11-13
---

Decided on 2026-11-13 by the aweb-expert seat working on OATS owner acts,
with the OATS seat.

# Decision

- **An OATS root has no address.** `aw id create --no-address` mints a
  self-custodial key, registers that key's own did:aw mapping at the pinned
  registry, reads it back, and writes the identity home. The human
  assurance contract says why this is enough. An endorsement target needs no
  address: its new agent key signs its own DID-log mapping, and that gives no
  ancestry, address or team membership. The root's ID certificate then comes
  from the one live root endorsement.
- **`--json` carries `did_aw` and `did_key`.**
- **Creation is resumable.** aw writes the key (mode 0600) before it
  registers. A rerun on a home that holds that key without a confirmed
  registration resumes: it registers if needed, reads back, and finishes.
- **`identity_exists` refuses only a complete identity or a different one.**
  OATS setup treats a complete identity as "root already created".

# Why the order matters

If aw minted the key, registered it and only then wrote it, a run killed after
registration would leave a registered did:aw whose key nobody holds. The rerun
would then silently mint a second root.

# Rejected

- **Creating roots on the addressed path.** It looks simpler, because
  `aw id create` already takes `--domain` and `--name`. But claiming an
  address needs the namespace controller key and DNS verification on the
  machine. That would put the namespace controller key on every deployment
  host, and the protected design keeps that authority off workers.

# Status

Not yet built (2026-11-13). On main at f5fa94683, `aw id create` has no
`--no-address`; `--no-address` exists only for team joins. The contract text
is section 2 of `docs/human-assurance-contract.md` as frozen in 584d76c9, on
the branch `agents/aweb-protocol-expert-human-kind-human-status`.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/oats-root-has-no-address.md. The harvester read the contract's section 2
at 584d76c9 and checked `aw id create` on main. The decision records it cites
(aweb ca834e8f and 833af8aa, OATS 7404a78e and 799cb7f9) are message ids,
the source's report.
