---
type: Decision
title: Named addresses are shared; enumeration is publication
description: A person may choose a named address and give it out, and resolving that exact name is sharing; anonymous namespace listing or reverse lookup from an identifier to addresses is public disclosure, removed by migrating every consumer to authorized reads and then disabling anonymous enumeration for all addresses, with exact resolution kept. Direction and sequence accepted; nothing implemented or authorized to ship.
tags: [decision, identity, privacy, registry, addresses, humans, compatibility]
timestamp: 2026-11-14
---

The human clarified the privacy boundary on 2026-11-14; the OSS coordinator
relayed it to the source and then adopted the migration sequence below after
an independent inventory of callers. Both are **source-reported**: no
independently readable record exists.

**Status:** design direction and sequence only. No migration step is
implemented, released, or authorized to publish, release, or change registry
or DNS state.

# Decision

- **A named address is chosen sharing.** A person may pick a named address
  and give it to others. Resolving the exact name one was given is sharing,
  and exact-name resolution stays.
- **Enumeration is publication.** Anonymously listing a namespace's addresses,
  or reversing an opaque human identifier into its addresses, makes the
  mapping between a person and their names public. Open identity verification
  does not need an enumerable directory of personal handles.
- Personal names and contact details stay out of public human certificate and
  approval-provenance fields. An opaque identifier does not by itself make
  uses of it unlinkable.

# Sequence

1. Provide authorized reads that return the complete lists current consumers
   rely on.
2. Migrate every dependent caller to them.
3. Disable anonymous enumeration for **all** addresses, human or not, keeping
   exact resolution.

[Released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md)
binds step 3: removal waits until it is shown that no consumer still depends
on anonymous enumeration.

# Rejected

- **Rewriting people's chosen addresses into opaque handles**, or removing
  exact-name resolution. The privacy goal is to stop enumeration, not to take
  away a name someone chose to share.
- **An immediate filter that hides only human addresses from public
  enumeration.** It breaks current consumers that depend on complete lists,
  it needs to know whether each old record is human, which existing records
  cannot prove, and it would leave a permanent human-kind exception in a
  public interface.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-security-fixes,
2026-11-14; notes/human-address-sharing-not-enumeration.md. The proposal is
the source's explicit scope correction of its own earlier opaque-human-publication
proposal. Caller maps stay in the source's audit and are not recorded here.
