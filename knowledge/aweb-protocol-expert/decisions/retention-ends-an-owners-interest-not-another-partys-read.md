---
type: Decision
title: Retention ends an owner's interest, not another party's read
description: A retention sweep ends only the sweeping owner's established interest in shared correspondence; a message stays while any party still retains it, unknown ownership retains it, and current identity-based shared visibility is preserved rather than replaced by a per-party read cutoff. Accepted by delegated ruling, not yet implemented.
tags: [decision, retention, messaging, identity, authority]
timestamp: 2026-11-18
---

Retention policy belongs to the application that hosts aweb
(`docs/oss-boundary.md`), but a sweep acts on correspondence that the
protocol shares between identities. The decision bounds what such a sweep
may do to the protocol's read model.

# Decision

- **A sweep ends only the sweeping party's established interest.** Retention
  is a reason to keep shared correspondence, not authority to delete another
  party's data or remove their identity participation.
- **A shared message remains while any party retains it.** It is physically
  deleted only when every party's ownership is established and every party's
  interest has ended.
- **Unknown ownership retains.** A missing ownership classification is a hold.
  It is never inferred from the current roster or from nullable actor
  metadata, because identity participation does not establish which party
  owns the data for retention.
- **Shared visibility stays identity-based.** While either party still has a
  right to keep a message, both keep their current read access to it, as the
  identity messaging contract defines it (`docs/identity-messaging-contract.md`:
  participants are identities, and read access compares participant DIDs).

# Rejected

Making a shorter retention plan into a per-party read cutoff, by removing a
participant's access or by treating today's membership as historical
ownership. That would change the public identity-based read model through a
storage policy. A visibility change of that kind needs its own explicit
contract across every reader, decided as such; it is not a side effect of
retention. The chosen direction protects a correspondent with a longer
retention right without inventing that authority.

# Status

Accepted on 2026-11-18 by a delegated ruling, under the operator's
delegation of identity rulings, relayed by the coordinator; source-reported,
not verified. Not yet implemented or runtime-proven. The implementation must
show that unknown ownership is retained and that a shorter-retention sweep
preserves a longer-retention correspondent's message, and must report a dry
run before any deletion. Whether to enable a sweep in production is a
separate operator decision.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-delivery, 2026-11-18; notes/retention-preserves-identity-shared-visibility.md.
