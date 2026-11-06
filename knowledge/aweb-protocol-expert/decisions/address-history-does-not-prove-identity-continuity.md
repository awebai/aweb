---
type: Decision
title: Address history does not prove identity continuity
description: The identity registry rewrites an address's did_aw in place and keeps its created_at, so no timestamp shows who held an address earlier; legacy address-only contacts are left inert rather than bound by a guessed backfill, and every contact path writes the exact binding at creation.
tags: [decision, awid, contacts, identity, migration]
timestamp: 2026-10-23
---

Decided on 2026-10-23 by the OSS coordinator and the security reviewer while
shipping strict contacts-only inbound mode. Contacts created by address alone
had no binding to an identity, and a backfill was requested to bind them.

# Discovery

The registry's controller address update rewrites the address row's `did_aw`
in place and keeps the row's `created_at`; there is no address history. So
nothing in the registry shows that an address belonged to a given identity when
a contact was made.

# Decision

- No backfill, not even a classification-only command. Legacy address-only
  contacts stay inert; they already admitted no non-team senders under the
  previous mode.
- Owners rebind explicitly, or remove and re-add the contact through the current
  authority-resolved path.
- Every contact-creating path (REST and CLI, MCP tools, federation learning)
  writes the exact identity and controller binding at creation, or refuses.
- A continuity-proving backfill waits until the registry has address history,
  and is then a separate task.

# Rejected

- Resolve-and-bind to today's holder: binds unproven identities.
- Bind only when `created_at` predates the contact: "never infer continuity
  from created_at"; the timestamp survives a rebinding.
- An evidence allowlist or classification-only command: withdrawn as
  unnecessary (YAGNI).

`docs/contacts-only-deployment.md` states the outcome; this records the
registry fact and the rejected alternatives.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-contacts-only`
(STATE before retirement; coordinator bd7a049e and 7ec17e6b, security reviewer
63f99887, 35f5c4c7). Verified on main f8f627fb9: the address update in
`awid/src/awid_service/routes/dns_addresses.py` sets `did_aw` in place.
