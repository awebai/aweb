---
type: Lesson
title: A projection governs the whole query and the whole result
description: When a query masks or narrows data for authorization, every join and filter must use the projected value and the whole returned object must be whitelisted; projecting one field while joining on the raw column, or narrowing only the value inside a record envelope, leaks or corrupts.
tags: [lesson, security, authorization, sql, review]
timestamp: 2026-10-23
---

Two defects of the same shape, both reviewed before they were found.

- **Masked output, raw join.** A roster query masked an agent's `did_aw` and
  address unless the identity was bound to a verified key, but its
  encryption-key join matched the raw `did_aw`. A row in the masking window came
  out with no identity and a key assertion bound to the unmasked one; a released
  client rejected that assertion and failed the whole listing, which broke mail
  threading for the whole team. The team had first spent a day on a wrong
  recipient-side theory.
- **Narrowed value, full envelope.** A capability link that granted one field
  projected the record's `value` correctly before filtering and counting, but
  rebuilt the returned record from everything else in the envelope, so a synced
  record's upstream external id leaked through a link that never granted it. An
  expert ACK had checked the value projection "and not the rest of the returned
  record"; the independent reviewer found it.

Both are fixed: the envelope since aweb-naapp 0.3.0 and the roster join since
server 1.27.34.

# How to apply

- Compute a projection once (for example a lateral `projected` row) and use it
  for output, joins and filters alike.
- On capability paths whitelist the returned object (`id`, `rev`, `value`)
  instead of subtracting from it. The complete returned shape is part of
  authorization.
- When reviewing, find every reader of the masked table and of tables keyed by
  the masked field, and put a private sentinel in a non-value member of the
  regression fixture.
- A client that fails a whole list because of one bad row turns that row into
  an outage; see [keep the roster row, clear only the bad key](/aweb-expert/decisions/keep-the-roster-row-clear-the-bad-key.md).

This is the adjacent-dimension miss described in
[review every site on both axes](/aweb-expert/lessons/review-every-site-on-both-axes.md).

# Provenance

Harvested 2026-10-25 from seats `aweb-expert-security-review-2` (note
`masked-projection-must-feed-every-join.md`) and `aweb-expert-pages-data` (note
`capability-record-envelopes.md`; verify NACK 80c1c80b, security reviewer
00f1a408). Verified on main f8f627fb9: the roster query in
`server/src/aweb/routes/agents.py` joins through a single `projected` lateral.
