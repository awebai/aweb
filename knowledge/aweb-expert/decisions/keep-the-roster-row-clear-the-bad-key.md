---
type: Decision
title: Keep the roster row, clear only the bad key
description: When a roster row's encryption-key assertion fails verification, aw keeps the row exactly as the server projected it, clears only the key and warns once; it never fails the whole listing or drops the row, and encrypted sends to that row refuse with no plaintext fallback.
tags: [decision, aw-cli, roster, e2ee, messaging]
timestamp: 2026-10-23
---

Decided on 2026-10-23 by the OSS coordinator and the security reviewer, with
the operator's approval, while fixing a team-wide mail-send failure. A released
client failed the whole agent listing because one row carried an inconsistent
key assertion; mail send then silently skipped automatic threading, minted a
fresh conversation id, and the server refused the message as a duplicate
conversation. One bad row broke threading for every sender in the team.

# Decision

- A row whose encryption-key assertion fails keeps exactly the fields the
  server projected; only the encryption key is cleared.
- One warning per listing names the alias and the reason; `--json` output stays
  parseable and no schema changes.
- Encrypted mail and chat to that row refuse (no key), with no plaintext
  fallback and no cached or registry key substituted.
- A recipient-lookup failure during mail send warns that automatic threading is
  unavailable instead of logging at debug level.

# Rejected

- **Failing the whole listing** (the released behaviour): turns one
  inconsistent row into a team-wide outage.
- **Dropping the failed row:** breaks threading to that one recipient, whose
  existing conversation can no longer be found.
- **Also dropping rows that fail for non-key reasons:** withdrawn by the
  security reviewer. Listings verify only rows that carry a key, released
  clients never dropped rows, and the only non-key failure is refused by the
  server at registration. The operator's rule is no guards for impossible
  states.

# Why keeping the row is safe

No field from the failed assertion is used to fill or repair identity, and a
verified global row ignores the roster key anyway in favour of authoritative
registry discovery with a stable-id check.

The server-side root cause is recorded in
[a projection governs the whole query and the whole result](/aweb-expert/lessons/a-projection-governs-the-whole-query-and-result.md);
the review miss that came with the change is in
[review a change against its existing consumers](/aweb-expert/lessons/review-a-change-against-its-existing-consumers.md).

# Provenance

Harvested 2026-10-25 from seat `aweb-expert-security-review-2` (note
`roster-bad-key-keep-row-clear-key.md`; coordinator b5ef3444 and 7834285e,
security reviewer 1576c2f8, 4261da7d and the withdrawal 837a41f2, operator
approval b170f8cc).
