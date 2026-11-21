---
type: Decision
title: Measuring mode keeps the team-key pin only on an act key mismatch
description: With team-key pin enforcement off, a served key that differs from the pin moves the pin unless the registry's own act names a different key (key_mismatch), in which case the pin stays and the pinned key is used in both modes; never moving the pin and refusing on any act failure were rejected because both lock members out. Approved 2026-11-16; on a review branch, not on main.
tags: [decision, team-key, pinning, registry, membership, rotation]
timestamp: 2026-11-16
---

**Status:** ruled and approved by the operator on 2026-11-16 (source-reported:
an OSS ruling relayed in team mail, which this harvest could not read).
Implemented on the source's review branch in commit c7e45e9eb; not on main
when harvested.

# Decision

While `AWEB_ENFORCE_TEAM_KEY_PINS` is off (measuring mode), a served team key
that differs from the admitted pin still moves the pin
(`team_key_pin_moved_without_act`), with one exception:

- When the registry's own act names a key other than the one served
  (`key_mismatch`), the pin stays and the pinned key is used, in **both**
  modes (`team_key_pin_kept`).
- Every other mismatch moves the pin as before: no act at all (history from
  before acts were kept), and an act for the served key whose controller DNS
  cannot show it.
- A per-team memo of (served key -> answer) lasting 60 s, the registry key's
  freshness bound, keeps a lasting mismatch to one act read per minute.

# Why

The member check compares the key a member was accepted under with the pin,
and certificates verify under the key the server returns. The pin is therefore
not only an audit value: it decides who is a member.

- The flip measuring mode had to stop came from a stale or substituted
  registry read sitting beside an act that already names another key. Each
  flip back made every member a non-member. `key_mismatch` identifies exactly
  that case.

# Rejected

- **Never moving the pin in measuring mode.** Because membership compares the
  accepted key with the pin, every member of a team whose key changed before
  acts were kept would become a non-member: the lockout the staged flag exists
  to avoid. Do not "simplify" measuring mode to a pin that never moves.
- **Refusing the move on any act failure.** Hosted namespaces have no DNS
  record of their own, so every rotated hosted team would be locked out.

# Limit

A registry that serves another key and withholds the act still moves the pin.
That gap closes only when enforcement can be on for hosted organisations;
`docs/trust-model.md` on the review branch states it.

# Evidence

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-16; notes/measuring-mode-keeps-pin-on-act-key-mismatch.md, notes/member-check-compares-accepted-key-to-pin.md. The commit message of c7e45e9eb confirms the three outcomes, the memo and the limit.
