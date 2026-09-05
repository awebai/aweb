---
name: dont-assert-business-facts-messy-isnt-unneeded
description: Don't assert product/business/roadmap facts (pricing, are-we-charging, what's-needed-soon, which features matter) as known — verify or defer to Juan. And "messy/unproven/sprawl" != "unneeded": clean+consolidate needed machinery, don't cut it.
metadata:
  type: feedback
---

2026-06-18, during the ac scope-reset. I repeatedly pushed to CUT the m4/m5/m8
"dormant" machinery for simplicity, and **asserted wrong facts to justify it**:
"we launch free" (wrong — we are ALREADY charging), "the decomposition is
deferred" (wrong — it's SOON), "we don't need the hosted MCP gateway for the
demo" (wrong — we need it). Juan corrected all three. I churned the ac team
through cut -> hedge -> cut -> keep.

**Two lessons:**

1. **Do NOT assert product/business/roadmap facts as known** — pricing, whether
   we're charging, what's needed-soon, which features matter. That's Juan's
   reality; **verify or ask, don't assert.** (Same failure mode as
   [[aweb-deploy-topology]], but for business/roadmap facts instead of code.)

2. **"Messy / unproven / sprawl" != "unneeded."** Juan's complaint (7 migrations,
   untested folio) was about **cleanliness + provenness**, not the machinery
   being unwanted. The fix for a sprawl of *needed* machinery is to
   **clean/consolidate** it — fold fixes into the original migration, merge
   related ones, prove it end-to-end — **NOT cut it.** Don't reach for deletion
   when the real need is consolidation.

**How to apply:** when tempted to cut for "simplicity," first ask — is this
actually *unneeded*, or just *messy / unproven / ahead-of-need*? If it's needed
(even soon-not-now), clean + consolidate + keep. And **never justify a cut with
an assumed business fact — confirm it with Juan first.** See
[[correctness-over-momentum]].
