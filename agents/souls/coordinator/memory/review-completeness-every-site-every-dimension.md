---
name: review-completeness-every-site-every-dimension
description: When gating a fix, verify the fix's OWN stated purpose holds at EVERY affected site, and enumerate ALL completeness dimensions before ACK — don't anchor on the one dimension that's top of mind. I missed two gaps this way in the aabq.23/.24 arc (federation.py logging; quoted-key bypass), both caught by the second reviewer.
metadata:
  type: feedback
---

In the 503 + scanner arc (2026-06-22/23) I gave two ACKs that each missed a real
gap, both caught by the change-quality reviewer or fresh eyes:

1. **aabq.24** (scanner narrowing): I anchored on bare-form bypasses + edge cases
   and missed the quoted-JSON credential form. See
   [[security-review-detector-narrowing-check-wrapped-forms]].
2. **aabq.23** (surface real AWID errors): I anchored on FAIL-CLOSED (does every
   site still raise/deny?) and status semantics, verified those at all ~14 sites,
   and ACKed — but the task's STATED PURPOSE was *restore the diagnostic logging*
   (the real exception was being discarded). `routes/federation.py` raises a
   distinct message but never logs `exc_info` (the file has no logger), so the
   diagnostic-loss persisted there. I checked the dimension I anchored on, not the
   one the fix existed for.

**Why this keeps happening:** a review naturally anchors on the most salient
risk dimension (security → fail-closed; loosening → bypasses) and treats "all
sites" as satisfied once that one dimension checks out. The miss is always an
*adjacent* dimension at one *outlier* site.

**How to apply — before any review ACK, run an explicit 2-axis sweep:**
- **Axis 1 — the fix's own purpose:** restate why the change exists in one
  sentence, then verify THAT property holds at every site (here: "every AWID
  failure must leave a server-side trace" → grep each site for the log call, not
  just the raise).
- **Axis 2 — the standard dimensions:** for each affected site confirm ALL of:
  does it still deny/fail-closed? correct status? distinct/clear message? **does
  it log the real error (exc_info)?** tests both directions? Make it a checklist,
  not a vibe — the outlier site is the one that's structurally different (no
  logger; a different serialization form; a bare `except`).
- **Enumerate sites mechanically** (grep the pattern) and tick each against both
  axes; an ACK names what was checked at each, so a gap is visible.

The dual gate caught both — that's the system working — but my pass should have.
See [[verify-aw-developer-done-claims-against-code]], [[correctness-over-momentum]].
