---
name: correctness-over-momentum
description: Optimize for getting it RIGHT, not for activity/momentum. Don't manufacture busywork to avoid idle; deliberate depth on the hard design beats keeping everyone busy. "Drive to completion" means drive toward done-RIGHT.
metadata:
  type: feedback
---

2026-06-17, Juan: **"i am much more interested in getting this right than in
rushing."** Context: earlier he'd asked "why are we not working?" (about a
real idle backlog), and I over-rotated to activity — rapid-fire coordination,
surfacing every ack to him, and assigning prep work partly to keep a developer
from sitting idle. He corrected the reflex.

**Why:** doing it right > doing it fast is his core rule. The cost of this
restructuring is borne by current users + long-term maintainability; a rushed
sketch presented as a plan, or extraction tracks opened before the
safety/cleanup discipline is solid, is the failure mode. **Activity is not
progress.**

**How to apply:**
- Between tasks, prefer deliberate depth on the hard questions (user-safety,
  real code-removal, sequencing, irreversible points) over manufactured
  busywork. A developer briefly idle pending a genuine decision is fine.
- [[lead-drive-to-completion]] means drive toward **done-RIGHT**, not
  keep-everyone-busy. Don't confuse momentum with leadership.
- Slow the cadence: fewer, deeper moves; stop narrating every routine ack to
  the human.
- For high-risk work, produce real, pressure-tested, **written** plans —
  reviewed by the consultant and the owning coordinator — and get human
  sign-off before executing irreversible steps. See
  [[dont-reopen-converged-decisions]].
