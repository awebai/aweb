---
name: dont-reopen-converged-decisions
description: Once the team has converged AND committed on a functionally-fine choice, freeze it — don't re-open to optimize a marginal detail. A coordinator's flip-flop costs more thrash (reversals, blocked agents, eroded trust) than the marginal gain.
metadata:
  type: feedback
---

On 2026-06-17 the app-emit auth wire (for the events/subscriptions feature)
churned through ~6 reversals, and a large chunk of that was **my own
flip-flop**. I pinned the team to keep `45d414d2 + ed1b8ef2` (the `AWEB-App
DIDKey` Authorization marker), then — chasing a marginal forward-compat
benefit — sent a "DEFINITIVE 5-answer lock" switching to plain `DIDKey`, then
**retracted it minutes later** when I saw the team had already reverted and
locked on `AWEB-App DIDKey`. The contradiction propagated across two
coordinators (aw-coordinator latched onto my plain-DIDKey chat as the source
of truth while aweb-developer had my keep-AWEB-App mail) and **blocked**
aweb-developer + aw-developer until I corrected it.

**Why this was wrong:** both options were functionally identical — same
substance (no team cert, v2-family signed payload, manifest-keyed
verification, app-id/key-id headers); only the Authorization *token string*
differed. The committed state was already `AWEB-App DIDKey`, so switching meant
re-churning conformance vectors + re-amending the impl for a gain that could
ride the later durable step (`aaaj.6`, where the wire changes anyway). The
thrash cost vastly exceeded the gain.

**How to apply:**
- Once the team has **converged and committed** on a functionally-fine choice,
  **freeze it.** Don't re-open to optimize a marginal detail.
- If a refinement is genuinely better but non-blocking, **log it as a
  future/durable step** — don't force it mid-stream.
- A definitive-sounding "lock" you retract minutes later is **worse than no
  lock**: make the call once, then defer to the stable convergence.
- Push energy to the real remaining work (here: the byte-parity conformance
  vectors), not the bikeshed (here: a token string).
- When two channels carry different "final" answers from you, the newest
  *correction* wins — but the real fix is not creating the contradiction.

See [[lead-drive-to-completion]].
