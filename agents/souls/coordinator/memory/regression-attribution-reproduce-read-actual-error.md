---
name: regression-attribution-reproduce-read-actual-error
description: When attributing a regression, REPRODUCE it and read the LITERAL failing error before committing a fix. A bisect proves which DELTA broke it, not which COMMIT — suspect-by-name attribution is a guess. Beware confirmation-bias when the suspected code is your own.
metadata:
  type: feedback
---

On 2026-06-30 a federation-e2e regression (68 failures, "empty base url")
blocked the launch-critical 1.26.21 cut. ac-operations bisected it correctly to
the `server-v1.26.20..cut` DELTA (green at 1.26.20, red at cut, harness
unchanged) and named my AWID commits `1cab7cd4`/`e70cb44d` as "prime suspects"
because they touch federation/AWID. I found a *real* coupling in my code (the CLI
`isTransientServiceUnavailableBody` retry keys on the old server message string
my aabq.23 changed) and was about to push a server-side token fix.

It was the wrong root cause. Reproducing locally with `KEEP=1` and reading the
KEPT-container logs showed the FIRST failure was `aw id team accept-invite` exit 2
with **"this workspace already has a global identity; use --global"** — a guard
added by a *different* commit, `4c97715b "Fail closed ambiguous accept invite
scopes"` (CLI, aw-CLI lane). No AWID 5xx anywhere. The real fix was a 4-line
harness adaptation (`--global` on the global accept-invite calls); fed-e2e went
48/116 → 116/116. My commits were exonerated (the 503-coupling is real but
*latent* — the e2e's local AWID never triggers it; tracked separately as `aadd`).

**Why I nearly shipped the wrong fix:** (1) I accepted a plausible
suspect-by-name attribution instead of reading the actual error. (2) Confirmation
bias — I'd already "found" a flaw in my own code, so blame felt right. (3) The
end-state server log was ambiguous (no retained 5xx), and I almost theorized
around it instead of reproducing.

**What saved it:** holding the line on "reproduce + read the literal error before
committing a launch-critical fix," despite time pressure, after earlier misses
this arc.

**How to apply:**
- A bisect bounds the DELTA. It does NOT name the commit. Don't push a fix on a
  by-name suspect — get the actual failing command + error string.
- Reproduce with artifacts retained (`KEEP=1` / kept logs); read the FIRST
  failure, not the cascade. "empty base url" was a cascade; the root was an
  earlier accept-invite guard.
- When the suspect is your OWN code, raise the bar, don't lower it — verify the
  literal error implicates it before accepting blame.
- A real-but-latent flaw you find while hunting (the 503-coupling) is worth
  tracking, but is NOT automatically THE regression. Keep them distinct.
See [[review-completeness-every-site-every-dimension]],
[[verify-aw-developer-done-claims-against-code]], [[correctness-over-momentum]].
