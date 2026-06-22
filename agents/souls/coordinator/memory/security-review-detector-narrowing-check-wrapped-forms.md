---
name: security-review-detector-narrowing-check-wrapped-forms
description: When security-reviewing a change that narrows a broad substring scanner into structured regex detectors, enumerate the SERIALIZATION-WRAPPED forms (JSON/YAML quoted keys, quoted headers), not just bare assignment + edge cases. A name-then-delimiter regex misses quoted-name forms that the old bare-substring scanner caught — a real regression.
metadata:
  type: feedback
---

On 2026-06-22, reviewing aabq.24 (narrowing the blueprint secret scanner from
bare substring matches to structured regex), I gated it as security-preserving
after an adversarial pass — I checked cross-newline values, `<placeholder>`
exclusion, and the `==` edge. **I missed the quoted-key JSON form.** The
credential regex required `name` then `:`/`=`, but in `{"api_key":"secret"}` a
closing quote sits between the name and the colon, so it did not match — and the
old bare-substring scanner *did* catch it (it matched `api_key` anywhere). My
"no new bypass" conclusion was wrong; the second reviewer (change-quality lane)
caught it. The dual gate worked, but my pass should have.

**Why:** when a detector moves from "contains substring X" to "X in
structure S", every serialization that wraps X differently is a candidate
bypass — and a regression against the looser-but-broader original.

**How to apply — for any scanner/detector NARROWING, explicitly test the
wrapped/serialized variants before ACK:**
- JSON: `{"name":"value"}`, spaced `"name": "value"`
- YAML quoted key: `"name": value` / `'name': value`
- single AND double quotes around the name, on both sides
- quoted headers: `"X-Header": "value"`
- and confirm the inverse: concept-mentions / quoted-name-without-value still PASS

**Scope check that helped:** substring/`FindAllString`-based detectors (the
did:key / did:aw / PEM matchers here) are NOT affected by wrapping quotes — only
the `name`-then-`delimiter` regexes were. Naming which detectors are
structurally vulnerable vs substring-based scopes the fix and prevents over-fix.

A narrowing is a LOOSENING: review it for false NEGATIVES (real material that now
passes), and any form the old broad matcher caught is a regression candidate.
See [[verify-aw-developer-done-claims-against-code]],
[[correctness-over-momentum]].
