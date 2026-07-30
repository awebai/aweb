# 2026-06-14 — atext canonical reshape: repo, present, templates, billing

After the London hackathon, Juan and I decided how atext moves forward as the
showcase of agent-first BYOT. Recorded so the team doesn't relitigate it.

## Canonical repo: keep `awebai/atext`, fold the hackathon home

Two options were on the table: keep the atext repo and bring in the good
hackathon work, or clean up the hackathon repo and rename it to atext.

**Decision: atext repo is canonical.** Deciding facts:

- Provenance. `awebai/atext` is our own history (root = the BYOT scaffold).
  The hackathon repo (`generative-ui-london-hackathon-starter`) descends from
  "Initial import: base starter from CopilotKit/examples" — 118 commits of
  someone else's starter + hackathon churn. A showcase repo's `git log` is
  part of the showcase.
- The security core is identical: `auth.py` is byte-for-byte the same in both
  (the hackathon server was copied from atext). So folding home is a bounded,
  additive port — isolation e2e + Neon db config + deploy wiring — not a
  rewrite.
- Name collision: you cannot rename the hackathon repo to `atext` without
  first disposing of the real, better-named, cleaner-history atext repo.

The hackathon repo is archived (not deleted) once atext.ai serves from the
atext repo. Tracked as epic **default-aaae**; supersedes **default-aaad**.

## Present: rebind from A2UI artifact → DOCUMENT version

The hackathon's "present" presented an agent-composed **A2UI artifact** via the
CopilotKit renderer. Juan's real use case is different: he and Eugenie's agents
co-author a **document** (e.g. a pitch) and atext shows a specific version to
investors via a unique link.

**Decision:** present binds to a **document version**, not an artifact. Mint an
opaque, expiring, revocable capability token; resolve it as a **server-rendered**
read-only page; **pin the version at mint** by default. Drop the artifact
object, A2UI envelopes, the CopilotKit renderer, `/v1/search` (LinkUp), and the
LangGraph concierge. This deletes most of the hackathon weight while keeping
exactly the capability Juan wants, and it adds a second BYOT property to the
showcase: capability-scoped public sharing with no account.

## Templates: theme now, declarative templates designed-in, A2UI's idea not its machinery

Bare markdown won't carry an investor page, so presentation is brandable —
but `/present/{token}` is public, so all rendering inputs are **declarative
data atext renders server-side**, never agent-authored HTML/JS.

**Decision:**
- **Theme layer ships now**: team brand tokens + logo + optional header/footer,
  wrapping server-rendered markdown. Optional; any markdown fits any theme, so
  no content-fit failure.
- **Structured templates are designed-in, deferred**: atext's **own** small
  declarative layout schema (slots, schema-validated, themed-markdown
  fallback), rendered by atext. We adopt A2UI's **idea** (declarative,
  data-bound, agent-generatable JSON) but **not** its machinery (CopilotKit
  catalog/renderer) — that would re-import the frontend we're deleting.
- Templates are **never mandatory** — they only ever upgrade a presentation.
- **Built-in layouts first** (decided 2026-06-14). Letting teams author their
  own declarative templates is an attractive future maybe, gated on a careful
  safety design before it's scoped.

Tracked as **default-aaae.6** (deferred; built-in layouts in scope when we get
to it, team-authored a separate future investigation).

## Billing: stays in the showcase; pulled only for the hackathon

Briefly removed billing from the SOT, then corrected: Juan only wanted it out
for the hackathon submission. **Decision: billing stays** — free-tier caps in
v1, Stripe in v2 (existing epic **default-aaac**) — because "how to build an
agent-first app that *bills*" is a core model-repo lesson. The framing
improved: the human appears in exactly two brief no-login browser moments — to
**pay**, and as the **audience** of a presented document — never as an account.

## Source of truth

All of the above is written into `docs/sot.md` (atext repo), updated
2026-06-14. The SOT, not this note, is the contract the team builds to.
