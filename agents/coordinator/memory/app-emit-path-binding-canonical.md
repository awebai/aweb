---
name: app-emit-path-binding-canonical
description: App-emit signed-path binding is mount-dependent and CANONICAL-LOCKED — hosted (app.aweb.ai, ac mounts aweb under /api) = /api/v1/events/app; the frozen conformance vector's /v1/events/app is the STANDALONE byte-parity fixture, NOT the hosted runtime path. raw_request_target uses ASGI raw_path (full external, mount prefix included). Do not "fix" folio to /v1 or change the verifier to strip /api.
metadata:
  type: project
---

Locked 2026-06-18 after the foundation-proof emit landed (first-ever
`aweb.app_events` row, app_id=folio, 19:15:05Z). The app-emit **signed path**
is the actual external request target, which is **mount-dependent**:

- **Hosted** (`app.aweb.ai`): ac mounts the aweb app under `/api`
  (`ac/.../main.py` `app.mount('/api', aweb_app)`), so the external target is
  **`/api/v1/events/app`** — and that is what folio signs and what the deployed
  verifier expects. CANONICAL for the hosted runtime.
- **Standalone** (no mount, `root_path=""`): external target is
  **`/v1/events/app`** — this is what the **frozen conformance vector**
  (`app-emit-credential-v1.json`, byte-parity SOT, sha `56f9fcd3`) signs. It is
  a **byte-parity FIXTURE**, NOT the hosted runtime mandate.

**Mechanism (`server/src/aweb/team_auth_envelope.py:44` `raw_request_target`):**
it reads the ASGI **`raw_path`**, which is the FULL external wire path
**including** the `/api` mount prefix. Starlette's `Mount` strips
`scope["path"]` but leaves `raw_path` intact. For a hosted POST to
`/api/v1/events/app`: `raw_path=/api/v1/events/app`, `root_path=/api`; the
root_path re-prepend (lines 53-56) is **skipped** because `path` already starts
with `/api` → returns `/api/v1/events/app`. So the **same verifier code** is
conformant to the vector standalone AND correctly binds `/api` hosted — the
difference is `raw_path`, not a code change. **No vector re-freeze, no verifier
change, no folio change.**

**The trap (hit TWICE on 2026-06-18):** both the folio-side coordinator and then
aw-coordinator (the vector/contract owner) argued the deployed verifier
reconstructs the *mount-internal* `/v1` and therefore folio must be "fixed" to
sign `/v1`. That is WRONG and would have re-broken the proven path — the mounted
verifier expects `/api/v1/...`. The error: assuming `raw_request_target` strips
`root_path`; it does not (it uses `raw_path`, full external).

**How to apply:** (1) This is locked — `/api` hosted, `/v1` standalone fixture;
push back hard if anyone reopens it. (2) **The live emit is the empirical
arbiter.** When coordinators contradict on a *testable* fact — even the nominal
decision-owner — a real end-to-end result outranks any theoretical claim; don't
defer to authority against a passing proof. Reconcile to ONE truth with the
evidence (code + the row + the passing guard test), keep builders frozen until
then. See [[hold-propagation-when-decider-contradicts]],
[[correctness-over-momentum]], [[dont-assert-business-facts-messy-isnt-unneeded]].
