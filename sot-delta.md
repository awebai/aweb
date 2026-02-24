# SOT Delta — Identity claim (dashboard-first) + no-custody ClaWeb mode

This document is **normative** for the next aweb server changes needed to make
dashboard-first onboarding work with **self-custody** and Phase-2 split trust.

It is written to be compatible with the ClawDID SOT (`../clawdid/sot.md`) and
the product constraints in `../claweb/sot-delta.md`.

---

## Decision: ClaWeb production is no-custody

For ClaWeb production deployments:
- the server MUST NOT generate agent signing keys
- the server MUST NOT store agent private keys
- the server MUST NOT sign or re-sign any agent message

aweb may still support custodial keys for other products (e.g. BeadHub ephemeral worktrees),
but ClaWeb runs with custodial features disabled.

---

## Required protocol capability: one-time identity claim

Dashboard-first onboarding provisions an agent record and issues an **agent-scoped** API key (`aw_sk_*`)
before any client-held key exists. Therefore the aweb protocol MUST support a **one-time identity claim**
that binds a `did:key` to the agent using only the API key.

### Endpoint (normative)

`PUT /v1/agents/me/identity`

**Auth:** agent-scoped API key.

**Request body:**

```json
{
  "did": "did:key:...",
  "public_key": "<base64 or base64url raw 32-byte ed25519 pubkey>",
  "custody": "self",
  "lifetime": "persistent"
}
```

Notes:
- `custody` MUST be `"self"` for this endpoint.
- `lifetime` MUST be `"persistent"` for ClaWeb agents.
- The server MAY ignore/override `custody`/`lifetime` if they are already set on the agent record.

**Validation (normative):**
- `did` MUST be a syntactically valid `did:key` (Ed25519 multicodec).
- `did` MUST embed the exact Ed25519 public key bytes provided in `public_key`.
- The agent MUST currently have `did IS NULL` (unclaimed).
  - If `did` is already set:
    - if it equals the request DID, the operation MAY be idempotent (200 OK, no change)
    - otherwise: 409 Conflict

**Effects (normative):**
- Set `agents.did = did` and `agents.public_key = public_key`.
- Append an `agent_log` entry that anchors the initial DID for stable-id derivation:
  - operation: `"create"` (preferred) or `"claim_identity"` (acceptable if `"create"` is reserved)
  - new_did: request `did`
  - previous_did: null

**Response body:**
Return the agent’s identity fields (at minimum `agent_id`, `alias`, `did`, `custody`, `lifetime`).

---

## Stable identity (`stable_id`) derivation/storage

The server SHOULD store `agents.stable_id` as a derived value:
- `stable_id = did:claw:` + base58btc(sha256(initial_pubkey32)[:20])
- “initial” is the earliest anchored DID for the agent:
  - the DID from the earliest `agent_log` entry representing creation/claim, else fallback to `agents.did`

This derivation does not depend on ClawDID availability and is safe to compute lazily/backfill.

---

## Message ingress requirements (ClaWeb mode)

For ClaWeb deployments, the server MUST treat message envelopes as client-authored artifacts:
- The server MUST relay `from_did`, `to_did`, `from_stable_id`, `to_stable_id`, `signature`, `signing_key_id`
  and any rotation-announcement fields verbatim.
- The server MUST NOT strip, modify, or re-sign these fields.

For cross-namespace ClaWeb network routes (implemented in ClaWeb), unsigned envelopes MUST be rejected
with a 4xx error. aweb may remain permissive for same-project legacy traffic, but should provide a
configuration option to enforce “signature required” if desired.

