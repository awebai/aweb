# AWID ensure-team endpoint — design proposal

**Status**: Draft, awaiting Juan's GO on the strawman shape (Tom 2026-04-28).
**Owners**: John (coord-aweb, awid). Tom (coord-cloud) on the ac caller side.
**Tracker**: aalr.2 (axis question: "is the AWID API the wrong shape?").

---

## Problem

ac's `ensure_registered_team` calls AWID 2–4 times per signup:

1. `get_namespace`
2. conditional `register_namespace`
3. `get_team`
4. conditional `register_team` (with retry-`get_team` on 409)

Two pressure points:

**In-txn HTTP boundary violation.** ac calls AWID inside a Postgres
transaction (multi_schema_transaction with shared pool, fanned via
TransactionManager). Holding a Postgres txn over external HTTP is an
architectural boundary violation — under degraded AWID, the txn pool
saturates. 30 slots × up to 20s hold time (4 × 5s timeout) = throughput
collapse at sustained-degraded AWID.

**Round-trip count.** Even if the in-txn issue is fixed (two-phase
persist refactor — Mia's outline, separate concern), four round-trips
per signup is a cost on the normal path and a blast-radius multiplier
under any AWID slowdown.

aalr.2's ac-side persist refactor addresses the boundary violation. This
proposal addresses the round-trip count. **Both refactors are
complementary, not alternative.** Doing only the endpoint without the
persist refactor is symptom-treatment; doing only the persist refactor
leaves a 4× round-trip cost.

---

## Proposal

A new AWID endpoint that does namespace get-or-register + team
get-or-register in one round-trip:

```
POST /v1/namespaces/{domain}/teams:ensure
```

### Request body

```json
{
  "controller_did": "did:key:z6Mk...",
  "team": {
    "name": "aweb",
    "display_name": "Aweb Team",
    "team_did_key": "did:key:z6Mk...",
    "visibility": "private"
  },
  "member": {
    "member_did_aw": "did:aw:...",
    "member_address": "juan.aweb.ai/aweb"
  }
}
```

- `controller_did`: the namespace controller's did:key. If the namespace
  doesn't exist, this is the controller it gets registered with. If it
  exists, this must match the stored controller_did (mismatch → reported
  in response, see below). Optional — defaults to the request signer's
  did:key (matching today's `register_namespace` behavior at
  dns_namespaces.py:201-207).
- `team.name`, `team.team_did_key`, `team.visibility`, `team.display_name`:
  identical shape to today's `TeamCreateRequest` (teams.py:232-257).
- `member` (optional): if present, AWID also records initial membership
  binding. Mirrors the optional-member-address path in current cert
  registration. Drop-from-request if cloud onboarding doesn't bind a
  member at signup-time — open for Tom to confirm.

### Auth

**Single signature, by `controller_did`** (matching today's
`_require_namespace_controller` at teams.py:53-70 and
`register_namespace` at dns_namespaces.py:201).

The team_did_key is declared in the request body, not used to sign the
request. AWID stores it as the namespace controller's claim about the
team's identity. This matches today's `create_team` semantics exactly —
team_did_key is signing-relevant only for team-controlled operations
(cert publication via `_require_team_controller` at teams.py:73-94),
not for registration.

This means the ensure-endpoint auth model is **exactly today's
create_team auth, applied to namespace + team simultaneously**. No
dual-signature payload structure needed.

### Behavior

AWID processes the request as **two separate per-step transactions**:

**Step 1 — namespace.**
- If namespace doesn't exist:
  - DNS verification (TXT record check) is **required** unless
    `AWID_SKIP_DNS_VERIFY=1`, parent-namespace authorization header is
    present, or domain is reserved-local. Same gate as
    `register_namespace` at dns_namespaces.py:209-222.
  - Insert row with `controller_did`. Status: `created`.
- If namespace exists with same `controller_did`: status:
  `already_registered`.
- If namespace exists with **different** `controller_did`: status:
  `controller_mismatch`. Step 2 is **skipped** (proceeding would mean
  registering a team in a namespace the caller doesn't control).

**Step 2 — team.** Only runs if step 1 was `created` or
`already_registered`.
- If team doesn't exist: insert row with `team_did_key`. Status:
  `created`.
- If team exists with same `team_did_key`: status: `already_registered`.
- If team exists with **different** `team_did_key`: status:
  `team_did_key_mismatch`. The existing `team_did_key` is returned in
  the response so the caller can detect divergence.

**Step 3 — member binding (optional).** Only runs if `member` was
provided and step 2 was `created` or `already_registered`. Mirrors the
existing public-address binding logic.

### Response

```json
{
  "namespace": {
    "status": "created" | "already_registered" | "controller_mismatch",
    "domain": "juan.aweb.ai",
    "controller_did": "did:key:z6Mk...",
    "verification_status": "verified",
    "namespace_id": "...",
    "created_at": "..."
  },
  "team": {
    "status": "created" | "already_registered" | "team_did_key_mismatch" | "skipped",
    "team_id": "...",
    "name": "aweb",
    "team_did_key": "did:key:z6Mk...",
    "visibility": "private",
    "created_at": "..."
  },
  "member": {
    "status": "created" | "already_registered" | "skipped" | "absent",
    "member_did_aw": "...",
    "member_address": "..."
  }
}
```

HTTP status codes:
- `200 OK` — all requested steps reached a non-conflict terminal state
  (`created`, `already_registered`, `absent`, or `skipped` because the
  optional member step was not requested). The structured response
  carries the per-step outcome.
- `409 Conflict` — the request is well-formed and authenticated, but a
  stored namespace or team conflicts with the requested controller or
  team DID key. The response body is still the normal structured
  response with `namespace.status=controller_mismatch` and
  `team.status=skipped`, or `team.status=team_did_key_mismatch`.
- `400` / `422` — request shape invalid, missing required fields,
  invalid did:key, etc. Same as existing endpoints.
- `401` — signature verification failed.
- `403` — DNS verification required and signing key doesn't match DNS
  controller. Step 1 fails before the multi-step structure begins.
- `5xx` — AWID-side errors (DB, internal).

**Mismatch is 409 with a structured body.** A controller_mismatch or
team_did_key_mismatch is not an AWID server error, but it is a
registration conflict that callers must not accidentally treat as
success. Returning `409 Conflict` keeps HTTP semantics hard to misuse
while preserving the per-step response body so the caller can report the
exact conflict and any prior successful step.

### Idempotency

Idempotent on retry with **same** `controller_did` + `team_did_key` +
`member_did_aw` triple. Every retry returns the same terminal state
(`already_registered` for any steps that landed on first call).

Different `controller_did` from a stored row → `controller_mismatch`.
Different `team_did_key` → `team_did_key_mismatch`. Both are stable
outcomes (deterministic, not race-dependent).

### Partial-success semantics: leave-it

If step 1 succeeds but step 2 fails (DB error, conflict, etc.), the
namespace row stays. AWID **does not roll back**.

**Why:** rolling back the namespace registration creates a
controller-squat race window. If AWID rolls back, the next caller (a
different controller_did) can claim the namespace before the original
controller retries. Leave-it preserves the controller_did claim as
soon as it's established. The caller observes the partial success in
the structured response and retries the team step on its own.

This means ensure makes states true incrementally, not atomically. The
contract: "after a successful response, the namespace and team steps
have reached their reported terminal states." There's no implicit
rollback-on-later-failure.

### AWID-side transactions

**Two separate transactions, not one multi-row txn.**

```
async with db.transaction() as tx:
    # namespace step
    ...

async with db.transaction() as tx:
    # team step
    ...

async with db.transaction() as tx:
    # member step (if present)
    ...
```

Each step is internally atomic (check-then-insert under SERIALIZABLE).
The endpoint wraps three serial txns, not one. Consistent with leave-it
semantics — partial success is observable because the txn boundaries
are independent.

This also avoids long-held AWID-internal locks. A single txn spanning
three INSERTs would lock dns_namespaces and teams simultaneously,
serializing concurrent registrations across unrelated domains.

### Backward compatibility

**Strictly additive.** The four existing endpoints (`get_namespace`,
`register_namespace`, `get_team`, `register_team`) stay. ensure is an
optimization for the cloud-onboarding compound case; other callers
(BYOD, hosted-custodial, manual `aw id register`) keep using the
finer-grained surface.

No schema changes. No changes to existing endpoint behavior. No
rate-limit-tier reshuffles for existing endpoints.

---

## Open questions

1. **Member binding scope.** Does ac's signup flow want to bind the
   initial member at the same call, or is that a separate later step?
   If always-separate, drop `member` from request and keep ensure as
   namespace+team only. (Tom: confirm.)

2. **Naming.** `:ensure` follows Google's REST convention and reads as
   "create-or-find." Defensible alternative is PUT-as-upsert
   (`PUT /v1/namespaces/{domain}/teams/{name}`), which is more REST-pure
   but ambiguous between "replace-or-create" and "create-or-find." I
   prefer `:ensure` for explicit intent. Open for Juan/Tom redirect.

3. **Rate-limit tier.** ensure is roughly equivalent to
   `namespace_register` + `team_create` cost-wise; needs a tier of its
   own (likely the more restrictive of the two — namespace_register —
   to prevent rate-limit-arbitrage).

4. **DNS verification cost on namespace-not-exist.** First-time signups
   that hit ensure with a not-yet-registered namespace pay the DNS
   verification latency (TXT lookup). For ac onboarding's new-org case,
   this is unavoidable — same cost as today's separate
   `register_namespace`. For the namespace-already-exists case (most
   common in steady state), no DNS lookup; fast path.

---

## Implementation sketch

New router file or addition to `awid_service/routes/teams.py`:

```python
@router.post(
    "/{domain}/teams:ensure",  # or path-suffix style
    response_model=EnsureTeamResponse,
    dependencies=[Depends(rate_limit_dep("team_ensure"))],
)
async def ensure_team(
    request: Request,
    domain: str,
    body: EnsureTeamRequest,
    db_infra=Depends(get_db),
    verify_domain: DomainVerifier = Depends(get_domain_verifier),
) -> EnsureTeamResponse:
    db = db_infra.get_manager("aweb")
    domain = _validate_domain(domain)
    caller_did = _verify_controller_signature(
        request, domain=domain, operation="ensure_team",
        extra_payload={"team_name": body.team.name, "team_did_key": body.team.team_did_key},
    )
    # ... three serial steps, each returning a NamespaceStep / TeamStep / MemberStep
    return EnsureTeamResponse(namespace=..., team=..., member=...)
```

Extra-payload signing-context for the namespace_controller signature
includes `team_name` and `team_did_key` so a captured signature can't be
replayed against a different team registration in the same namespace.
This is the same anti-replay shape today's `_verify_signed_request`
already uses (teams.py:39-50).

---

## What this does NOT change

- **AWID's trust model.** Cert-presentation-as-auth (post-1.18.6) stays
  exactly as-is. ensure is a registration-time optimization, not an
  authorization-time change.
- **Schema.** No new tables, no column additions. dns_namespaces and
  teams unchanged.
- **CLI.** No `aw` command surface change. CLI keeps using
  `register_namespace` and `register_team` separately for the BYOD/manual
  paths.
- **awid 0.5.x → 0.6 boundary.** This is additive; lands in a 0.5.x
  release with strict back-compat.

---

## Sequencing

1. Juan reviews and approves strawman shape (this doc, or a redirect).
2. ac-side persist refactor (Mia/Tom's lane) lands first. Independent
   of this endpoint. Removes the in-txn HTTP boundary violation.
3. AWID 0.5.3 (or whatever release) ships ensure-team. Adds the new
   endpoint, doesn't break existing surface.
4. ac switches `ensure_registered_team` to call the new endpoint. Drops
   round-trip count from 4 to 1.
5. Backfill dispatched-already-without-this is a no-op — existing
   namespaces and teams stay valid.

---

## References

- `awid_service/routes/dns_namespaces.py:182-275` — current
  register_namespace handler (auth, DNS check, idempotent insert).
- `awid_service/routes/teams.py:404-442` — current create_team handler
  (auth, INSERT, 409-on-conflict).
- `awid_service/routes/teams.py:39-70` — auth helpers
  (`_verify_signed_request`, `_require_namespace_controller`).
- `aweb/docs/awid-sot.md` — AWID contract SOT (corrected 2026-04-26
  for cert-presentation trust model).
- aalr.2 axis question (Juan + Tom 2026-04-28) — context for this
  proposal.
- Mia's two-phase persist refactor outline (ac-side, separate
  concern) — complement to this endpoint, addresses in-txn boundary.
