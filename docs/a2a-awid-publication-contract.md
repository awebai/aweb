# AWID A2A Publication and Bridge Delegation Contract

Status: normative contract for `aweb-aaqa.7`. Downstream AWID/aweb/AC code must cite this document and the fixtures in `docs/vectors/a2a-awid-publication-v1.json`.

This contract defines how AWID publishes A2A Agent Card routes for aweb identities. AWID is the durable identity, address, delegation, and directory registry. AWID is not the default runtime card host and does not make hosted gateway traffic end-to-end encrypted.

## Invariants

- Generic A2A clients can ignore AWID and use ordinary card URLs.
- aweb-aware clients verify that an aweb address has an active AWID A2A publication, the card digest matches the fetched card, the gateway is authorized, and the signer is current for the identity at assertion time.
- No customer-facing `verified`, `AWID-backed`, or `authorized for address` A2A claim is allowed until publication, delegation, digest, expiry, key-history, and revocation checks are enforced.
- Self-custodial private keys never leave the operator/agent device. A hosted gateway may be delegated; it must not receive a self-custodial identity private key.
- Cards are operational service descriptions. The authoritative AWID fact is URL + digest + route/delegation metadata. Card-body caching is optional cache only and must never override digest verification.

## Canonicalization and Signatures

All signed A2A publication and delegation payloads use the shared AWID canonical JSON scheme implemented by `awid.CanonicalJSONValue` and the Python AWID equivalent:

- UTF-8 JSON object bytes.
- Deterministic object-key ordering as implemented by AWID canonical JSON.
- No insignificant whitespace.
- Timestamps are RFC3339 UTC seconds with `Z`; fractional seconds are rejected for signed payload construction.
- Empty optional fields are omitted, not serialized as empty strings.
- Signatures are Ed25519 over the canonical payload bytes.
- Signatures are encoded with raw standard base64 without padding, matching existing AWID signed operation practice.
- `*_hash` fields use `sha256:` plus raw standard base64 without padding of the SHA-256 digest unless the field explicitly names another encoding.
- `*_digest` fields that bind a signed assertion use `sha256:` plus raw standard base64 without padding of `SHA256(canonical_assertion_bytes || decoded_signature_bytes)`, matching `AtomicAddressClaimIdentityProofHash`.
- `card_digest` uses the Agent Card digest from `a2a.CardDigest`: `sha256:` plus lowercase hex SHA-256 of the canonical Agent Card with `signatures` omitted.

The AWID verifier must reconstruct canonical bytes from trusted normalized fields and re-verify signatures server-side. It must not trust client-provided canonical bytes, hashes, conflict-code interpretation, signed-field extraction, or normalized URLs.

The fixture `docs/vectors/a2a-awid-publication-v1.json` contains release-blocking byte-equivalence cases:

- `publication.canonical`
- `delegation.canonical`
- `publication_delegation_hash`

Go producer tests and AWID/Python verifier tests must assert the same bytes before implementation release.

## Publication Assertion

Operation: `publish_a2a_route`.

Natural key for idempotency:

```text
(address, route_id, card_url, rpc_url, gateway_identity, card_revision)
```

Exact signed payload fields:

| Field | Required | Notes |
|---|---:|---|
| `operation` | yes | Literal `publish_a2a_route`. |
| `assertion_id` | yes | Stable AWID event/assertion id; UUIDv4 or stronger. |
| `address` | yes | Canonical aweb address, e.g. `acme.com/help`. |
| `did_aw` | yes | Stable identity DID for the published address. |
| `current_did_key` | yes | Current signing key for `did_aw` at `published_at`. |
| `signer_did` | yes | DID that signs this assertion. For direct self-custodial publication this equals `current_did_key`; for delegated/hosted publication it is the authorized signer. |
| `signer_kid` | yes | Key id used for signature verification. |
| `card_url` | yes | Absolute HTTPS URL. |
| `rpc_url` | yes | Absolute HTTPS URL. |
| `route_id` | yes | Opaque A2A gateway route id. |
| `tenant` | no | Omitted by default for path-routed direct cards. |
| `gateway_identity` | yes | DID/address of the bridge gateway identity. |
| `delegation_id` | no | Required when gateway identity differs from the published identity. |
| `delegation_digest` | no | Required when `delegation_id` is present. |
| `card_digest_alg` | yes | Literal `sha256`. |
| `card_digest` | yes | Digest of fetched Agent Card with signatures omitted. |
| `card_revision` | yes | Monotonic string or integer-as-string chosen by publisher. |
| `default_for_host` | yes | Whether this is the root `/.well-known/agent-card.json` card for the host. |
| `status` | yes | `active` or `revoked`. |
| `published_at` | yes | Signed timestamp. |
| `expires_at` | yes | Expiry timestamp. |
| `registry_url` | yes | Canonical registry origin, e.g. `https://api.awid.ai`. |
| `identity_custody` | yes | `self`, `hosted_custodial`, or `delegated_bridge`. |
| `authority_source` | yes | Machine value naming how authority was presented. |

The wire object also carries `signature`, but `signature` is not part of the signed payload.

## Bridge Delegation Assertion

Operation: `delegate_a2a_bridge`.

Natural key for idempotency:

```text
(delegation_id, delegator_did_aw, gateway_identity, address, route_id)
```

Exact signed payload fields:

| Field | Required | Notes |
|---|---:|---|
| `operation` | yes | Literal `delegate_a2a_bridge`. |
| `delegation_id` | yes | Stable delegation id. |
| `delegator_did_aw` | yes | Identity granting gateway authority. |
| `delegator_current_did_key` | yes | Current key at `issued_at`. |
| `delegated_gateway_identity` | yes | Gateway identity authorized to bridge. |
| `address` | yes | Address for which bridging is authorized. |
| `route_id` | yes | Route id authorized. |
| `card_url` | yes | Allowed Agent Card URL. |
| `rpc_url` | yes | Allowed RPC URL. |
| `allowed_operations` | yes | Array. Minimum product set: `send_task`, `receive_reply`, `cancel_task`, `serve_card`. |
| `card_digest_alg` | yes | Literal `sha256`. |
| `card_digest` | yes | Agent Card digest at delegation issuance. |
| `publication_assertion_id` | no | Omitted in v1 when the publication assertion binds this delegation by `delegation_digest`; mutual publication/delegation digests are not allowed. |
| `publication_digest` | no | Omitted in v1 when the publication assertion binds this delegation by `delegation_digest`; mutual publication/delegation digests are not allowed. |
| `custody_mode` | yes | Custody row from the matrix below. |
| `authority_source` | yes | Machine value naming how delegation authority was presented. |
| `signer_did` | yes | DID that signs this delegation. |
| `signer_kid` | yes | Key id used for verification. |
| `issued_at` | yes | Signed timestamp. |
| `expires_at` | yes | Expiry timestamp. |
| `status` | yes | `active` or `revoked`. |
| `revoked_at` | no | Required when status is `revoked`. |
| `revocation_reason` | no | Machine-readable reason when revoked. |
| `registry_url` | yes | Canonical registry origin. |

The wire object carries `signature`, but `signature` is not part of the signed payload.

`delegation_digest` is:

```text
sha256:<base64-raw-std-no-padding>(SHA256(canonical_delegation_bytes || decoded_delegation_signature_bytes))
```

V1 intentionally avoids a mutual digest cycle. The delegation assertion independently authorizes `address`, `route_id`, `card_url`, `rpc_url`, allowed operations, gateway identity, expiry, and custody mode. The publication assertion may then bind that delegation by `delegation_id` and `delegation_digest`. A delegation assertion must not require a digest of the publication assertion that already embeds the delegation digest.

## Custody and Authority Matrix

| Publication mode | Identity custody | Gateway custody | Authority source | Supported |
|---|---|---|---|---|
| Direct self-custodial | self | same identity/operator | Local identity signing key plus current AWID did log | yes |
| Hosted custodial | hosted_custodial | hosted gateway | Authenticated hosted session; AC/AWID signs with hosted custody authority | yes |
| Self-custodial delegated bridge | self | delegated_bridge | Local identity signs delegation to gateway; gateway signs route operations with delegation reference | yes |
| Hosted identity to self-hosted gateway | hosted_custodial | delegated_bridge | Hosted session creates delegation to external gateway identity | yes, only if gateway identity is separately registered and delegation expiry is bounded |
| Gateway without delegation for self-custodial address | self | delegated_bridge | Operator config only | no product-trusted verified claim; may be labeled local/unverified only |

Missing authority errors must name both:

- the expected authority source for the claimed custody combination;
- the supplied or wrong authority source.

Generic `authority invalid` errors are rejected at review.

## Verification Rules

An aweb-aware verifier for an A2A card must:

1. Resolve the aweb address in AWID.
2. Fetch active A2A publication assertions for that address.
3. Reconstruct canonical publication bytes and verify the publication signature.
4. Check `published_at` is within the replay window at write time and `expires_at` is in the future at read time.
5. Verify `did_aw` key history: `current_did_key` was current for `did_aw` at `published_at` and has not been rolled back or split-viewed.
6. Fetch the Agent Card from `card_url`, remove `signatures`, canonicalize, and compute `card_digest`.
7. Reject if digest, `rpc_url`, `route_id`, gateway identity, or tenant disagree with the active publication.
8. If `delegation_id` is present, fetch the delegation assertion and verify canonical bytes, signature, expiry, status, allowed operations, card URL/RPC URL/route/address, `delegation_digest`, and identity key history.
9. Check revocation: publication, delegation, namespace, team certificate, and identity key revocation invalidate stale publications according to their timestamps.
10. Return verification tier:
    - Tier 0: ignored/unsigned generic A2A.
    - Tier 1: card signature verifies but no AWID publication/delegation verification.
    - Tier 2: AWID publication + digest + delegation + identity history verified.

## Replay, Expiry, and Idempotency

- Server clock is authoritative.
- Write-time signed timestamp skew window: 5 minutes past/future unless AWID adopts a stricter signed-operation standard.
- `expires_at` must be greater than `published_at` and must not exceed 90 days for public routes in v1.
- Natural-key idempotency is preferred. Exact same active assertion can return `already_applied`.
- Nonce tables are out of scope for v1. Adding nonce storage requires a contract amendment with retention and cleanup policy.
- Replaying an expired or revoked assertion fails with a structured conflict code.

## Conflict Codes

AWID publication/delegation write APIs must return structured machine codes. Minimum taxonomy:

- `a2a_publication_exists_different_digest`
- `a2a_publication_exists_different_gateway`
- `a2a_delegation_missing`
- `a2a_delegation_digest_mismatch`
- `a2a_delegation_expired`
- `a2a_delegation_revoked`
- `a2a_card_digest_mismatch`
- `a2a_card_url_invalid`
- `a2a_rpc_url_invalid`
- `a2a_route_id_invalid`
- `a2a_identity_signature_invalid`
- `a2a_delegation_signature_invalid`
- `a2a_timestamp_stale`
- `a2a_namespace_not_registered`
- `a2a_address_not_registered`
- `a2a_custody_combination_unsupported`
- `a2a_authority_source_invalid`
- `a2a_payload_canonicalization_mismatch`
- `a2a_primitive_disabled`
- `a2a_primitive_not_supported`

A shared conflict-code fixture must be asserted by AWID server tests and CLI/SDK consumer mapping tests. New codes without consumer mapping fail CI.

## Read API Shape

Anonymous read/discovery is allowed. Minimum response for aweb-aware discovery:

```json
{
  "address": "acme.com/help",
  "did_aw": "did:aw:...",
  "a2a": {
    "status": "active",
    "card_url": "https://acme.com/a2a/agents/r_help_01/agent-card.json",
    "rpc_url": "https://acme.com/a2a/agents/r_help_01/rpc",
    "route_id": "r_help_01",
    "tenant": "",
    "gateway_identity": "did:aw:...",
    "card_digest_alg": "sha256",
    "card_digest": "sha256:...",
    "card_revision": "2026-06-07.1",
    "publication_assertion_id": "pub_...",
    "delegation_id": "del_...",
    "delegation_digest": "sha256:...",
    "published_at": "2026-06-07T20:00:00Z",
    "expires_at": "2026-07-07T20:00:00Z",
    "verification": "awid_publication_available"
  }
}
```

Read APIs must not require authenticated caller identity for public directory verification.

## Schema and Migration Rules

If AWID storage changes are needed, implementation must add new ordered migrations after the current latest migration. At the time of this contract, the next AWID migration would be:

```text
awid/src/awid_service/migrations/007_a2a_publications.sql
```

Do not edit `001_registry.sql` or any already shipped migration.

## Operational Observability

Server-side write and verification logs must include:

- request id;
- operation;
- dry-run/apply flag if applicable;
- outcome/conflict code;
- redacted address/did/gateway hash prefixes;
- custody mode and authority source class;
- latency;
- assertion id/delegation id.

Logs must not include private keys, raw signatures unless debug-gated, raw card bodies, or raw caller task plaintext.
