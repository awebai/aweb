# Protected-service profile and requester authentication

This is the implementation-owned configuration seam for
`human-assurance-contract.md` section 3. Its validator is
`server/src/aweb/protected_signing/profile.py` (`ProtectedServiceProfile.from_json`).
The complete public fixture is
[`vectors/protected-service-profile-v1.json`](vectors/protected-service-profile-v1.json).
It contains no private key, credential or private key locator. It is synthetic
test configuration, not a registry publication or deployed service.

The profile is supplied through the operator's trusted configuration boundary.
Load an explicitly selected local file. Do not discover a service from an
approval response, account default, runtime response URL, or local human keychain.
Loading the profile grants neither requester permission nor human approval.

| Field | Exact meaning |
| --- | --- |
| `v` | Integer `1`. |
| `service_id` | Explicit stable service identifier. |
| `request_origin` | Canonical request origin; fixed prepare/receipt paths below. |
| `human_origin` | Pinned canonical HTTPS human origin. |
| `rp_id` | Exactly the hostname of `human_origin`, without port. |
| `registry_origin` | Configured authoritative registry origin, with no fallback. |
| `namespace_authorities` | Nonempty array of `{domain, controller_did}` public namespace trust references. |
| `bindings` | Nonempty array of `{scope, authority_key_did, policy}`. |

Each `scope` is the existing protected context, exactly
`{v:1,kind:"protected_key",service_id,authority:{kind,id,domain},human:{id,domain},generation}`.
`authority_key_did` is the referenced authority's public key, not an authorizer
or private custody locator. `policy` is exactly
`{ref:"aweb.human-assurance/1",version:POSITIVE_INTEGER}`. The server's current
SQL authority and shared policy remain authoritative; configuration cannot
weaken their checks. This binding does not provision an agent-admission policy.

Unknown/duplicate fields, floats, null, booleans used as integers, unsafe-range
integers, malformed public keys, unconfigured namespaces, conflicting authority
keys, duplicate current bindings and origin/RP mismatches refuse. There is one
current generation per stable authority/human binding. `binding_for(scope)`
selects only an exact configured scope; it never selects a default human.
The typed validator can also export structural JSON Schema through
`ProtectedServiceProfile.model_json_schema()`; origin/key/cross-reference
semantics additionally use its code validators.

Validate the fixture without a service or database:

```sh
PYTHONPATH=server/src python -m aweb.protected_signing.profile \
  docs/vectors/protected-service-profile-v1.json
```

## Prepare and receipt proof: the same existing covering-v2 encoding

[`vectors/protected-service-request-v1.json`](vectors/protected-service-request-v1.json)
contains exact matching POST/GET bodies, envelopes and signatures over public
synthetic test identities. The fixture timestamp is fixed; its test controls
the clock, while live requests use the current timestamp. No signing seed is
included. Both directions run through the reviewed
`awid.protected_request.verify_protected_request`.

`authenticate_prepare` uses `POST /protected-operations`, label
`protected_operation_prepare`, and the exact configured operation scope.
The body is the shared operation's `intent()` JSON; an optional loopback
`redirect_uri` follows the existing shared parser. No extra requester body
field is added. `authenticate_receipt` uses
`GET /protected-operations/{operation_id}`, label `protected_operation_receipt`,
and an empty body. It obtains the original scope from
`signer.lookup_context(operation_id)` before proof verification. That lookup is
internal routing metadata, never public authorization or a receipt.

Both requests carry:

```text
Authorization: DIDKey <requester did:key> <unpadded standard-base64 signature>
X-AWEB-DID-AW: <selected requester's registered stable ID>
X-AWEB-Timestamp: <timestamp>
X-AWEB-Signed-Payload: <unpadded base64url canonical envelope>
```

`X-AWEB-DID-AW` reuses aweb's existing identity-selection header. It selects
the claimed requester only: the adapter independently resolves that exact
stable ID's current key and requires it to equal the verified proof key. It
then requires the current SQL requester binding for the selected scope. It
cannot select H or replace any authority. A root's key continuity preserves
its stable requester ID; deriving a new stable ID from a rotated key is wrong.

The canonical envelope contains exactly
`v:2`, `type:"aweb.awid-controller-request"`, the configured request `aud`,
`domain:scope.authority.domain`, the route's fixed operation label, timestamp,
uppercase method, external raw path/query, exact `body_sha256`, `service_id`,
and `scope_sha256` of the canonical complete scope. The POST body includes every
wire byte in its digest. GET hashes the empty body. Existing canonical JSON,
signature verification and 300-second skew checks apply; the final body wait
cannot extend the original deadline.

Save/resume retains the original operation ID, frozen scope and selected service
pins. A receipt request signs that original retained scope with the requester's
current key; it must not reconstruct a newer generation or another human from
a default. The server rechecks current authorization for the same stable scope
and original requester under its operation/authority locks. Reading a receipt
never re-signs. No token/cookie, response URL or keychain fallback is accepted.

The shared `ProtectedOperationsHTTP` owns HTTP parsing and receipt shape.
Governance human/session routes and browser pages remain with shared/console
and package .5. These request proofs can prepare/read; they cannot provide H's
LOGIN, B3 UV or controller execution authority.
