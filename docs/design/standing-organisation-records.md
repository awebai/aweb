# AWID organisation records and standing issuer trust

Design for review. This document specifies the records for pilot D2 and
the issuer trust binding used by [standing proofs §6](standing-proof-and-feed.md#6-federation-and-issuer-discovery).
Juan approved the identity-path work on 2026-11-28. The records, routes
and controller commands ship with the new standing registry.

## 1. Encoding and authority

D2 has two namespace-controller record types, the issuer association and
the organisation head. Each has its own chain. The registry publishes a
separate issuer-wide key set under its registry domain controller. A
purpose-key change updates that one key set and its registry discovery
commitment. Subscriber domains keep their existing issuer association
and organisation head.

Sign the ASCII purpose below, LF, then the RFC 8785 canonical UTF-8
JSON payload with Ed25519. Define `digest` as the lowercase hex SHA-256 of
those signed bytes, excluding the signature. A signed envelope has
`payload` and `signature`, each unpadded base64url. The operation selects
the purpose. Reject unknown fields, duplicate keys, noncanonical bytes
and keys of any other algorithm. Domain and team IDs use the canonical
AWID spelling. Origins are canonical HTTPS origins. Revisions, epochs
and Unix millisecond times are canonical unsigned decimal strings in
the unsigned 64-bit range. Revisions start at one. Digests are 64
lowercase hexadecimal characters. Nonces and salts are 32 random bytes
encoded as unpadded base64url.

| Purpose | Exact payload fields |
| --- | --- |
| `awid.standing-issuer/1` | `domain`, `registry_origin`, `controller_epoch`, `revision`, `previous`, `issuer` |
| `awid.organisation-head/1` | `domain`, `registry_origin`, `controller_epoch`, `revision`, `previous`, `definition_sha256` |
| `awid.standing-key-set/1` | `issuer`, `registry_origin`, `controller_epoch`, `revision`, `previous`, `feed_id`, `keys` |

`issuer` is the registry authority's canonical DNS name. Its value stays
stable across operational key changes. `feed_id` is a stable opaque
identifier of that registry's authenticated feed, encoded as a lowercase UUID. `previous` is null for
revision one and the preceding record's digest otherwise. Chains run by
namespace and type, or by issuer for key sets. They continue across
controller epochs. Publish against the prior digest under the
namespace write lock. Verify the covering controller request and the
exact open epoch and controller independently from the object. A retry
with identical canonical bytes, signature and private input returns the
same result. A conflicting revision or stale predecessor refuses.

## 2. Issuer discovery and withdrawal

For an exact domain, authenticated discovery binds its controller and
`registry=`. Standing discovery also carries `standing_issuer=`, with
the same value as the association's `issuer`. For a delegated child, a
delegation or trusted pin must authenticate that exact child's pair.
An ancestor or configured default cannot serve as a fallback. Compare
the association to the authenticated pair and current domain
controller epoch. Issuer associations carry only the stable issuer
identity and origin as their target. A domain changes the association
when it changes registry. It can re-sign the same association after a
namespace-controller rotation.

At the issuer's own exact `_awid` TXT name, the record carries
`awid=v1; controller=<did:key>; registry=<origin>; standing_key_set_sha256=<digest>;`.
Resolve the pair's exact issuer name independently. Trust the key set
only if the issuer and origin match both discovery results, the issuer
DNS controller verifies the signature, and the digest equals the
`standing_key_set_sha256` commitment. A trusted explicit pin can supply
those same authenticated fields and observation bounds. A missing or
ambiguous commitment, digest mismatch, stale answer or failed authority
read leaves the issuer unavailable. Retry via the original authority.
Never switch origins or accept a registry-supplied replacement digest.
Stage a key set at its digest before pointing discovery at it.

`keys` is an object with exactly these entries:
`standing_statement`, `exact_request_evidence`, `feed_barrier`,
`feed_snapshot`, `feed_era_transition`, `namespace_read`.
Each value has `key_id` and `did_key`. Reject duplicate IDs or public key
material across purposes. Require exactly one key per purpose and no
rollover overlap. A replaced key immediately loses current-evidence use
when the new set is applied. Previously admitted effects can finish.
Retain the last verified feed prefix and live denies. Obtain a fresh
barrier under the new key before admitting again. Validated historical
prefix evidence remains useful for continuity and cannot supply current
freshness. Resync via a current signed snapshot when needed. Replace
outstanding statements signed by a replaced proof key using the
issuance recovery capacity in the standing design.

Cap the lifetime of a verified issuer discovery observation at
**30 seconds**, and cap it further by the authenticated DNS answer's
remaining TTL or the explicit pin's validity. Use an authenticated
fresh authority read. A bare cached RRset without authenticated freshness
is insufficient for this bound. Publish the DNS record
with a TTL at most 30 seconds. Measure the lifetime from the original
discovery observation. Cached answers must preserve their original
refresh bound. A retry, signed feed point or key-set read cannot extend
it. If a resolver cannot establish remaining freshness or serves stale
answers, fail closed. A verifier with a warm pin can trust a withdrawn
key for at most 30 seconds after the withdrawal is visible at the
authoritative discovery service. Measure publication delay separately.
After a verified withdrawal, discard the previous active pins
immediately. A refresh outage at the bound refuses new effects.

## 3. Organisation definition and continuity

Use `awid.organisation-opening/1` + LF + canonical JSON to compute
`definition_sha256`. The private opening has `admin_team_id`,
`team_incarnation`, `manifest_sha256` and `salt`. The registry assigns
`team_incarnation` as an opaque canonical lowercase UUID. It allocates
a new value on each creation and durably reserves prior values so that
delete-and-recreate cannot reuse one. A team key change within an
incarnation leaves it unchanged.

Compute `manifest_sha256` from `awid.bootstrap-manifest/1` + LF + its
canonical JSON. The manifest fields are `domain`, `controller_epoch`,
`registry_origin`, `service_origin`, `audience`, `nonce`,
`teams`, `admin_team_id`, `admin_team_incarnation`,
`first_admin_subject`, `instruction_id`, `not_before` and
`expires_at`. Each `teams` element has `team_id`, `did_key` and
`team_incarnation`, sorted by `team_id` without duplicates. The
`instruction_id` is a lowercase UUID, the `audience` is the exact
canonical pilot service ID, and `first_admin_subject` is the canonical
global DID of the first admin for the E5 bootstrap. Verify the
opening, the manifest digest and the exact matching designation and
current incarnation during staging and activation. Store the opening with
its head in the same transaction. The controller shares the manifest
and opening privately with the intended pilot. The public read exposes
the signed head and its signed currentness response.

In a verified continuity rotation the successor republishes the head at
revision + 1 under the successor and new epoch, with `previous` equal
to the predecessor digest and the identical `definition_sha256`.
O13b can compute its expected digest before the ceremony. Promotion
requires the existing exact rotation evidence and fresh observations.
An unchanged commitment supplies opening continuity. A changed
commitment follows the operator path. After a takeover, continue the
chain from the last retained head at revision + 1. A recovery read can
return that retained opening to the current controller. Only the new
epoch's authorised controller can publish the new current head.
Takeover and definition changes require operator reconciliation even
when the old commitment is repeated.

## 4. Currentness and private read authority

Current read observations use purpose `awid.namespace-read/1` and the
pinned `namespace_read` key. Sign only from a committed, consistent
registry read. All observations include `issuer`, `registry_origin`,
`kind`, `domain`, `controller_epoch`, a request `nonce`,
`observed_at` and exclusive `expires_at`. The lifetime is at most 30
seconds. Enforce the standing design's clock bound and original
expiry after the last wait. A replay for another nonce, scope or
read kind is unusable. A worker can reuse its own successful observation
until its original expiry. Network reads stay off the serving request
path.

For `kind` equal to `organisation_head` or `standing_issuer`, include
`state`, `revision` and `record_sha256`. State is `present` or
`absent`. Present carries the exact current committed record and its
digest, and the response also returns the controller-signed `record`
envelope. Absent is possible for a committed open namespace with no
current record and carries null revision and digest. Failure to establish
the epoch, scope or current read returns authority unavailable and no
signed absence. A record signature alone proves authorship. The pilot
pins `record_sha256`, the same digest used by `previous`. Verify the
observation, controller signature, scope and digest together. Rollback or
conflicting evidence on a known pin needs reconciliation. A verified
current different head counts as a custody mismatch under its gate.

A current namespace controller registers a read grant under
`awid.incarnation-read-grant/1`. Exact fields are `domain`,
`registry_origin`, `controller_epoch`, `grant_id`, `team_id`,
`definition_sha256`, `reader_did_key`, `not_before` and `expires_at`.
`grant_id` is a nonreusable UUID. A grant names one team and one worker
key. It can be revoked by the current controller. At registration,
verify that team against the private current designation. Before each
read, verify the live grant and exact scope against committed state.
Continuity republish can carry a live grant across a verified rotation
with the same definition commitment. Takeover or a changed definition
invalidates it. A grant gives no signing, write, roster or opening access.
Service tokens and bearer use give no access.

A worker signs `awid.incarnation-read-request/1` with the grant's
`reader_did_key`. Exact fields are `domain`, `registry_origin`,
`grant_id`, `team_id`, `expected_incarnation`, `nonce` and
`expires_at`. Accept only a live, exact-scope request with at most
30 seconds of remaining validity. Match the expected incarnation to
the committed private designation. Cap the observation expiry by the
request and grant expiry. For `kind=team_incarnation` the signed
response additionally includes `grant_id`, `team_id`,
`expected_incarnation`, `current_incarnation` and `state`.
State is `current` for equality, `different` for a verified current
different value, or `absent` with null current incarnation for confirmed
absence. Do not reject a grant merely because the live team incarnation
differs from the expected incarnation. This is the case the custody
gate must see and freeze on. Failed, expired, absent or out-of-scope
evidence refuses without freezing. This read never returns the roster,
key, bootstrap instruction or opening.

## 5. Registry routes and controller commands

Put each typed canonical object in its signed envelope. Mutations use
the exact signed controller request in addition to the object
signature. Each PUT body has `record` containing the signed envelope.
Organisation publication adds the private `opening` object. Public reads
take a fresh 32-byte `nonce` query parameter. Registry observations are
returned as an `observation` envelope, with `record` present only for a
present namespace head or association. An unavailable authority read
returns HTTP 503 with `authority_unavailable` and no observation.
Opening reads use a fresh covering namespace-controller request with
`mode` equal to `current` or `recovery`, and return `record` and
`opening`. The proof-of-possession incarnation route takes a signed
`request` envelope and returns only `observation`. Its private response
is never publicly cached. Read grants belong to the controller.

| Method and path | Effect |
| --- | --- |
| `PUT /v1/namespaces/{domain}/standing-issuer` | Publish the issuer association. |
| `GET /v1/namespaces/{domain}/standing-issuer?nonce={nonce}` | Read the association and signed currentness. |
| `PUT /v1/namespaces/{domain}/organisation-head` | Publish the head with its private `opening` alongside the `record` envelope. |
| `GET /v1/namespaces/{domain}/organisation-head?nonce={nonce}` | Read the public head and signed currentness. |
| `POST /v1/namespaces/{domain}/organisation-opening:read` | Current controller reads the private opening using body `mode`. |
| `PUT /v1/standing/issuers/{issuer}/key-sets/{digest}` | Issuer domain controller stages the exact signed key set by digest. |
| `GET /v1/standing/issuers/{issuer}/key-sets/{digest}` | Read the exact staged key set. The independent TXT digest selects the trusted set. |
| `PUT /v1/namespaces/{domain}/incarnation-read-grants/{grant_id}` | Register the signed worker grant. |
| `DELETE /v1/namespaces/{domain}/incarnation-read-grants/{grant_id}` | Revoke the grant, including across allowed continuity rotations. |
| `POST /v1/namespaces/{domain}/team-incarnation:read` | Worker submits the signed request and receives a signed private observation. |

The standing client's controller commands reuse the typed namespace
controller signing path. The binary name `aweb` is provisional.
`--registry` must match authenticated discovery. Publication accepts
exact JSON input, verifies scope and produces the canonical signed
object. Private files are local inputs.

```text
aweb id namespace standing-issuer publish --domain D --registry ORIGIN --input FILE --json
aweb id namespace organisation-head publish --domain D --registry ORIGIN --input FILE --opening FILE --json
aweb id namespace organisation-head read-opening --domain D --registry ORIGIN --mode current|recovery --json
aweb id namespace standing-key-set publish --domain ISSUER --registry ORIGIN --input FILE --json
aweb id namespace incarnation-read-grant issue --domain D --registry ORIGIN --input FILE --json
aweb id namespace incarnation-read-grant revoke --domain D --registry ORIGIN --grant-id UUID --json
```

## 6. Conformance

- Check byte vectors, wrong purpose, origin, controller and epoch,
  CAS conflict beside exact retry, and loss of discovery with no fallback.
- Rotate the registry key set once for two unrelated namespaces. Both
  adopt it with unchanged association and organisation heads. Refuse
  same-key reuse and missing or overlapping purpose slots. Exercise
  mismatched digest, cold withdrawal and warm withdrawal at the exact
  freshness bound, including a stale resolver answer.
- Refuse stale public heads, wrong nonces and signed absence substituted
  for an unavailable read. Confirm the digest equality to the CAS and
  pin. Verify the public surface exposes no private opening or team.
- Exercise the assigned worker without controller custody and a wrong
  reader or team, revoked grant and expired observation. Recreate the
  team with the same name and key and sign the different incarnation.
  Refuse missing and out-of-scope evidence. Test staging, holderless
  custody lanes and expiry after the last lock wait.
- Confirm continuity republish and grant carry with an identical
  commitment. Refuse auto-promotion on a changed commitment or takeover.
  Verify the new controller can read the retained recovery target
  without the old team key.
