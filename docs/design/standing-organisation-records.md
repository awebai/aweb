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
| `awid.standing-key-set/1` | `issuer`, `registry_origin`, `controller_epoch`, `revision`, `previous`, `feed_id`, `keys`, `verify_only` |

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

Read the exact domain and issuer TXT records through configured
DNSSEC-validating DNS-over-HTTPS resolvers. Authenticate each configured
resolver by its HTTPS origin and TLS certificate. Require the resolver's
authenticated-data (AD) indication for the exact answer. The resolver
validates DNSSEC from its configured root trust anchor and is trusted for
freshness, remaining TTL and cache handling. Disable serve-stale and
deduct any HTTP cache age from the DNS TTL. A network attacker between
the verifier and the trusted resolver cannot substitute or replay a TXT
answer over that TLS connection. DNSSEC authenticates the RRset and
does not establish 30-second freshness by itself. A resolver that
accepts upstream replay of a still-signed old RRset violates the
freshness assumption. An unavailable trusted read fails closed.
[DNSSEC trust and replay limits](https://www.rfc-editor.org/rfc/rfc4033.html#section-8)
[DoH TTL and HTTP age](https://www.rfc-editor.org/rfc/rfc8484.html#section-5.1)

`keys` is an object with exactly these entries:
`standing_statement`, `exact_request_evidence`, `feed_barrier`,
`feed_snapshot`, `feed_era_transition`, `namespace_read`.
Each value has `key_id` and `did_key`. The two proof-key entries also
have `valid_from`, the earliest signed observation time accepted for
that key. Require one current key per purpose. Reject duplicate IDs
or public key material anywhere in the current or verify-only entries.

For scheduled rotation, `verify_only` can name the previous key for
`standing_statement` or `exact_request_evidence`. The object is empty
when there is no carryover. Each entry has `key_id`, `did_key` and
exclusive `signed_before`. At introduction, `signed_before` equals the
new current key's `valid_from`. Carry the cutoff unchanged until it is
removed. Accept old evidence only for its original purpose, with a
signed observation time strictly before that cutoff, and until its
original expiry within the purpose's lifetime limit. An ordinary
statement can remain valid for at most 30 minutes. A verify-only entry
gives no issuance authority and cannot verify barriers, snapshots,
era transitions or namespace reads.

Publish a scheduled proof-key set to authoritative discovery at least
one full 30-second discovery window before `valid_from`. The predecessor
set covers issuance only up to that time. Issue with the new key from
`valid_from`. Verifiers that learn the new set early can still check
pre-cutoff evidence during the publication window. Schedule the next
rotation of that purpose once the previous verify-only window has ended.
An emergency withdrawal removes the affected key from both objects.
Apply the removal when the replacement set is verified and reject
outstanding evidence under the withdrawn key, even if unexpired.
Previously admitted effects can finish. Replace withdrawn proof evidence
using the issuance recovery capacity in the standing design.

Barrier keys have no verify-only entry. On a barrier-key change, retain
the verified feed prefix and live denies. Obtain a fresh barrier under
the new key before admitting again. Publish that barrier within the
five-second cadence. Historical prefix evidence supports continuity.
For current freshness use the active key, with a current signed snapshot
to resynchronise when needed.

Cap the lifetime of a verified issuer discovery observation at
**30 seconds**, and cap it further by the authenticated DNS answer's
remaining TTL or the explicit pin's validity. Publish the DNS record
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
Ed25519 `did:key` of the first admin's signing key. In O0, that admin
is the local root agent. Match the first certificate's subject to
that exact `did:key` and require proof of possession of the key.
Verify the opening, the manifest digest and the exact matching
designation and current incarnation during staging and activation.
Store the opening with its head in the same transaction. The controller
shares the manifest and opening privately with the intended pilot.
The public read exposes the signed head and its signed currentness
response.

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
differs from the expected incarnation. At an active organisation's
custody gate, a fresh, verified `different` or `absent` for the pinned
team on unchanged pins freezes. Staging and activation require
`current`. Failed, expired or out-of-scope evidence, or no evidence,
refuses without freezing. This read never returns the roster, key,
bootstrap instruction or opening.

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
Use it for all E5 bootstrap commands, including namespace, team,
root exchange and team-server operations.
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
  same-key reuse and missing or overlapping current purpose slots.
  Exercise a mismatched digest, unauthenticated resolver response,
  exhausted TTL after HTTP cache age, a stale answer and cold and warm
  withdrawal at the exact freshness bound.
- Hold a valid statement and exact-request proof through a scheduled
  rotation. After the switch, accept prior-key proofs observed before
  the cutoff until their original expiry. Refuse evidence observed at or after the
  cutoff, verify-only keys used for another purpose, and the same
  earlier evidence after withdrawal. Test acquisition of a fresh barrier
  without using the former barrier key for current freshness.
- Refuse stale public heads, wrong nonces and signed absence substituted
  for an unavailable read. Confirm the digest equality to the CAS and
  pin. Verify the public surface exposes no private opening or team.
- Exercise the assigned worker without controller custody and a wrong
  reader or team, revoked grant and expired observation. Recreate the
  team with the same name and key and sign the different incarnation.
  Exercise a pinned team that was deleted and returns a signed
  `absent`, beside an unavailable read. Test active and holderless
  custody lanes, staging and activation, and expiry after the last
  lock wait.
- Accept the local root agent's exact `did:key` and proof of
  possession. Refuse a global DID, a different certificate subject or
  proof made with another signing key.
- Confirm continuity republish and grant carry with an identical
  commitment. Refuse auto-promotion on a changed commitment or takeover.
  Verify the new controller can read the retained recovery target
  without the old team key.

### Credential-free sentinel

The operator supplies the sentinel with the expected controller and epoch,
head and issuer pins, and one known certificate ID for each watched team.
The watch list and approval record live outside worker custody. The
sentinel verifies public DNS and registry evidence and polls on a bounded
schedule, including when the feed is idle. Feed handles alone do not
identify a namespace or team.

The E5 issuer retains the [anonymous exact certificate status
read](../awid-sot.md#teams), including for private teams. Given the
known team and certificate ID, its response names that team's current key.
An unexpected key or certificate-status change, or loss of the known
status read, alerts. The public
organisation head continues to hide the team and the opening. The worker's
incarnation read still uses its own scoped grant under §4.

Run these cases against the real registry without a sentinel credential.
Include the expected unchanged and operator-approved neighbours.

- An unapproved controller rotation changes the observed controller or
  epoch. A planned head revision that remains unpublished at its approved
  deadline, and a published revision the operator did not approve, each
  produce an alert.
- An issuer key-set change is detected through the authenticated issuer DNS
  commitment and the digest-bound key set. A planned rollover is checked
  against the operator's record.
- Re-key a watched private team without changing its namespace epoch or
  head. The exact anonymous certificate status read changes its current
  key and the sentinel alerts. A watched certificate changing from
  active to revoked also alerts. Delete and recreate the team without
  the watched certificate. Its 404 also alerts. Private team
  enumeration remains restricted.
- An unexplained feed gap, or an era change without a verified resync,
  alerts as lost feed coverage. A verified resync and contiguous tail
  restore coverage.

Previously unknown private teams and new grants can appear without a
matching negative handle. The separate namespace inventory work (D4)
addresses registry-visible additions. A root certificate for a local agent
is holder-carried. Issuing it alone leaves no registry record to inventory.
