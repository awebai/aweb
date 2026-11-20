# P8: portable presence approval

Status: the Go verifiers in `awid` below are the implementation, and only their
tests call them. The Python copy, `aweb.human_channels.presence`, was removed
because nothing in aweb or aweb Cloud called it.

The public Go library verifies the P0 presence records. They do not
create an OSS presence registry, operate bots, store generations, suppress
messages or change author verification. There is no migration or new OSS HTTP
route. Cloud/self-hosting operators own authenticated endpoints and resource,
consent, lifecycle and delivery policy. P0's signed wire DTOs remain unchanged.

Native suppression and shared/dedicated binding approval have separate verifiers,
signed versions and ownership-proof purposes. A token, team-admin role or claimed
owner cannot replace the actor's signature or a current, independently pinned
owner binding. See the [decided authority rule](human-channels-contract-proposal.md#native-registration-and-ownership-changes)
and [P0 records](human-channels-contract-v1.md#presence-and-native-operation-records).

## Public entry points

| Purpose | Go `awid` |
| --- | --- |
| Sign one presence intent/proof | `SignHumanChannelsPresenceRecord(record, privateKey)` |
| Verify native suppression approval | `VerifyHumanChannelsNativePresence(artifact, context)` |
| Verify shared/dedicated binding approval | `VerifyHumanChannelsPresenceBinding(artifact, context)` |

Inputs/outputs use P0 `HumanChannelsRecord` and `SignedArtifact`.
Signing accepts only PresenceIntent, PresenceBindingIntent, OwnershipProof and
BindingOwnershipProof. The supplied key must match `signing_key_id`; signing
alone makes no assertion that the identity/key/owner is current. Signing takes
an `ed25519.PrivateKey`.

## Trusted verification context

`PresenceVerificationContext` / `HumanChannelsPresenceContext` are **in-process
host facts, not wire DTOs**. Never deserialize them from a request or accept the
submitted proof as its own authority pin. The host supplies:

- exact typed subject, active/access status, platform, scope, mode and configured
  service audience, plus its current combined authorization revision;
- the native subject's independently resolved current principal/key when that
  lane is used; local authorized context and global registry/key continuity are
  distinct sources, and missing authority is not inferred from a DID string;
- authenticated caller identity/current key, authorization for this exact action
  under current user/org/resource/consent policy, and the actual session-grant
  scopes/expiry when present;
- `expected_intent_hash`, SHA256 of the exact canonical typed intent the host's
  action decision covered; compute it from `canonical_record(intent)` after
  parsing, not from a submitted hash;
- current per-(subject, platform, scope) generation, consumed request IDs
  across native/binding families (an exact lookup of this request ID is sufficient;
  no historical ledger enumeration is required), a current trusted clock, explicit maximum
  intent/proof TTL and maximum future clock skew;
- for binding approval, the blinded `binding_digest` of the private resource
  actually authorized, independently matched to the signed intent;
- for the owner lane, `PresenceOwnershipPin` /
  `HumanChannelsPresenceOwnershipPin`: the exact subject/service, current owner
  principal/key, separately configured proof issuer principal/key and current
  ownership authorization revision. Missing owner, issuer, key or revision
  refuses; route discovery or the proof's signer cannot supply the pin. The
  configured issuer must differ from the owner in both principal and current
  signing key; self-issued ownership authority refuses as `authority_unavailable`.

The caller must act as the signed subject or owner, using its current identity
binding (stable principal or its verified current key). An unrelated authenticated
caller cannot relay an approval through this port. A Cloud browser owner operation
uses its authenticated owner actor and actual custody path to sign the owner
intent. No ownership issuer convention is invented by P8; Cloud must configure,
issue and test that authority before enabling its owner lane. Bridged subjects
have no native subject-signing lane; their separately authorized owner/bridge
lane remains confined to the configured subject/service/provider policy.

A session grant must include `presence.write`, remain live and accompany the
actual subject/owner-signed intent. Its session key cannot substitute for the
root identity signature. A mail-only grant refuses even if it presents a valid
root-signed intent.

All inputs must match their exact target, purpose and current authority. The
verifier checks canonical original bytes, key/signature, freshness, generation,
consumed request ID and exact ownership-proof scope/mode/operations/revision.
An owner-authorized intent without its ownership proof refuses as `invalid` in
both languages; optional schema placement does not authorize omission in that lane.
Owner proof expiry and caller grant expiry shorten the result's deadline.
Expired or stale proof cannot be promoted by the longer lifetime of its intent.
No private key, external account identifier or credential appears in a verified result.

Platform-wide native scope is the initial policy. Session-scoped native intents
refuse unless the host explicitly enables its approved scoped policy through
`allow_scoped_native` / `AllowScopedNative`. That is host configuration, never
an intent field or inference from platform observations or online status.

## Applying a verified result

Success returns P0 VerifiedPresence or VerifiedPresenceBinding with exact
operation/target/request ID, original intent hash, checked authorization revision,
expected generation and bounded expiry; binding results retain the exact digest.
This is a checked snapshot, not a bearer capability or a mutation receipt.

Cloud must recheck the deadline/current rights/revision and atomically CAS the
persistent generation, claim the cross-family request ID and apply its private
resource change. Preserve generation tombstones across remove/unbind/delete;
never derive a public generation from an inert C1 row revision. If a concurrent
change wins, refresh/recompose rather than applying a stale snapshot. The library
rejects an already consumed ID; authorized exact-result recovery comes from the
host's original committed result and never reactivates a removed registration.

For native subject/owner actors, Python embeddings use
`aweb.human_channels.authority.lock_native_actors(db_infra, connection, expected)`
inside that host transaction. `db_infra` is the initialized OSS database
infrastructure; `connection` is the host's already-open asyncpg transaction
connection (for pgdbm, `tx.connection`). `expected` is a nonempty sequence of
immutable `NativeMessagingSubject(principal, signing_key_id, actor_id, team_id)`
references with all four fields populated from independently authorized facts.
These are exact actor bindings, not aliases to discover or claims from an intent.

The primitive acquires actor row locks in actor-ID order, rechecks active and
non-deleted state and exact team/principal/current verified signing-key bindings,
and returns an immutable tuple of checked bindings in input order. Missing or
inactive/deleted actors refuse as `forbidden`; changed or unverified bindings
refuse as `stale`. An absent transaction or incomplete reference refuses as
`invalid`. It performs no network I/O, opens/commits no transaction and requires
no prepared send or message. It adds no wire record, HTTP route or migration.
Locks last through the host's outer commit/rollback; do not release a savepoint
and reuse returned facts after rollback.

Resolve external authority before taking locks. On the same connection, lock and
recheck the host's account/session/link/consent/ownership/custody authority first,
then call `lock_native_actors`, compose the presence context using those checked
identity facts, run the portable verifier and apply the host's generation/request
CAS. Keep this host-authority-before-actor order consistent with native message
acceptance. A refusal aborts the host mutation; do not catch it and commit a
partial activation. The helper supplies projection stability, not permission or
custody: it cannot replace the caller, owner/issuer, grant or consent checks above.

For a global identity, these locks freeze **only the OSS actor projection**,
including its verified principal/key binding. Independently current AWID key
verification is still required; the OSS transaction does not lock the remote
registry or make a remote rotation atomic with the host's database commit.

Cloud separately proves the exact platform resource/intake and its owner. Neither
this verifier nor a valid intent proves bot-token ownership. Native registration
wins overlapping relay scopes; unhealthy native transport produces visible
`native_unavailable`, not removal or shared-bot fallback. There is no health
input capable of authorizing a mutation here. Those operational suppression,
handover, replay-storage and platform journeys remain C2/N integration work.

Failures use P0 ContractError / HumanChannelsContractError: invalid shape/signature,
unsupported purpose/policy, forbidden identity/target/action, stale
key/generation/revision/freshness, replay_conflict, or authority_unavailable.
The hosting endpoint maps the code into P0's presence family/HTTP response and
logs its precise diagnostic field without exposing credentials. No refusal has
presence, messaging, wake or usage effects in this stateless library.

## Evidence and remaining integration

Both languages consume [the same signed cases](vectors/human-channels-presence-v1.json).
They cover local/global and rotated key neighbors; distinct owner and guest-owner
lanes; native/shared/dedicated purposes; wrong actor/admin/token-owner context,
missing/self-pinned/expired owner authority, cross-purpose proof misuse,
stale generation, cross-family replay, audience, consent policy, invalid
signatures, canonical bytes, grant restrictions and exact private binding digest.
No P0 or released native signing/encryption vector is re-frozen.

Actual Cloud owner issuance/pins, lifecycle storage/CAS, consent and
bot-resource operations must pass C2 acceptance using these published types.
The public library needs no Cloud tables, token or private endpoint, and does
not claim C2-D-ready.
