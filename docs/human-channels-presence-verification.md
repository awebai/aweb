# P8: portable presence approval

The public Python and Go libraries verify the P0 presence records. They do not
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

| Purpose | Python `aweb.human_channels.presence` | Go `awid` |
| --- | --- | --- |
| Sign one presence intent/proof | `sign_presence_record(record, signing_key)` | `SignHumanChannelsPresenceRecord(record, privateKey)` |
| Verify native suppression approval | `verify_native_presence(artifact, context)` | `VerifyHumanChannelsNativePresence(artifact, context)` |
| Verify shared/dedicated binding approval | `verify_presence_binding(artifact, context)` | `VerifyHumanChannelsPresenceBinding(artifact, context)` |
| Implement P0's two embedding ports | `PresenceVerifier(provider)` | Compose the two portable verifiers with the host's authenticated service |

Inputs/outputs use P0 `ContractRecord` / `HumanChannelsRecord` and `SignedArtifact`.
Signing accepts only PresenceIntent, PresenceBindingIntent, OwnershipProof and
BindingOwnershipProof. The supplied key must match `signing_key_id`; signing
alone makes no assertion that the identity/key/owner is current. Python takes
the existing 32-byte Ed25519 seed form; Go takes `ed25519.PrivateKey`.

Python's `PresenceVerifier` calls an embedding's
`PresenceContextProvider.resolve(auth, intent)` with existing, already verified
`MessagingAuth` and the closed, typed intent. It snapshots the artifact before
awaiting authority, checks returned caller/grant facts against that actual auth,
then calls the same portable verifier. Returning a context for another principal
or silently dropping a session grant refuses. The provider is read-only and receives untrusted
intent data to resolve; it must not authorize merely because the signature fields
name an actor or issuer. No private schema access is part of these interfaces.

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
root-signed intent. The Python port also prevents a host provider from hiding
that grant in a purported root caller context.

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

The focused Python host integration starts actual OSS HTTP/AWID/PG/Redis,
registers disposable identities through public AWID, resolves their current keys,
and receives real Go-signed HTTP requests. Go's public signer and authenticated
client call an embedding fixture that uses real request auth and the public
Python port. Local, global subject and configured-owner requests pass, including
the new current key after a public registry rotation. Unrelated authenticated
teammates, freshly signed stale generations, a wrong configured owner pin and
the non-current key refuse with the expected presence code and diagnostic field.
The fixture's action policy permits the unrelated teammate, so the verifier's
signer binding must enforce that refusal. A separate test ensures
caller-retained input mutation across the authority await cannot change the
operation whose context was authorized.

The fixture is an example host adapter, **not deployed Cloud C2**. Actual Cloud
owner issuance/pins, lifecycle storage/CAS, consent and bot-resource operations
must pass C2 acceptance using these published types. The public libraries need
no Cloud tables, token or private endpoint, and do not claim C2-D-ready.
