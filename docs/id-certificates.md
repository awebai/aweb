# Identity certificates v1

Status: **contract candidate; docs and vectors before implementation**.
[`vectors/id-certificates-v1.json`](vectors/id-certificates-v1.json) freezes the
bytes and decisions below. This is the source of truth for the identity tree;
it supersedes [member attribution](member-attribution.md), not existing team
certificates, `member_person`, `member_custody`, owner acts or membership auth.
The identity-path change was approved on 2026-10-26: a namespace admits human
and agent identities, humans can issue humans, and local agents need no registry
registration. This document enables no new authority until implemented.

## 1. What the tree proves

An identity has a key, an ID and a parent-signed certificate. The DNS namespace
root admits its first identities; a human can issue humans or agents; an agent
can issue agents. For an agent, its nearest human ancestor answers for it. A
human ID means **one natural person**, never a shared account. Its issuer vouches
for that claim. How a domain admits its first human is the domain's own process,
outside this protocol: there is no email-validation, SMTP or person-attestation
ceremony here. DNS control and a valid signature do not independently prove
natural personhood or a fresh human gesture for each descendant's action.

A team certificate says who coordinates. An ID certificate says who answers.
The namespace root key, team controller key and identity key are different
authorities even if an operator holds more than one. ID issuance does not admit
anyone to a team, assign an org role, allocate a seat, authorize a channel binding
or confer key custody. A human ID can hold ordinary team certificates and sign
messages and tasks as itself. It is reusable across teams and same-domain orgs
without new keys, a new ID certificate or re-parenting. For a human leaf, the
responsible-human result is that human itself, not its inviter.

Human keys are held by the CLI user's OS keychain or a custodial server acting
for a checked logged-in human session. They never live in an agent home, `.aw`,
agent-readable file or environment variable. There is no extra login for an
owned agent's spawn. Hosted namespaces may use hosted root authority. In v1 a
customer's custom-domain controller key stays with that customer's controller;
Cloud does not take custody of it. The customer signs the first human from the
CLI; a custodial deployment can hold subsequent human keys.

## 2. Certificate and exact bytes

Every field is required. Unknown fields, duplicate JSON keys, floats, invalid
Unicode, wrong types and defaulted/omitted fields refuse. An ID certificate is:

```json
{
  "v": 1,
  "type": "aweb.id-certificate",
  "id": "did:aw:...",
  "domain": "example.com",
  "parent": {"kind": "namespace", "id": "example.com"},
  "kind": "human",
  "issuer_key": "did:key:...",
  "issued_at": "2026-10-26T00:00:00Z"
}
```

- `id` is a canonical existing `did:aw` or Ed25519 `did:key`. A human always has
  a registered `did:aw`. An unregistered local agent uses its `did:key` as ID;
  that ID cannot rotate. Global agents use registered `did:aw` IDs. No DID
  syntax changes and no address allocation are required by this certificate.
- `domain` is a canonical ASCII DNS name: lowercase A-labels, at most 253 bytes;
  labels are 1–63 ASCII letters/digits/hyphens, with no leading/trailing hyphen.
  No whitespace, trailing dot, empty label or automatic IDNA conversion. It is
  a signed field, not inferred from the domain-free `did:aw` or from a team.
- `parent` is exactly `{kind,id}`. `kind="namespace"` names this exact `domain`;
  `kind="identity"` names a canonical parent ID in the same domain. The former
  is resolved from the domain's `_awid` DNS authority and its registry history;
  the latter from the parent's certificate and key evidence. `issuer_key` is
  an Ed25519 `did:key`, a selector to verify, never independent authority.
- `kind` is exactly `human` or `agent`. `issued_at` is ASCII RFC 3339 UTC to the
  second with `Z`; it is informational, not an admission time witness.

```text
signing_bytes  = UTF8("aweb.id-certificate/1\n") || canonical_json(certificate)
signature      = base64url_no_padding(Ed25519(parent_key, signing_bytes))
signed         = {"certificate": certificate, "signature": signature}
certificate_id = "sha256:" || lowercase_hex(SHA256(signing_bytes))
```

The prefix ends with one LF. Canonical JSON is the existing signed-record
convention: recursively sort object keys, no whitespace, UTF-8, integers only,
no duplicate keys. Input carrying canonical bytes must equal its re-encoding.
Signatures decode to exactly 64 bytes and must re-encode identically; padding,
alternate alphabet or nonzero unused bits refuse. The `signed` wrapper has
exactly those two fields. Its digest identifies the immutable certificate
revision; signatures, team certs and message payloads are never folded into it.

Every verifier applies these rules on **every link**, independent of AWID's
admission verdict:

1. **R1:** a human's issuer is a namespace root or a verified human, never an
   agent. Agent issuers can issue only agents.
2. **R2:** signed kind and parent do not change within a certificate. A
   registered ID's kind and domain are fixed at its first enrollment. Changing
   its parent needs an explicit new certificate/head, never reconnect/import.
3. **R3:** every certificate's domain equals the chain root's domain. V1 has
   no cross-domain parent link. Membership in another domain's team does not
   change the identity tree. Existing controller-only address assignment stays
   separate: a human issuing a human cannot allocate a namespace address. If
   an address is offered as this ID's domain address, independently verify its
   ordinary namespace→ID binding; the address does not establish parentage.

An unregistered local key has one parent and kind for that key. Re-parenting
requires a new local key plus member certificate, or registered enrollment that
replaces the old local membership. Initial certification of a previously
chainless local key is not re-parenting. Explicit registered enrollment may
keep its private key and acquire a stable ID, without guessing its past. Local
descendants do not silently change their parent ID when that conversion occurs.

## 3. Registration, heads, rotation and revocation

Human and global IDs are valid in this tree only after AWID registration.
Local agent certificates are carried by their holder; they need no AWID insert
or witnessed issuance time. A root→agent chain is valid and means **no human**;
a missing certificate means **unknown**, not no human.

### Atomic registration and re-parenting

`POST /v1/id-certificates/register` on the domain's authoritative registry takes
exactly `{certificate,expected_head,invitation_id}`: `certificate` is the signed
wrapper, `expected_head` is null for first enrollment or the current digest,
and `invitation_id` is null or the canonical UUID of the pending invitation.
The caller proves possession of the subject's current key with the existing
request-bound DIDKey envelope over this exact method/path/body. The parent
signature authorizes issuance. A bare team key, org role, email, label or
client-supplied parent claim does not replace either proof.

The covering request uses the existing
[AWID request-binding envelope](awid-controller-requests.md): `v=2`,
`type="aweb.awid-controller-request"`, configured `aud`, uppercase method,
external raw path/query, exact body_sha256 and timestamp, plus exactly `domain`
and `operation="register_id_certificate"`. Authorization is the subject's
DIDKey signature, not team-certificate auth; the HTTP envelope name does not
make that subject a namespace/team controller. Issuance authority still comes
from the separately verified parent certificate signature. Revoke uses the
same covering family with `operation="revoke_id_certificate"` and the allowed
revoker's signature. Authenticated status reads use
`operation="read_id_certificate_status"`; anonymous status has no signature.
These new endpoints have no legacy envelope fallback. Register first verifies
subject key possession independently; it does not require its not-yet-registered
child certificate already to confer tree authority.

Register also carries `X-AWID-ID-Chain` with the full candidate chain; its leaf
must be byte-identical to the signed certificate in the body. The registry
retains the supporting public chain with the registered revision. A global
agent can have an unregistered local agent as parent: that parent's immutable
did:key is its key version, represented by issuer_key_seq=0. Retaining its
signed proof does not register that local identity or give it a registry head.

One AWID transaction serializes registration with parent/namespace rotation,
revocation and re-parenting. After its last lock wait it checks the full chain,
R1–R3, the subject's current key and non-revoked ID state, parent's live
state/current signing key,
cutoffs and expected head. It records witnessed `registered_at`, the exact
issuer key-version sequence, invitation ID and immutable signed bytes before
success. `registered_at` is assigned by AWID, never taken from `issued_at` or
a local signing time. Registry timestamps use fixed UTC microseconds
(`YYYY-MM-DDTHH:MM:SS.ffffffZ`); key-version sequences disambiguate a rotation
and admission at the same timestamp. No registration can authorize a signature
from a key already retired when it is registered.
Success returns exactly `{certificate_id,registered_at}`. It is a registration
receipt, not a current-authority result; verification still uses §4.

A byte-identical retry returns its original digest and registration time, even
after the head moves; it does not reactivate that revision. One invitation ID
can register one exact child certificate. Reuse for another child, parent,
domain or certificate refuses `invitation_conflict`; a new conflicting head
refuses `head_conflict`. Re-sign/rotation outside the original invitation uses
null invitation ID. Concurrent retries do not produce a second registration.
After authenticating the subject's request, resolve an exact existing receipt
before applying fresh-issuance checks: an accepted human invite remains an
accepted historical registration even if its inviter later rotates or is
revoked. Returning that receipt writes nothing and confers no current authority;
current validity always comes from status. A new or conflicting registration
still performs every live-parent check in the serialized transaction.

An explicit registered re-parent requires the new parent's signature, subject
key proof and expected-head CAS. It preserves ID, key and ordinary team
certificates when their member-key/team binding is unchanged. It supersedes
the old ID certificate without deleting it. Descendants naming that stable
parent use its current head for current agent authority; old evidence retains
its old parent/time and is not retroactively rewritten. An existing same-domain
human joining another org is membership only, not this operation.

### Key rotation and re-sign

An unregistered local child verifies against the parent's **current key**.
Parent rotation therefore makes its old-key certificate stale until re-signed.
On its next contact the child presents its old certificate and proves its own
key; the parent verifies the
old signature against its own verified key history and signs the **same
id/domain/parent/kind** with the current issuer key and a new issued_at. It must
not sign a request with a substituted ID or kind. The local child carries the
re-signed certificate. There is no job or silent fallback to an old signing key.

Every REGISTERED child, agent or human, uses the issuer key valid at its
witnessed registration. Its historic signature survives an ordinary parent
key rotation. Signature-key selection and cascade validity are separate:
an agent still needs a CURRENTLY valid parent; a human uses parent validity
at registration subject to effective_from. Existing DID continuity logs
authenticate identity key history; AWID additionally keeps
witnessed namespace-controller epochs instead of overwriting the only evidence
of an old root key. No pre-upgrade namespace history is guessed. A local
`did:key` parent cannot rotate in place; a different key is a different parent.

### Human key lifecycle and two machines

Routine rotation retains the did:aw through the existing old-key-signed
continuity log. Registered children retain their historic issuer-key witness;
unregistered children request re-sign on contact. Rotating a member's own key
still requires ordinary member-certificate reissue, as today.

The ONE v1 multi-machine method is an explicit password-encrypted export/import
of the SAME human Ed25519 key between OS keychains, using the established
encrypted PKCS#8 private-key format, not a new aweb backup protocol. Standard
[private-key serialization](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/#serialization-formats)
supports this encoding. A human invokes it interactively; passphrases never
appear in argv, environment or agent scripts. Cleartext key material stays in
memory; the encrypted backup is kept outside agent homes. Import compares its
public key with the current verified human key before installing it in the
second keychain. A wrong password/key refuses without replacing the existing
entry. It creates no new human, key, parent certificate or device-flow signer.
Rotation requires refreshing the other machine's keychain from a new encrypted
export; an old machine cannot keep signing as the current key.

Loss without the old key is replacement, not ordinary did:aw rotation. The
domain root or a valid parent admits an explicit replacement human ID, and the
address controller can reassign its address through the existing replacement
procedure. Kept registered agents re-parent to the replacement with the same
keys/team certificates. Kept local agents follow the one-parent-per-local-key
exception. Revoke the old human at now for loss, or let the root set an earlier
compromise cutoff. Earlier invited humans stand unless the cutoff catches
them. Old signatures/history keep the old ID. Address continuity does not
silently transfer pinned contact trust: retain the old contact/history and use
the existing explicit replacement/rebind procedure for the new ID. This does
not add root-authorized reset of an existing global DID's continuity log.

### Revocation authority and cascade

`POST /v1/id-certificates/revoke` takes exactly
`{domain,id,expected_head,effective_from}` and request-bound proof from the ID
itself, its current parent while that parent is valid, or the namespace root.
A team admin or unrelated human cannot revoke it. `effective_from=null` means
AWID's transaction time. Only the namespace root may supply an earlier cutoff;
a parent or the subject cannot backdate, and future cutoffs refuse. A Cloud
owner exercises root backdating only through the actual authorized namespace
signer; an owner role alone is not a portable revocation proof. Repeated revoke
is idempotent; only the root can move an existing cutoff earlier, never later.

Revocation is serialized with registration and has `revoked_at` plus
`effective_from`. An agent edge needs a currently valid parent, so revoking a
human ends their own agent subtree's current authority. A human→human edge
checks issuer validity at the child's registration: an earlier human invitee
survives ordinary inviter departure. A root's earlier compromise cutoff can
invalidate humans registered at/after it and their dependent agents. Equality
is refused: registration at the cutoff is not before it. The root→human edge
uses namespace authority valid at registration, not the latest root key.

Preview retained branches and re-parent them before offboarding/revoking their
human. Existing unregistered local members have no portable per-ID revocation:
revoking their team membership ends that team's authority, not every identity
use or descendant in other teams. To end that subtree's portable authority,
revoke its nearest registered ancestor or explicitly register/enroll it. Do not
claim that a local member revocation is a global ID revocation.

Org/team membership removal is a separate act: it ends that org's owner/role
authority immediately under the host's transaction and never revokes a human
ID shared with other orgs. Domain-ID offboarding uses the portable signer:
hosted operators sign with their namespace root for an authorized owner/admin
after the session check; a BYOT customer's controller signs from the CLI, not
from a dashboard-held custom-domain root. If the inviter has left, the root
signs. Retained branches must complete re-parenting before revoke; a partial
failure is reported and must not be advertised as completed preservation.
ID revocation is subject to the 60s/900s status bound, not instant worldwide
delivery. Current owner policy must still recheck membership/session/removal
in its own mutation transaction, including accepted removal with surviving
agent rows and a human who remains a member of another org.

## 4. One batch and the production cache

`POST /v1/id-certificates/status` takes exactly `{v:1,domain,ids}`, with 0–8
distinct registered-ID references; clients do not submit local
unregistered IDs for an enrollment check. An empty list requests only namespace
evidence for a root→local-agent chain. The response is a coherent snapshot:

```text
{
  v: 1, domain, observed_at,
  namespace: {epochs: [{seq, did_key, registered_at, retired_at}]},
  identities: [{
    id, current_certificate_id, current_key_seq,
    key_history: [{entry, registered_at}],
    certificates: [{signed, registered_at, superseded_at,
                    issuer_key_seq, invitation_id}],
    revocation: null | {revoked_at, effective_from}
  }],
  missing: [id]
}
```

This pseudocode fixes field names, not a second encoding: bodies use strict
JSON. All fields are required; `retired_at`/`superseded_at`/`invitation_id` may
be null; the other values have the types above. A proof-supporting LOCAL row,
if needed by a registered descendant, has current_certificate_id=null,
current_key_seq=0, empty key_history and revocation=null. Its certificate
entries have registered_at=null, superseded_at=null, issuer_key_seq=0 and
invitation_id=null. These are signed support bytes retained with the registered
descendant, not local registration witnesses. A fresh local re-sign presented
with the same id/domain/parent/kind can replace that old supporting proof for
current verification; its signature must pass the current-key rule. Old local
proof left stale after rotation yields unknown, not automatic re-signing.
Human/global rows must have nonnull registration/head evidence.
`entry` is an existing complete
DID-log evidence object (seq, operation, previous_did_key, new_did_key,
prev_entry_hash, entry_hash, state_hash, authorized_by, signature, timestamp).
Verify that log from its genesis ID/key or an independently verified checkpoint;
never pin a key merely because a server returned it. Its registered_at is the
registry's witness of the epoch, not the log's caller-signed timestamp.
Namespace epochs have positive increasing sequence numbers and verified DNS
authority at their witnessed time. Namespace history/time witnesses come from
the registry independently selected through DNS, not an agent-supplied URL.

Each certificate entry's digest is recomputed from `signed`. Heads and history
must be unique, ordered, nonoverlapping and consistent with current_certificate_id;
key versions must exist and agree with issuer_key. Human admission uses the
recorded issuer_key_seq, not a key chosen by signed issued_at. For historical
human-parent evaluation the response includes the required historic ancestor
certificates/status as well; identities therefore includes the bounded proof
closure, not only the requested list. No extra round trip per link. Limit the
entire uncompressed response to 131072 bytes; incomplete, contradictory,
over-depth or over-limit evidence means unavailable, never a partial success.
`missing` is an explicit unknown-registration result. Invitation/email/account
details, secrets and a human directory are not exposed by this endpoint.

Use the existing per-caller rate limiter under the operation
`id_certificate_status`: default 60 requests per minute for a verified caller
key, or source IP for anonymous callers. A submitted ID is not caller identity;
limit before expensive history/proof work and return 429 without partial
evidence. The normal deployment rate-limit configuration may size this bucket
for its callers; no unlimited anonymous/trusted-service bypass is added.
There is no list, prefix, search or pagination operation for a domain's humans.
Only exact requested IDs and proof-necessary ancestor/key history are returned,
never team memberships, private certificate blobs, email/account mappings or
mail/task bodies. Private-team gates remain at their existing boundary; a
public ID chain or status response grants no private-team read authority.

The response is authority evidence only when obtained from the authoritative
registry by the production **cached** client. An arbitrary body presented by an
agent is not a registry witness. This does not delegate R1–R3 or signature
verification to AWID. An offline bundle needs the same independently obtained,
freshness-bounded status/namespace/key evidence as online verification.

**R-1 (F-19):** every per-request authority path uses the production cached
status client, including team, identity-only, grant, naapp and hook consumers.
Pure verification takes already trusted facts; it never performs its own live
HTTP read. Implementations/reviewers trace the class production builds, not
just a test wrapper. Reuse complete evidence to age **60 seconds inclusive**;
then synchronously refresh through that client. If refresh fails, reuse only
last-known-good evidence to age **900 seconds inclusive**, with an explicit
stale/outage indication. Past 900s, with no prior evidence, or with invalid
evidence, authority fails closed and display reports unknown/unavailable. Grace
does not restart on a failed fetch or process restart; a local trusted fetch
time measures age. Do not mix fresh and stale fragments to manufacture a valid
chain or an uncached network dependency on every request.

## 5. Presentation, binding and verification result

The bundle is exactly `{v:1,type:"aweb.id-chain",certificates:[signed,...]}`,
ordered namespace child first and authenticated leaf last. No duplicate IDs,
cycles, omitted intermediate, unrelated link or repeated certificate. Maximum
**8 certificates**, counting humans and agents, excluding the DNS root.
Canonical decoded UTF-8 JSON is at most **6144 bytes**. The request header
`X-AWID-ID-Chain` is its strict base64url-without-padding encoding, at most
**8192 ASCII bytes**. Check encoded size before decode and decoded size/depth
before cryptography. Response/message metadata `id_chain` carries that same
JSON object and cap. Do not embed it inside the old team certificate or signed
mail/chat/E2EE bytes; those formats remain unchanged.

Verify the original authentication first. A local leaf's id equals the
authenticated subject's did:key. A global leaf must resolve through verified
DID continuity to that current did:key. If a team cert supplies member_did_aw,
it must equal that leaf id and its member_did_key must equal the authenticated
key. If it supplies only member_did_key, match that key without promoting the
local certificate into a different auth lane. A human chain does not supply
missing team membership, audience, signature or grant scope.

The header is allowed on team auth, identity-only auth and grant auth. A grant
is the same identity acting through a constrained session key, not a child:
bind to the independently verified grant SUBJECT ID/key, not the request's
session signing key. Messaging binds to its independently authenticated author;
federation preserves the sender's signed payload and verifies the adjacent
chain against that author, not the forwarding server. Client hook producers
use the same rule; service/app keys keep their separate authority. New readers
accept the optional carrier before writers send it. Do not insert new fields
into an older peer's extra-forbid federation wrapper.

After structural/signature/R1–R3 checks, evaluate a current chain from leaf
toward the root. Select the signature key by registration: a registered child
uses its witnessed issuer_key_seq; an unregistered local child uses the
parent's current key. For each agent edge, select the parent's current
certificate head and evaluate its current validity. For each human edge,
require the child's AWID registration, select its parent's certificate valid
at that registered_at, and evaluate that historical parent state against the
latest known effective_from cutoffs. Repeat this rule through historical human links;
do not treat a currently revoked inviter as a revoked earlier human invitee.
Every evaluated path is same-domain, acyclic and at most eight certificates.
Any missing support evidence refuses authority. Resolve the closest human only
after the whole required proof passes, including the DNS root.

Expose **one shared verified result**, used by Cloud and OSS rather than a
Cloud copy of the ancestor algorithm:

| outcome | Meaning |
|---|---|
| `nearest_human` | Valid chain; human_id names the human leaf or nearest human ancestor. |
| `no_human` | Valid root→agent* chain; human_id is null. |
| `unknown` | Legacy/no chain, unregistered human/global ID, stale agent certificate or invalid proof; human_id is null. |
| `unavailable` | Required authoritative evidence could not be obtained within freshness/size bounds; human_id is null. |

The result has exactly `outcome`, `human_id`, `identity_valid`, `kind` and
`reason`. `identity_valid` is true, false, or JSON null (unknown); `kind` is
human/agent only for an established valid chain and otherwise null. `reason`
is the stable code from the vectors. Revoked or malformed proof has
identity_valid=false; missing proof has unknown;
unavailable evidence has unknown. No outcome silently grants a role. A policy
needing a valid/current human refuses unknown/unavailable/no_human. `aw who`
fetches through the cached client and shows nearest human/no human/unknown,
with a distinct revoked or stale reason and the verified chain. It never
prints a supplied label as a verified human.

An enrolled global ID cannot evade status/revocation by omitting the header:
its independently authenticated stable ID is checked through the same cached
batch and its current certificate is fetched there. A known enrolled ID with
invalid/revoked evidence does not become a legacy success. A truly chainless
legacy identity retains ordinary authentication, with unknown accountability.
Invalid presented evidence never yields human authority or changes auth lane.

Servers derive verified human/agent kind from this result, never self-declared
agent_type. Without proof that field may be shown only as unverified legacy
information; human_name stays display-only. Routing changes must preserve the
released legacy-human journeys without treating their labels as chain-backed
authority. This does not convert existing member_person booleans into IDs.

## 6. Invitations, adoption and migration

An org-member invite is issued by the inviting human. Fix its intended
recipient, domain, parent and kind at issue, privately; after the child key
exists that human's signer signs the exact certificate. No portable signed
delegation. A custodial server can perform bounded deferred signing for that
exact pending invitation, rechecking session/invitation authorization and the
parent after lock waits. A self-custodial parent receives a CSR-style pending
request; its aw signs on next contact. Immediate init/spawn signs directly.
Agents can issue agent spawns, never human invites. An untyped new invite from
an attributed agent is a spawn/inherits or refuses, not an unattributed escape.
Do not guess a parent from pre-upgrade bearer tokens or local instance names.

Org membership may complete while identity registration is **pending**.
Expose pending/registered/failed registration state and reuse the same
invitation ID for its one exact-child registration. Before successful AWID
registration, the human and their new agents have unknown accountability and
no chain-backed authority. A parent signature, team key or local timestamp
cannot substitute. The AWID sign→revoke→register race is checked at registration
even if the custodial server already checked and signed. A rejected
registration does not undo independently completed org membership; it leaves
registration pending/failed. Success at AWID followed by a failed Cloud commit
is reconciled by the exact retry, preserving the original witnessed time and
without another certificate/human key. A pre-existing same-domain human needs
membership only, not an invite-triggered new human or re-parent.
Pending human registration cannot authorize child signing. A constructor may
retain its exact authenticated intended-parent operation and resume issuance
after registration with current checks and no extra login; it must not guess
or retroactively attach unrelated legacy agents.

Adoption is explicit and prospective. Retain existing global ID, key, address,
mailbox and ordinary member certificates when their bindings do not change.
Require actual new-parent/root authority and the agent's key proof; do not
infer them from API-key users, org roles, mutable owner metadata, human_name,
an old email claim, address age or a snapshot import. Initial local adoption
can certify the existing key; an already-certified local re-parent follows
§2's exception. Reconnect/import restore and verify, never mint a new ancestry.
Old work remains unattributed; current heads are not historical action proofs.
No per-action revision snapshots or automatic backfill is introduced.

Human-less teams stay supported. A DNS-enrolled root→agent* path reports no
human; existing local/unsigned ancestry reports unknown. Local spawning does
not require AWID registration; registered ancestor status uses §4's cache.
An OSS deployment without a valid DNS authority/registered human can coordinate
normally but cannot claim a verified human tree. The CLI root holder admits
its human using its domain process, the human key stays in the keychain and
agents sign descendants without new human authentication. OATS must obtain the
actual parent's signature rather than equating the deployment minting root or
an unsigned instance-parent label with that parent. Membership issuance can
still use the separate configured team controller.

Released clients, team certificate bytes, membership/revocation, messages,
custody and scoped grants continue. Old verifiers cannot enforce ID cascades
and are not advertised as doing so. New human-required policies refuse unknown;
ordinary legacy callers remain accepted until a separately measured removal.
Keep existing member_person/member_custody and dashboard compatibility actors
until their owning contracts are deliberately replaced. B3 passkey holders,
secrets approvers and logs readers need no human ID/member DID; contacts
outside the domain keep working. BYOT `aweb.owner-act/1` remains controller-key
signed; no team-owner binding or human-signed owner act is added here.
Cloud C2-D still proves the logged-in session and independently checks its
human ID against the agent's verified nearest human, plus its existing
membership/custody/endpoint/action checks. Attribution is not key custody.

## 7. Vector interpretation and implementation order

The fixture's keys are public synthetic test seeds. Certificates freeze exact
canonical/signing bytes, signatures and digests. Cases carry independently
supplied synthetic registry/cache facts, not permission to accept such facts
from a real caller. A structurally invalid record is signed correctly wherever
the intended refusal is shape/binding, rather than accidental bad crypto.
Wire-negative cases test raw decoding before the semantic cases. Ordered
operation cases test effects and atomicity; they are not substitutes for real
Postgres/concurrency and released-client journeys in later slices.

Freeze docs/vectors first; then shared Python/Go/TS verification, AWID history/
registration/cache, CLI/keychain, transport and creation adapters. Publish OSS
RC artifacts before Cloud integration; no source overlays. All runtimes consume
these same root vector bytes. Only docs/vectors are delivered by this slice.
