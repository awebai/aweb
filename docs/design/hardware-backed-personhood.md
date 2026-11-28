# Hardware-backed personhood at an ID's issuer

Status: **design for review** (aweb-adyx.13, for the hosted pilot aweb-adyx).
Not implemented. This document enables no new authority until it is
implemented and reviewed.

Goal 1, making aweb.ai a significant business, depends on trust. An
organisation or a person relying on an aweb ID must be able to trust what
aweb.ai says about whether a person stands behind that ID. Trust breaks in two
ways. aweb.ai can claim more than it knows. Or it can make a claim that nobody
else can check. This design avoids both.

## Fixed decisions (Juan, 2026-11-28)

1. An ID's issuer stands behind "this ID is a person". For people who sign in,
   the issuer is aweb.ai. For an organisation's own people, it is the
   organisation. aweb.ai can host an ID that an organisation issued.
2. There is no new kind of entity.
3. As an issuer, aweb.ai reports personhood as **unknown** unless the person
   uses a physical key.

This design does not reopen these decisions.

## Summary

- Personhood is a new short statement, **P**, that the ID's issuer signs. It
  says one thing: "this exact person ID, at this exact certificate and
  identity key, is backed by this certified hardware credential, until this
  date."
- P sits on top of the enrollment binding **B** that already exists. B is
  signed by the same issuer, at the approval service (awsign). P adds no
  second enrollment, no second attestation check, no second metadata loader
  and no registry record.
- The default reading is **unknown**. Personhood is unknown when P is absent,
  expired or fails to verify, and for every agent link. P never says "not a
  person".
- P lasts no longer than the FIDO metadata snapshot under which the issuer
  last assessed the credential. When FIDO withdraws a model, the issuer stops
  renewing P, and personhood reverts to unknown without a key rotation.
- The attestation certificate chain and the model identifier stay private to
  the issuer. P carries neither.

## 1. Terms and the existing pieces

| Term | Meaning | Defined at |
|---|---|---|
| Issuer | The authority that signs a person's ID certificate and their binding. This is the checked current namespace controller, or the person's actual-parent issuer. | approval-service@be53c0a `README.md:148-153` |
| B | The issuer-signed enrollment binding. It names the person's ID, certificate digest and identity key, the awsign origin and RP, and each enrolled credential with its own grade, snapshot reference and grade-policy id. | approval-service@be53c0a `docs/protocol.md:493-494` |
| E | Issuer-signed identity evidence: creation and later transitions. | `docs/protocol.md:498-499` |
| Grade | `certified_hardware` or `passkey_uv`. Each credential has its own grade. | `docs/protocol.md:408-436`; `docs/human-approval-architecture.md:136-145` |
| `check_registration` | The shared registration verifier. The service and the issuer each run it on the same raw WebAuthn create response. | approval-service@be53c0a `src/approval_service/registration.py:218-341` |
| Snapshot | A pinned and verified FIDO MDS blob, loaded through `metadata_cache.fetch_and_pin` and `EnrollmentGrading`. | `src/approval_service/metadata.py:79-136`, `grading.py:20-146` |

A `kind=human` ID certificate stays exactly as it is (decision 2). It
classifies the ID as a person's ID rather than an agent's. Personhood, meaning
that the issuer stands behind the claim that a natural person holds this ID,
is reported only from P. See §9 for the contract wording this changes.

## 2. Attestation formats accepted, and why

The approval service accepts five registration formats:
`none`, `packed`, `fido-u2f`, `tpm` and `apple`
(approval-service@be53c0a `src/approval_service/data/format-v1.json:1840-1846`).
It refuses every other format at registration (`registration.py:255-256`).
P needs a narrower rule than registration does, because P is a public claim
about a person and is renewed for as long as it holds.

| Format | Registration grade under the shared check | Basis for P? | Why |
|---|---|---|---|
| `packed` with an `x5c` chain (basic or AttCA) | `certified_hardware` when the chain verifies to an MDS root for the attested AAGUID, the model has an applicable L1+ certification and no withdrawal, and the credential is single-device | **Yes** | Its privacy is established by checks that already exist. `_packed` refuses a subject serial number, requires OU "Authenticator Attestation" and refuses CA certificates (`registration.py:132-163`). Enterprise attestation is refused, not downgraded (`registration.py:118-119`). Batch attestation shares one attestation key across many devices (WebAuthn L3 §14.4.1), so the retained chain identifies a model and batch, not a device. |
| `packed` self-attestation (no `x5c`) | `passkey_uv` at most | No | Nothing ties the key to a certified model. |
| `none` | `passkey_uv` at most | No | There is no attestation. |
| `fido-u2f` | `passkey_uv` at most | No | U2F carries the all-zero AAGUID. The snapshot lookup by AAGUID cannot match it (`registration.py:309`, `metadata.py:228-237`). CTAP1 devices also cannot set UV, which registration requires (`registration.py:84-85`). In practice it can never reach the hardware grade. |
| `tpm` | `certified_hardware` is possible under the shared check | **No: privacy not established** | A TPM's attestation identity key (AIK) and its certificate can be reused across credentials on one device. The certificate's SAN names the TPM manufacturer and model. An issuer that hosts several organisations' issuance (decision 1) could then link one person's separate IDs. That would break the rule that nothing links a person's separate IDs (`docs/protocol.md:41-50`; `docs/human-approval-architecture.md:303-306`). At be53c0a no test, vector or document establishes TPM privacy. The implementer confirmed the format is untested in the repository, including in its introducing commit e5d1a3c. Refused until a reviewed privacy analysis exists. |
| `apple` | `passkey_uv` in practice | **No: privacy not established** | Apple's anonymous attestation issues a certificate for each credential. That certificate is unique to the credential and has no MDS model entry to check. Synced Apple passkeys also report backup eligibility, which excludes them (`registration.py:310`). At be53c0a no test or document covers the format (confirmed by the implementer, as for `tpm`). Refused until reviewed. |

The rule for P is therefore: **the basis credential's grade in B is
`certified_hardware`, and the issuer's own retained assessment (§5) records
format `packed` with a verified `x5c` chain.** This is not a second hardware
definition. It is the existing grade, restricted to the one format whose
privacy has been established. Adding `tpm` or `apple` later is an additive
policy version, after a reviewed privacy analysis.

B's grade is left unchanged. A `tpm` credential that the shared check grades
`certified_hardware` keeps that grade for approval requirements. It does not
ground P.

## 3. Trust policy for authenticator roots

Everything in this section is reused unchanged from the approval service. The
issuer runs its own instance of the same code over its own installed copy of
the same reviewed pin.

**Source.** FIDO Metadata Service v3. The JWT blob comes from
`https://mds.fidoalliance.org/`, is signed under the pinned GlobalSign Root R46,
and its revocation is checked against pinned CRLs
(approval-service@be53c0a `src/approval_service/data/mds-pin-v1.json`;
the loader is `metadata.py:139-245`). The status semantics follow FIDO
MDS 3.1.1 (`docs/protocol.md:418-424`).

**Eligibility policy.** `fido-mds-l1-single-device-uv-v1`
(`src/approval_service/data/mds-policy-v1.json`):

- certifications FIDO_CERTIFIED_L1 to L3plus qualify;
- `REVOKED`, `RETIRED`, `USER_VERIFICATION_BYPASS`, `ATTESTATION_KEY_COMPROMISE`,
  `USER_KEY_REMOTE_COMPROMISE` and `USER_KEY_PHYSICAL_COMPROMISE` withdraw;
- any status the policy does not know refuses (`metadata.py:131-133`).

A withdrawal with no certificate scope disqualifies the whole model at every
firmware version. A certificate-scoped withdrawal disqualifies only its batch
(`metadata.py:117-130`).

**Pinned.** The pin file holds the SHA-256 of the blob, root and CRLs, and the
minimum sequence. At be53c0a that is sequence 303, valid until
2026-12-01T00:00:00Z. Installation checks the pins, the root, the signer chain,
the CRLs, the signature, `nextUpdate`, and the highest installed sequence, so
there is no rollback. Vendor bytes are never committed. The cache lives
outside the repository with mode 0700 (approval-service@be53c0a `README.md:60-78`;
`docs/deployment.md:44-60`).

**Renewed.** `.github/workflows/metadata-pin.yml` runs daily. It verifies the
live blob under the existing pinned root and opens a pin-only PR. It never
merges or deploys. It stops on a root change, a new CRL route, a rollback or a
verification failure, and it fails when the pin on main is under 72 hours from
cutoff and a renewal PR is still open (`docs/deployment.md:24-41`).

**Reviewed.** The approval-service maintainer reviews and lands each pin PR. A
root change, a new CRL route or a change to the policy file is a deliberate,
reviewed code change, never automation (`docs/deployment.md:16-34`).

**Installed at the issuer.** The issuer's operator installs the reviewed pin
into the issuer's own manifest file and private cache. The issuer then uses
`EnrollmentGrading.load(mode="hardware", cache_dir=…, manifest_path=…)` with
`watch_metadata`. The issuer **never** takes a snapshot from awsign: the shared
verifier requires the caller's independently loaded input
(`registration.py:228-234`). The 7-day warning and the hourly `--check`
monitor also apply to the issuer (`docs/deployment.md:62-86`).

**On expiry.** Expiry already has one effect: attested enrollment refuses with
`snapshot_expired`, `snapshot_validation_expired` or `snapshot_unavailable`,
and passkeys continue (`docs/deployment.md:171-186`). For P it has a second:
the issuer cannot renew any P without a current snapshot. Existing P therefore
run out at their own `valid_until`, and personhood reads unknown for every
hardware-backed person. This is the honest outcome, because the issuer no
longer has current eligibility data. It does mean the pin renewal now protects
personhood for every hardware-backed person, not only new enrollments. The
operator's existing expiry alert must name that consequence.

**On withdrawal.** When the issuer installs a new snapshot, it re-evaluates
each retained basis credential (§5) with `Snapshot.model(aaguid, now=…,
attestation_chain=…, authenticator_version=…)`, the same function registration
uses (`metadata.py:88-136`). It also requires the retained root to still be
listed for that AAGUID. A credential that no longer qualifies gets no new P.
Its current P runs out at its `valid_until`. The issuer cannot recall a P
already signed. The exposure window is bounded by that lifetime (§4).

## 4. What the issuer signs, and where

### 4.1 The personhood statement P

The domain and encoding follow the B and E rules: canonical JSON, a literal
prefix ending in one newline, and an issuer signature
(`docs/protocol.md:487-500`).

`P_body`, closed:

| Field | Value |
|---|---|
| `version` | `1` |
| `namespace` | The person's exact namespace |
| `person` | The person's `did:aw` |
| `certificate` | Digest of the person's current ID certificate |
| `identity_key` | The person's current identity key (`did:key`) |
| `binding` | `H_B` of the current B that lists the basis credential |
| `credential` | The basis credential's selector in that B |
| `basis` | `certified_hardware`, the only v1 value |
| `grade_policy` | The B entry's `grade_policy` (for example `fido-mds-l1-single-device-uv-v1`) |
| `assessed_under` | `sha256:` digest of the snapshot under which the issuer last confirmed the credential's eligibility. At first issuance it equals the snapshot in B. Later it names the renewal snapshot. |
| `issued_at` | The issuer's clock time |
| `valid_until` | `min(assessed_under.valid_until, issued_at + 31 days)` |

`P` = issuer signature over `UTF8("aweb.human-personhood/1\n") + canonical_json(P_body)`.
The issuer selection and key are those that sign B for this person, and they
are checked the same way (approval-service@be53c0a `README.md:30-37,148-153`).

P has no negative or partial form. Leaving out a `basis` value, or adding a
value that is not `certified_hardware`, makes P unsupported in v1.

### 4.2 When the issuer signs P

The issuer signs P only when all of the following hold:

- the issuer itself ran `check_registration` on the credential's raw
  registration, with its own challenge and its own snapshot, and graded it
  `certified_hardware` (the existing precondition for signing that grade in B,
  `docs/protocol.md:439-446`);
- its retained assessment records `packed` with an `x5c` chain (§2);
- the credential is in the person's current B, and B binds the person's
  current certificate and identity key;
- re-evaluation against a current installed snapshot succeeds (§3).

The issuer re-signs P after it installs each new snapshot, and before the
current P expires. Re-signing needs no ceremony from the person: the
credential was already proved at enrollment, and possession is shown by
receipts (§5.2).

### 4.3 Where P lives

P travels where B and E already travel. It goes beside the ID chain, in the
evidence a holder presents: `aw id proof` files, and the reserved `evidence`
member of the export envelope (`docs/protocol.md:619-640`;
`docs/human-approval-architecture.md:161-162,181-182`). P is not published in
the registry, and there is no lookup by bare ID. P is issued to the person,
who chooses where to present it.

### 4.4 What stays private

These stay private: the raw attestation, the attestation chain, the AAGUID,
the format, the firmware version and the MDS entry. §6 has the full split.

## 5. How a verifier reads it

### 5.1 The reading rule

For each **human** link of a checked chain, the verifier reports
`personhood`. An agent link never has a personhood reading. Its responsible
human's link carries its own. An agent never inherits a person's reading. An agent can
never pass as a person.

The status is `person` only if every check below passes. Otherwise it is
`unknown`, and a typed reason says why.

1. A P is presented for this link. If not, the reason is `missing_statement`.
2. The version is supported and the body is well formed and closed. If not,
   `unsupported_version` or `malformed`.
3. The issuer signature verifies under independently obtained Trust, using the
   same issuer selection rule as B. If the signature fails, the reason is
   `signature_invalid`. If a trust input cannot be read, it is
   `trust_input_unavailable`, never a manufactured invalid signature.
4. `person`, `certificate` and `identity_key` equal this link's checked subject.
   If not, `binding_mismatch`.
5. A presented B verifies, `H_B(B)` equals `binding`, and B lists `credential`
   with grade `certified_hardware` and the same `grade_policy`. If B is absent,
   the reason is `missing_binding`. If it does not match, `binding_mismatch`.
6. The evaluation time is inside `[issued_at, valid_until)`. If not,
   `not_yet_valid` or `expired`.
7. For a current reading, the certificate and identity key are current under
   fresh public status, using the existing 60-second rule
   (`docs/human-approval-architecture.md:91-94`). If not, the reason is
   `not_current`. If status cannot be read, it is `trust_input_unavailable`.

All three of the following read `unknown` with reason `missing_statement`:
an ID certificate of `kind=human` with no P, a valid B with only `passkey_uv`
credentials, and a valid B with a `certified_hardware` credential but no P.

### 5.2 Proof, reported separately

As in §8.2 of the approval protocol, the verifier separately reports
`proof_binds_credential`. It is true only when a presented receipt carries a
valid UV assertion by the credential that P names, verified against B's public
key and the awsign origin and RP. It is false when such a check fails, and
null when no receipt is presented. This is what lets a relying party check
more than the issuer's word. The attestation itself stays the issuer's
assessment, as for B's grade today (`docs/protocol.md:426-436,467-473`). Two
independent assessments back it: the issuer's own check, and awsign's
refusal of any grade beyond its own (`registration.py:42-56`).

### 5.3 Result shape and default wording

Each human link gets one result, added beside the existing fields in
`docs/protocol.md:582-593`:

| Field | Values |
|---|---|
| `personhood.status` | `person` or `unknown` |
| `personhood.reason` | `checked`, `missing_statement`, `missing_binding`, `malformed`, `unsupported_version`, `signature_invalid`, `binding_mismatch`, `not_yet_valid`, `expired`, `not_current`, `trust_input_unavailable` |
| `personhood.issuer` | The checked issuer namespace, or null |
| `personhood.basis` / `credential` / `assessed_under` / `valid_until` | From a checked P, or null |
| `personhood.proof_binds_credential` | `true`, `false` or null |
| `personhood.as_of` | The evaluation time, and whether this is a current or a historical reading |

The default `aw verify` line for each human link:

| Condition | Text |
|---|---|
| `person`, proof true | `personhood: <issuer> states a person, backed by certified hardware until <date>; key use proven` |
| `person`, proof null | `personhood: <issuer> states a person, backed by certified hardware until <date>; key use not shown` |
| `person`, proof false | `personhood: <issuer> states a person, backed by certified hardware until <date>; key use proof invalid: <reason>` |
| `unknown`, missing statement | `personhood unknown` |
| `unknown`, any other reason | `personhood unknown: <reason words>` |

The wording always attributes the claim to the issuer. Personhood is
independent of the message and chain verdict and its exit code, as with the
evidence results (`docs/protocol.md:575-578`). It is not a person-wide maximum
grade. The grade of an approval is still the grade of the credential that
actually signed (`docs/protocol.md:558-563`).

### 5.4 Historical (as-of) reading

A relying party that saved P, B, any receipt, and as-of Trust (the issuer key
and the certificate status at time T) can later ask "was this ID
hardware-backed at T?" The check runs §5.1 with time T and the as-of Trust,
which is the existing explicit as-of practice (approval-service@be53c0a
`README.md:23-27,159-160`). Step 7 then uses status as of T.

A later controller rotation, a key change, or a lapsed P does not change a
historical reading of a window that P covered. That matches the existing rule
not to rewrite a historical claim as failed (`docs/protocol.md:667-668`).

A historical reading reports what the issuer stated under the snapshot it
named. It does not re-evaluate withdrawals that FIDO published later. The
verifier could not do so anyway, because the AAGUID is private. WebAuthn has
no trusted signing timestamp, so `issued_at` is the issuer's clock, and T is
the relying party's own record (`docs/protocol.md:403-406`).

## 6. Privacy

| Item | Where it lives | Why |
|---|---|---|
| Raw attestation object | Never retained. The issuer checks it and drops it, the same rule awsign applies (`docs/deployment.md:120-125`). | Not needed after the check. |
| AAGUID, format, firmware version, verified `x5c` chain (DER) of a P-basis credential | **Issuer only**: private, encrypted at rest, keyed by (namespace, person, credential). Deleted when the credential leaves B or the ID is revoked. Never logged, exported, or put in P, B, E or the registry. | Needed to re-evaluate against later snapshots (§3). Only `packed` chains are retained. They identify a model and batch, never a device (§2). |
| Credential public key, selector, grade, enrollment snapshot digest | Public in B, as today | Existing |
| Person ID, certificate digest, identity key, `H_B`, selector, basis, grade policy, `assessed_under`, dates | Public in P | The minimum needed to check P |
| Which model or vendor the person uses | Never public | P names no model, and `assessed_under` is the same for everyone |

Further rules:

- **No verifier contact.** P verifies offline against public Trust. There is
  no status endpoint, so the issuer never learns who checks a person.
- **No cross-ID link.** Each of a person's IDs has fresh credentials and its
  own B and P (`docs/protocol.md:41-50`). Retained `packed` chains are batch
  certificates, so the issuer's private store can tell "same model and batch"
  but not "same device". This is also the reason `tpm` is refused (§2).
- **Presence is information.** Presenting P shows that this ID has certified
  hardware. That is the holder's choice: P is never pushed or published.

## 7. Key loss, rotation and re-enrollment

| Event | Effect on P | Basis |
|---|---|---|
| Identity-key rotation (enrolled keys unchanged) | The old P binds the old identity key and certificate, so a current reading gives `not_current`. The issuer re-signs B (an existing duty) and then P. No ceremony is needed. | approval-service@be53c0a `README.md:30-37,153-157` |
| Namespace-controller rotation | P signed by the superseded key no longer verifies for current readings. The issuer re-signs at the next renewal. Historical readings use as-of Trust. | `README.md:30-37` |
| Basis credential lost, replaced or withdrawn | Replacing or withdrawing an enrolled key changes the identity key (`docs/protocol.md:94-99`). The old P becomes not current. A new P needs a `certified_hardware` `packed` credential in the new B. If only passkeys remain, personhood is unknown from then on. The retained reference is deleted. | §4.2 |
| A second hardware credential is still enrolled | The issuer issues the new P on that credential. P names it, and a basis never moves silently. | §4.1 |
| Re-enrollment at another origin or RP | New B, new assessment, new P. Nothing carries over. | `docs/protocol.md:121-126` |
| Recovery or recreation after losing every key | A new creation event after an explicit break. P starts over and never inherits the old basis. | `docs/deployment.md:160-167`; `docs/protocol.md:100-106` |
| ID revoked | Current readings give `not_current`. Retained references are deleted. Historical readings of earlier windows still hold. | §5.4 |
| Model withdrawn by FIDO | No renewal. The status reverts to unknown at `valid_until`. B's grade is untouched (see §10.4). | §3 |
| Pin renewal lapses | No renewals. Every P runs out at its `valid_until`. | §3 |

## 8. aweb.ai's issuer policy

This section is the policy of one issuer: the hosted pilot service (aweb-adyx)
acting for namespaces it controls. The contract in §§2-7 is generic. An
organisation's key holder can sign the same P under the same rule.

- For people who sign in to aweb.ai, aweb.ai signs P only under §4.2. Signing
  in, a verified email, the sign-in second factor, payment, an invitation, a
  passkey, or custody of the person's key never produces a personhood claim.
  They all read unknown.
- The hosted sign-in security key (Juan's sign-in requirement for aweb-adyx)
  is a credential at the hosted service's own RP. It is **not** a P basis
  (§10.2). A person can register the same physical key at awsign as a
  separate credential, which then becomes the basis.
- For an organisation's IDs that aweb.ai hosts, aweb.ai signs P as that
  organisation's issuer, under the same v1 rule. The reading attributes it to
  the organisation's namespace, not to aweb.ai. In v1 there is no other basis
  that an organisation could choose (§10.1).
- The pilot runs the issuer side of §3: its own pin manifest, private cache,
  watcher, monitor and re-evaluation job. It depends on awsign running for
  enrollment (`docs/human-approval-architecture.md:452-453`).

## 9. Contract text this changes

These are identity-path wording changes. They need Juan's recorded approval
when they are implemented; the coordinator routes that. They are listed here
so they are changed by an explicit ruling rather than reinterpreted:

- `docs/id-certificates.md:16-18`: "A human ID means one natural person …
  Its issuer vouches for that claim." Proposed text: a human ID is a person's
  ID, never a shared account or an agent, by its issuer's classification.
  Whether the issuer stands behind a natural person holding it is the separate
  personhood statement. Without that statement, personhood is unknown.
- `docs/human-assurance-contract.md:21-22`: "A verified `kind=human` ID
  certificate records that its issuer vouches for one person." This changes
  the same way.
- The pilot's hosted-service design (row O1) says the issuer vouches
  for a natural person "only under the checked enrolment ceremony". That needs
  to say that this vouching is P, under §4.2.

## 10. Rejected alternatives and open points

### 10.1 Open: does an organisation have a basis without hardware?

Decision 1 says an organisation stands behind its own people. Decision 3
limits only aweb.ai. An organisation may know its people by its own process,
such as employment, and could sign a P with a basis like `issuer_attested`.
The verifier would report it as "<org> states a person, by its own process".
v1 leaves this out: nobody can check such a claim beyond trusting the
organisation. Adding it later is a new `basis` value, an additive change.
**Question for the coordinator.**

### 10.2 Rejected: the sign-in security key as the basis

The hosted service's sign-in second factor could run `check_registration` and
ground P directly. This was rejected for two reasons. Sign-in assertions are
never presented to anyone else, so no relying party could check possession;
that is the "claim nobody can check". It would also create a second binding
mechanism next to B. Using the awsign credential reuses B and its receipts.

### 10.3 Rejected: reading personhood from B's grade alone

B has no lifetime. Its currentness is anchored to the identity key
(`docs/protocol.md:94-99`). A grade signed before a FIDO withdrawal would keep
reading "person" indefinitely: an overclaim that grows silently. E records
events and is not a renewable state, so it was rejected for the same reason.
Registry publication was rejected as well: it would contradict "a bare ID
cannot be looked up for its grade"
(`docs/human-approval-architecture.md:181-182`).

### 10.4 Observation for the approval-service owner, outside this design

B's `certified_hardware` grade is not re-evaluated when FIDO later withdraws a
model. A pin reload changes only the snapshot used for new registrations
(approval-service@be53c0a `grading.py:84-123`). Act verification consumes the
signed grade (`verify/receipt.go:168-193`). An approval requirement of
`hardware` would therefore still be met by a withdrawn model until rotation,
retirement or replacement ends the binding. P avoids this for personhood. Whether
approvals need the same treatment is the approval service's decision.

### 10.5 Open: does "physical key" cover certified platform authenticators?

v1 uses the existing `certified_hardware` definition: L1+ certified,
single-device, with UV. A `packed` platform authenticator that meets that
definition qualifies. The alternative is to also require the MDS
`attachmentHint` to be external, which would mean a roaming security key only.
That would be a second hardware definition beside the shared grade. The
recommendation is to keep v1 as written. `docs/human-approval-architecture.md:334`
says "certified security key", so this should be confirmed. **Question for
the coordinator.**

### 10.6 Follow-up: carriage in messages

Ordinary mail and chat carry the chain without evidence
(`docs/human-approval-architecture.md:161-162`), so personhood reads unknown
there until evidence carriage exists. A separate design will cover how a
person's current P reaches the export-envelope `evidence` member, and the
mail sent by the person's agents.

## 11. What is reused, what is new

| Reused unchanged | Where |
|---|---|
| Registration check, shared by service and issuer | `registration.py:218-341` |
| Metadata loader, snapshot and eligibility evaluation | `metadata.py`, `metadata_cache.py` |
| Pins, policy file, daily renewal workflow, review and install duties | `mds-pin-v1.json`, `mds-policy-v1.json`, `.github/workflows/metadata-pin.yml`, `docs/deployment.md` |
| Grading modes, watcher, health and expiry monitor | `grading.py` |
| Grade vocabulary | `certified_hardware`, `passkey_uv` |
| B, E, receipts, issuer selection, as-of Trust, canonical encoding | `docs/protocol.md` §4, §8 |
| Evidence carriage and no-lookup rule | `docs/human-approval-architecture.md:147-182` |

| New | Why it is not a reuse |
|---|---|
| Statement P and its domain `aweb.human-personhood/1` | B and E cannot express a claim that expires when eligibility lapses (§10.3) |
| Issuer's private retained assessment and its re-evaluation job | Nothing retains it today. The key holder persists only the selector, public key, grade, snapshot digest and policy id (key-holder@16752b74 `enrollment.py:783-801`). awsign clears raw registration at activation. Public verifiers cannot see the AAGUID. Only the issuer can honour a withdrawal. |
| The P basis restricted to `packed` | `tpm` and `apple` privacy are not established (§2) |
| The verifier's `personhood` result and wording | No existing field reports the issuer's personhood claim |
| The issuer's own pin installation | Required independence: the issuer never uses awsign's snapshot (`registration.py:228-234`) |

Not reused: awsign's metadata cache (independence), B as the carrier of the
claim (no lifetime), and the hosted sign-in credential (§10.2).

## 12. Acceptance evidence for the implementation

Following the lesson *vary independent assurance dimensions*
(`aweb/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md@fbfa65f22efe`),
each test holds the authorising fact fixed and varies a property that must not
matter, and each test is paired with a valid neighbouring case:

- With a `certified_hardware` `packed` credential and a valid P held fixed,
  vary custody (hosted or self-held), the sign-in method, email verification
  and team membership. The reading stays `person`.
- With a valid B holding only `passkey_uv` held fixed, vary everything else,
  including a `kind=human` certificate and a hardware sign-in key at the
  hosted RP. The reading stays `unknown`.
- An agent link under a person with a valid P reads no personhood. The
  person's link reads `person`.
- P expired by one second, P one second before `issued_at`, P for another
  certificate digest, P whose `H_B` does not match, and P whose credential is
  `passkey_uv` in B each give `unknown` with their distinct reasons.
- P signed by a superseded controller key gives `not_current` when read now,
  and `person` when read as of a time inside its window.
- A synthetic-vendor-root snapshot that adds an unscoped `REVOKED`, and one
  that adds a batch-scoped withdrawal (the existing test approach,
  approval-service `README.md:83-86`), stop the renewal of P only for the
  affected credentials.
- A `tpm` registration graded `certified_hardware` in B produces no P.
- An expired pin stops every renewal, and the operator check exits nonzero.
- Status that cannot be read gives `trust_input_unavailable`, never
  `signature_invalid`.
