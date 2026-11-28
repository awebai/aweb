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

- **Personhood is the issuer's vouching, as today.** A verified `kind=human`
  certificate means its issuer vouches, by its own conditions, that one natural
  person holds the ID (`docs/id-certificates.md:16-20`). An organisation's
  vouching is unchanged by this design. A verifier sees which issuer vouches
  and decides whether it trusts that issuer.
- **The physical-key rule is aweb.ai's condition as an issuer.** It is not
  everyone's. How aweb.ai applies it to its own issuance is an open decision
  for Juan (§8).
- **Hardware backing is new, separate and checkable.** The issuer can sign a
  short statement, **P**: "this exact person ID, at this exact certificate and
  identity key, is backed by this certified hardware credential, until this
  date". P sits on top of the enrollment binding **B** that already exists,
  which the same issuer signs, at the approval service (awsign). P adds no
  second enrollment, no second attestation check, no second metadata loader
  and no registry record. Any issuer may sign it. None is required to.
- P lasts no longer than the FIDO metadata snapshot under which the issuer
  last assessed the credential, and never past a withdrawal date the issuer
  already knows. When FIDO withdraws a model, the issuer stops renewing, and
  the verifier shows **hardware backing lapsed**. Nothing is revoked, and the
  person can enrol a current key. P never says "not hardware".
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

A `kind=human` ID certificate keeps exactly its current meaning (decision 2,
and `docs/id-certificates.md:16-20`). Its issuer vouches for one natural person,
by the issuer's own process. P is an additional, independent fact about one
of that person's credentials. It never creates or removes the vouching.

## 2. Attestation formats accepted, and why

The approval service accepts five registration formats:
`none`, `packed`, `fido-u2f`, `tpm` and `apple`
(approval-service@be53c0a `src/approval_service/data/format-v1.json:1840-1846`).
It refuses every other format at registration (`registration.py:255-256`).
P needs a narrower rule than registration does, because P is a public claim
about a person and is renewed for as long as it holds.

| Format | Registration grade under the shared check | Basis for P? | Why |
|---|---|---|---|
| `packed` with an `x5c` chain, **batch profile** (below) | `certified_hardware` when the chain verifies to an MDS root for the attested AAGUID, the model has an applicable L1+ certification and no withdrawal, and the credential is single-device | **Yes** | The batch profile is positive evidence that the attestation key is shared across a batch. Basic (batch) attestation shares one attestation key across many devices (WebAuthn L3 §6.5.3, §14.4.1), so the chain identifies a model and batch, not a device. The existing `_packed` checks add to that: no subject serial number, OU "Authenticator Attestation", no CA leaf (`registration.py:132-163`), and enterprise attestation refused (`registration.py:118-119`). |
| `packed` with an `x5c` chain, any other or unresolved profile (AttCA, AnonCA, mixed) | `certified_hardware` is possible under the shared check, which accepts MDS entries listing `basic_full` or `attca` (`registration.py:170-173`) | **No: profile not established** | WebAuthn gives Basic, AttCA and AnonCA the same `packed`+`x5c` shape (§6.5.3). The field checks above do not exclude a device-specific attestation key or identifier. B's grade stays as signed; only P is withheld. |
| `packed` self-attestation (no `x5c`) | `passkey_uv` at most | No | Nothing ties the key to a certified model. |
| `none` | `passkey_uv` at most | No | There is no attestation. |
| `fido-u2f` | `passkey_uv` at most | No | U2F carries the all-zero AAGUID. The snapshot lookup by AAGUID cannot match it (`registration.py:309`, `metadata.py:228-237`). CTAP1 devices also cannot set UV, which registration requires (`registration.py:84-85`). In practice it can never reach the hardware grade. |
| `tpm` | `certified_hardware` is possible under the shared check | **No: privacy not established** | A TPM's attestation identity key (AIK) and its certificate can be reused across credentials on one device. The certificate's SAN names the TPM manufacturer and model. An issuer that hosts several organisations' issuance (decision 1) could then link one person's separate IDs. That would break the rule that nothing links a person's separate IDs (`docs/protocol.md:41-50`; `docs/human-approval-architecture.md:303-306`). At be53c0a no test, vector or document establishes TPM privacy. The implementer confirmed the format is untested in the repository, including in its introducing commit e5d1a3c. Refused until a reviewed privacy analysis exists. |
| `apple` | `passkey_uv` in practice | **No: privacy not established** | Apple's anonymous attestation issues a certificate for each credential. That certificate is unique to the credential and has no MDS model entry to check. Synced Apple passkeys also report backup eligibility, which excludes them (`registration.py:310`). At be53c0a no test or document covers the format (confirmed by the implementer, as for `tpm`). Refused until reviewed. |

**Batch profile, v1** (`aweb-attestation-batch-v1`). The issuer's private
assessment (§4.2) shows all of the following:

- format `packed` with an `x5c` chain that verified to a root listed for the
  attested AAGUID;
- the MDS entry for that AAGUID lists `attestationTypes` **exactly**
  `["basic_full"]`. This is the vendor's MDS declaration that the model uses
  batch attestation only. An entry that also lists `attca`, `anonca` or
  anything else is mixed, and mixed is not eligible;
- the leaf passes `_packed` and carries the AAGUID extension matching the
  authenticator data (`registration.py:114-129`).

The evidence is the vendor's declaration in the pinned, signed MDS. Nothing
else can prove from the certificate alone that a key is shared. That is the
stated limit.

The rule for P is therefore: **the basis credential's grade in B is
`certified_hardware`, and the issuer's own assessment establishes the batch
profile.** This is not a second hardware definition. It is the existing grade,
restricted to the one profile whose privacy has been established. A credential
outside the profile is never retained (§6). Adding a profile or format later is
an additive policy version, after a reviewed privacy analysis.

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
run out at their own `valid_until`, and hardware backing reads lapsed for
every hardware-backed person. This is the honest outcome, because the issuer
no longer has current eligibility data. It does mean the pin renewal now
protects hardware backing for every person, not only new enrollments. The
operator's existing expiry alert must name that consequence.

**On withdrawal.** When the issuer installs a new snapshot, it re-evaluates
each retained basis credential (§5) with `Snapshot.model(aaguid, now=…,
attestation_chain=…, authenticator_version=…)`, the same function registration
uses (`metadata.py:88-136`). It also requires the retained root to still be
listed for that AAGUID, and the entry to still satisfy the batch profile. A
credential that no longer qualifies gets no new P. Its current P runs out at
its `valid_until`. The issuer cannot recall a P already signed. The exposure
window is bounded by that lifetime (§4.1).

**Known future withdrawals.** `Snapshot.model` skips status reports whose
`effectiveDate` is still in the future (`metadata.py:101-108`). Such a report
is already known when the issuer signs. If an applicable withdrawal takes
effect at or before the P that would be signed expires, the issuer **signs no
P** for that credential (§4.2 step 4). It never shortens `valid_until` to the
withdrawal date. That date is specific to a model or batch, and with
`assessed_under` it would identify the model from the public MDS (§6). So P
never extends past a withdrawal date the issuer already holds, and the
credential's backing lapses at the previous P's ordinary, shared
`valid_until`. The remaining exposure is a withdrawal that FIDO publishes
after P is signed. That exposure is bounded by the 31-day cap and the
snapshot cutoff.

## 4. What the issuer signs, and where

### 4.1 The hardware-backing statement P

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
| `assessed_under` | `sha256:` digest of the snapshot whose evaluation, in the final decision of §4.2, justified **this** P. This holds for the first P as well. It may differ from the enrollment snapshot that B records, and B keeps that original snapshot unchanged. |
| `issued_at` | The issuer's clock time |
| `valid_until` | `min(assessed_under.valid_until, issued_at + 31 days)`. It is computed only from inputs that every credential assessed under that snapshot shares, never from a model- or batch-specific date (§3, §6). |

`P` = issuer signature over `UTF8("aweb.human-hardware-backing/1\n") + canonical_json(P_body)`.
The issuer selection and key are those that sign B for this person, and they
are checked the same way (approval-service@be53c0a `README.md:30-37,148-153`).

A verifier can enforce `issued_at < valid_until <= issued_at + 31 days` from the
signed body. The snapshot and withdrawal cutoffs are **issuer-attested**. The
`assessed_under` digest names the snapshot but supplies no independent cutoff,
because the verifier does not hold the model.

P has no negative or partial form. Leaving out a `basis` value, or adding a
value that is not `certified_hardware`, makes P unsupported in v1.

### 4.2 When the issuer signs P

The issuer signs P only when all of the following hold.

1. **Its own assessment.** The issuer ran the shared registration verifier on
   the credential's raw registration, with its own challenge and its own
   snapshot, and the result was `certified_hardware`. This is the existing
   precondition for signing that grade in B (`docs/protocol.md:439-446`). The
   same pass establishes the batch profile (§2).
2. **The exact basis completed its own proof, in the existing pending
   ceremony.** The order is acyclic and follows the bootstrap construction
   (`docs/protocol.md:511-533`):
   1. the issuer prepares the proposed certificate (or, for an existing
      person, names the committed one) and signs the pending B;
   2. the issuer checks that **the basis credential itself** made the accepted
      UV assertion of the `enrollment_confirmation` (or `enroll_existing_person`
      confirmation) that the issuer built, with its own nonce, over this
      pending `H_B`;
   3. the issuer commits the certificate and signs E referencing B and that
      receipt;
   4. only then may the issuer publish P. awsign activates on its normal
      observation of the committed certificate and E; P is not an input to
      activation.

   A pending B, with no commit, gives no P. Neither does a credential that is
   merely listed in a B whose confirmation another credential signed. A
   hardware key enrolled beside a passkey that did the confirming becomes a
   basis only after it completes its own issuer-built confirmation.
3. **Continuity.** The credential is in the person's current B, and B binds
   the person's current certificate and identity key. After an identity-key
   change, the basis carries over only through an authenticated continuity
   transition that the issuer recorded in E, with a receipt from a credential
   current before the change (`docs/protocol.md:535-556`). A bare rotation with
   no such evidence goes through the existing recovery or enrollment rule
   (§7) before any credential is a basis again.
4. **The final decision.** This step is the single compare-and-sign decision
   below. It runs the same way for the first P and for every renewal.

The issuer records the observation from steps 1 and 2 once, privately: the
committed `H_B`, `H_E` and confirmation receipt digest for the basis. Each
renewal, and each later continuity transition, reuses that observation rather
than repeating the person's ceremony.

**The final decision (compare-and-sign).** Under one lock, which installing a
snapshot and changing the person's binding also take, the issuer:

1. reads the installed snapshot S and the person's current `H_B`;
2. fixes `issued_at` to its clock and computes
   `valid_until = min(S.valid_until, issued_at + 31 days)`;
3. evaluates eligibility with `Snapshot.model(aaguid, now=issued_at, …)` under
   S (§3), and refuses if `issued_at >= S.valid_until`, or if any applicable
   withdrawal in S has an `effectiveDate` at or before `valid_until`;
4. signs P with `assessed_under = S`, that `issued_at` and that `valid_until`;
5. publishes P only if S and `H_B` are still the current ones and the
   publication time is still before `valid_until`. Otherwise it discards P and
   decides again.

Eligibility and the deadline therefore come from one evaluation at one time.
A wait that crosses a cutoff while both digests stay unchanged cannot publish
a P past it: step 5 checks the time, and step 3 has already ruled out every
withdrawal before `valid_until`. The first P after a delayed confirmation
names the snapshot actually evaluated. For example, B was prepared under N,
the confirmation completed after N+1 was installed, and P names N+1.

The issuer re-signs P after it installs each new snapshot, and before the
current P expires.

### 4.2a The private assessment result (shared-code addition)

The shared verifier's `RegisteredCredential` carries the grade and snapshot.
It carries no format, AAGUID, firmware, verified chain or root
(`registration.py:59-77,307-321`). P needs these from **the same verified
pass**, so there is still no second verifier. This is a real API addition to
approval-service:

- `check_registration` also returns a private `AttestationAssessment`: format,
  AAGUID, firmware version, the **verified** chain (DER, leaf to root, as
  `_hardware` built it), the matched root, the MDS `attestationTypes` and the
  derived profile (`aweb-attestation-batch-v1` or none).
- It is excluded from `repr`, from `binding_entry()` and from every serialized
  or public result. The B entry stays byte-identical.
- The issuer keeps it only for batch-profile credentials (§6). The service
  discards it, as it discards raw material today.

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

For each **human** link of a checked chain, the verifier reports two
independent facts: `personhood`, which is the issuer's vouching, and
`hardware_backing`, which comes from P. An agent link has neither. Its
responsible human's link carries its own. An agent never inherits a person's
reading, and an agent can never pass as a person. Neither fact changes the
message or chain verdict or its exit code (`docs/protocol.md:575-578`).

### 5.1 Personhood: the issuer's vouching (unchanged meaning)

`personhood.status` is `vouched` when this link's certificate verified with
`kind=human` under the existing chain rules, and `unknown` otherwise.
`personhood.issuer` is the checked issuing namespace. This is a reading of the
existing certificate, not a new artifact. The verifier attributes it ("<issuer>
vouches for a person") and makes no trust decision for the relying party.

aweb.ai's own issued IDs are the one case still open (§8). Under option A this
section applies to them unchanged. Under option B, sign-in IDs whose issuer is
aweb.ai must read `unknown` without hardware, and §8 states what that would
need.

### 5.2 Hardware backing: the reading rule for P

`hardware_backing.status` is one of these:

- `current` when every check below passes;
- `lapsed` when checks 1-5 pass, but the evaluation time is at or after
  `valid_until`;
- `none` when no P is presented;
- `invalid` for any other failure, with a typed reason.

1. A P is presented for this link. If not, the status is `none`, with reason
   `missing_statement`.
2. The version is supported and the body is well formed and closed. If not,
   `unsupported_version` or `malformed`.
3. The issuer signature verifies under independently obtained Trust, using the
   same issuer selection rule as B. If a trust input cannot be read, the
   reason is `trust_input_unavailable`, never a manufactured invalid
   signature. If the signature does not verify under current Trust, it is
   `signature_invalid`. The one exception is `issuer_superseded` (status
   `invalid`). That applies only when the verifier also holds
   **independently verified** predecessor evidence: the namespace's checked
   controller or issuer history, showing that the signing key was that
   issuer's authenticated key during `[issued_at, valid_until)` and has since
   been replaced. A holder-supplied key never counts. Without that evidence
   the result stays `signature_invalid`, so an arbitrary bad signature and an
   authenticated superseded signer are never confused.
4. `person`, `certificate` and `identity_key` equal this link's checked subject.
   If not, `binding_mismatch`.
5. A presented B verifies, `H_B(B)` equals `binding`, and B lists `credential`
   with grade `certified_hardware` and the same `grade_policy`. If B is absent,
   the reason is `missing_binding`. If it does not match, `binding_mismatch`.
   The body also satisfies `issued_at < valid_until <= issued_at + 31 days`;
   otherwise it is `malformed`.
6. The evaluation time is at or after `issued_at` (otherwise `not_yet_valid`)
   and before `valid_until` (otherwise `lapsed`, reason `expired`).
7. For a current reading, the certificate and identity key are current under
   fresh public status, using the existing 60-second rule
   (`docs/human-approval-architecture.md:91-94`). If not, the reason is
   `not_current`. If status cannot be read, it is `trust_input_unavailable`.

A holder can always leave out an expired P. In that case `lapsed` and `none`
both mean the same thing: not hardware-backed now. `lapsed` is shown when
the evidence is there to show it. Neither status changes `personhood`.

### 5.3 Enrollment proof, reported separately

The verifier separately reports `hardware_backing.enrollment_proof`. This is
optional public evidence that the named credential really signed. Only
**public identity receipts** count: the `enrollment_confirmation` or
`enroll_existing_person` confirmation receipt, or a continuity-transition
receipt (`docs/protocol.md:476-483,511-556`). Application receipts and their
resources stay private and are never used.

`enrollment_proof` is `true` only when a presented receipt checks fully. Its
raw UV assertion verifies under the public key that B lists for P's
`credential`, with the awsign origin and RP. Its challenge is `H(R)` of the
carried request. Its act is that confirmation or transition purpose. Its
`act.target` commits this P's `binding` (`H_B`) and names this exact subject,
certificate and identity key. The value is `false` when such a check fails,
and null when no receipt is presented.

A checked receipt shows that the credential was used **at its named event**.
It does not show that the key was used for this presentation or at the
evaluation time. The wording says so (§5.4). The attestation itself stays the
issuer's assessment, as for B's grade today (`docs/protocol.md:426-436,467-473`).
Two independent assessments back it: the issuer's own check, and awsign's
refusal of any grade beyond its own (`registration.py:42-56`).

### 5.4 Result shape and default wording

Each human link gets these results, added beside the existing fields in
`docs/protocol.md:582-593`:

| Field | Values |
|---|---|
| `personhood.status` | `vouched` or `unknown` |
| `personhood.issuer` | The checked issuing namespace, or null |
| `hardware_backing.status` | `current`, `lapsed`, `none` or `invalid` |
| `hardware_backing.reason` | `checked`, `missing_statement`, `missing_binding`, `malformed`, `unsupported_version`, `signature_invalid`, `issuer_superseded`, `binding_mismatch`, `not_yet_valid`, `expired`, `not_current`, `trust_input_unavailable` |
| `hardware_backing.issuer` / `credential` / `assessed_under` / `valid_until` | From a checked P, or null |
| `hardware_backing.enrollment_proof` | `true`, `false` or null, plus the receipt's event when it is true |
| `as_of` | The evaluation time, and whether this is a current or a historical reading |

The default `aw verify` line for each human link has the personhood phrase,
then the backing phrase:

| Condition | Text |
|---|---|
| `vouched` | `<issuer> vouches for a person` |
| `unknown` | `personhood unknown` |
| backing `current`, proof true | `; backed by certified hardware until <date>, key used at <event>` |
| backing `current`, proof null | `; backed by certified hardware until <date>, enrollment proof not presented` |
| backing `current`, proof false | `; backed by certified hardware until <date>, enrollment proof invalid: <reason>` |
| backing `lapsed` | `; hardware backing lapsed on <date>` |
| backing `none` | nothing appended |
| backing `invalid` | `; hardware backing invalid: <reason words>` |

Both phrases attribute their claim to the issuer. Hardware backing is not a
person-wide maximum grade. The grade of an approval is still the grade of the
credential that actually signed (`docs/protocol.md:558-563`).

### 5.5 Historical (as-of) reading

A relying party that saved P, B, any receipt, and as-of Trust (the issuer key
and the certificate status at time T) can later ask "was this ID
hardware-backed at T?" The check runs §5.2 with time T and the as-of Trust,
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
| The `AttestationAssessment` (§4.2a) of a batch-profile basis credential: format, AAGUID, firmware, verified chain, root, profile | **Issuer only**: private, encrypted at rest, keyed by (namespace, person, credential). Deleted when the credential leaves B or the ID is revoked. Never logged, exported, or put in P, B, E or the registry. | Needed to re-evaluate against later snapshots and certificate-scoped withdrawals (§3). Retained only for the batch profile, which identifies a model and batch, never a device (§2). Other profiles are discarded at assessment. |
| Credential public key, selector, grade, enrollment snapshot digest | Public in B, as today | Existing |
| Person ID, certificate digest, identity key, `H_B`, selector, basis, grade policy, `assessed_under`, dates | Public in P | The minimum needed to check P |
| Which model or vendor the person uses | Never public | P names no model. `assessed_under` and `valid_until` derive only from inputs shared by every credential assessed under that snapshot (§4.1). A known model- or batch-specific withdrawal date suppresses P rather than appearing in it (§3). |

Further rules:

- **No verifier contact.** P verifies offline against public Trust. There is
  no status endpoint, so the issuer never learns who checks a person.
- **No cross-ID link.** Each of a person's IDs has fresh credentials and its
  own B and P (`docs/protocol.md:41-50`). Retained batch-profile chains are batch
  certificates, so the issuer's private store can tell "same model and batch"
  but not "same device". This is also the reason `tpm` is refused (§2).
- **Presence is information.** Presenting P shows that this ID has certified
  hardware. That is the holder's choice: P is never pushed or published.

## 7. Key loss, rotation and re-enrollment

| Event | Effect on P and the reading | Basis |
|---|---|---|
| Identity-key rotation (enrolled keys unchanged) | The old P binds the old identity key and certificate, so a current reading gives `not_current`. The issuer re-signs B (an existing duty). It re-signs P only when the rotation is an authenticated continuity transition recorded in E (§4.2 step 3). A bare rotation goes through recovery or enrollment first. | approval-service@be53c0a `README.md:30-37,153-157`; §4.2 |
| Namespace-controller rotation | P signed by the superseded key no longer verifies under current Trust. That reads `signature_invalid`, or `issuer_superseded` with independently verified predecessor evidence (§5.2 step 3). The new issuer re-signs at the next renewal under §4.2. Historical readings use as-of Trust. | `README.md:30-37` |
| Basis credential lost, replaced or withdrawn | Replacing or withdrawing an enrolled key changes the identity key (`docs/protocol.md:94-99`). The old P becomes not current. A new P needs a batch-profile `certified_hardware` credential in the new B that completed its own proof (§4.2). If only passkeys remain, hardware backing is `none` from then on. Personhood (the issuer's vouching) is unaffected. The retained reference is deleted. | §4.2 |
| A second hardware credential is still enrolled | That credential grounds a new P only if it meets §4.2 itself: its own batch-profile assessment and its own completed issuer-built confirmation. P names it, and a basis never moves silently. | §4.2 |
| Re-enrollment at another origin or RP | New B, new assessment, new P. Nothing carries over. | `docs/protocol.md:121-126` |
| Recovery or recreation after losing every key | A new creation event after an explicit break. P starts over and never inherits the old basis. | `docs/deployment.md:160-167`; `docs/protocol.md:100-106` |
| ID revoked | Current readings give `not_current`. Retained references are deleted. Historical readings of earlier windows still hold. | §5.4 |
| Model withdrawn by FIDO | No renewal and no revocation. Backing reads `lapsed` from `valid_until`. The person can enrol a current key, which grounds a new P once it completes its own proof (§4.2). Personhood is unaffected. B's grade is untouched (see §10.4). | §3 |
| Pin renewal lapses | No renewals. Every P reads `lapsed` after its `valid_until`. | §3 |

## 8. aweb.ai as an issuer

The contract in §§2-7 is generic. Any issuer, including an organisation's key
holder or the hosted service acting as an organisation's issuer, may sign P
under the same rule. None is required to. This section covers aweb.ai's own
issuance, for people who sign in.

### 8.1 Settled

- aweb.ai signs P only under §4.2. Signing in, a verified email, the sign-in
  second factor, payment, an invitation, a passkey, or custody of the person's
  key never produces P.
- The hosted sign-in security key (Juan's sign-in requirement for aweb-adyx) is
  a credential at the hosted service's own RP. It is **not** a P basis (§10.2).
  A person can register the same physical key at awsign as a separate
  credential, which then becomes the basis.
- For an organisation's IDs that the hosted service holds, it signs P as that
  organisation's issuer. The reading attributes P to the organisation's
  namespace, not to aweb.ai. The organisation's vouching (`kind=human`) is the
  organisation's, unchanged.
- In the pilot, the organisation's members are the only person IDs, so they
  are unaffected by the open decision below.
- When FIDO withdraws a model, nothing is revoked. The reading shows
  "hardware backing lapsed", and the person can enrol a current key.
- The pilot runs the issuer side of §3: its own pin manifest, private cache,
  watcher, monitor and re-evaluation job. It depends on awsign running for
  enrollment (`docs/human-approval-architecture.md:452-453`).

### 8.2 Open decision for Juan: how aweb.ai issues to people who sign in

Decision 3 says aweb.ai reports personhood as unknown unless the person uses a
physical key. A `kind=human` certificate means its issuer vouches (§5.1), and
the certificate body is closed (`docs/id-certificates.md:102-116`), so it
cannot carry a per-issuer condition. That leaves two options. This design does
not choose between them.

**Option A: a person ID only after hardware (issuance-time policy).** aweb.ai
commits a `kind=human` certificate only when the pending ceremony of §4.2
step 2 succeeds with a basis-eligible credential. Until then, a signed-in
person has an account but no aweb.ai person ID. A first sign-in with no prior
ID runs the following order:

1. aweb.ai prepares the proposed certificate, but does not commit it, and the
   person registers at awsign under aweb.ai's challenge;
2. aweb.ai signs the pending B;
3. the eligible hardware credential itself completes the
   `enrollment_confirmation` over that `H_B`;
4. aweb.ai commits the certificate and signs E, and may then publish P;
5. awsign activates on its normal observation.

If the confirmation was made by a passkey, or the pending attempt expires, the
certificate is never committed under A. The pending material expires as it
does today.

- §5.1 applies to aweb.ai's IDs unchanged. Every `kind=human` certificate has
  one meaning, whichever issuer signed it.
- P stays the renewable, checkable evidence that aweb.ai's condition was met.
  A later lapse shows "hardware backing lapsed", and the vouching stays.
- Cost: sign-in alone does not give a person ID, which changes the pilot's
  sign-in and onboarding flow.

**Option B: an ID for every sign-in, with personhood unknown (reading-time
policy).** aweb.ai issues a `kind=human` certificate to everyone who signs
in. Its sign-in IDs read personhood `unknown` unless P is current. This is
coherent only with **authenticated issuer conditions that the holder cannot
suppress**. For a covered issuer, a missing or unavailable condition reads
`unknown` or `trust_input_unavailable`, and never silently yields `vouched`.
The issuer is the checked issuing namespace. A hosting provider's origin or
domain never selects it.

- A verifier must be able to tell that aweb.ai's `kind=human` does not vouch
  on its own. Nothing a holder presents can carry that, because the holder
  could leave it out and the reading would fall back to `vouched`. The
  condition must therefore come from something the holder cannot omit.
  Either it is a public, issuer-level record discoverable from the namespace,
  which is a new record and conflicts with the approval protocol's "no new
  registry record" rule (`docs/protocol.md` §1). Or it is a per-issuer rule
  built into verifiers, which lets one operator govern the contract.
- §5.1 would gain that issuer-condition input, and §9 would grow to change
  `docs/id-certificates.md:16-20` for such issuers.
- Benefit: every sign-in gets an ID immediately.

## 9. Contract text this changes

The organisation's vouching keeps its current text, so the change is small:

- `docs/human-approval-architecture.md` "Showing that an ID belongs to a
  person" gains the hardware-backing statement beside B and E, and the
  verifier result gains `personhood` and `hardware_backing` (§5.4).
- `docs/protocol.md` §8.2 and §8.4 in approval-service gain the same result
  fields and wording, if the P verifier lives in the shared Python and Go
  verifiers.
- Under option B only, `docs/id-certificates.md:16-20` and
  `docs/human-assurance-contract.md:21-22` would need to say that an issuer
  may declare that its `kind=human` certificates do not vouch on their own.
  That is an identity-path change, which needs Juan's recorded approval.
  Under option A they stay unchanged.

## 10. Rejected alternatives and open points

### 10.1 Settled: an organisation vouches by its own conditions

Each issuer vouches by its own conditions (oats-integration-coordinator's
ruling, relayed by approval-service on 2026-11-28). An organisation's
`kind=human` certificate already means it vouches for its own people. So v1
adds no "self-attestation" basis to P, and organisation-issued humans never
read `unknown` because they lack P. P records only hardware backing.

### 10.2 Rejected: the sign-in security key as the basis

The hosted service's sign-in second factor could run `check_registration` and
ground P directly. This was rejected for two reasons. Sign-in assertions are
never presented to anyone else, so no relying party could check possession;
that is the "claim nobody can check". It would also create a second binding
mechanism next to B. Using the awsign credential reuses B and its receipts.

### 10.3 Rejected: reading hardware backing from B's grade alone

B has no lifetime. Its currentness is anchored to the identity key
(`docs/protocol.md:94-99`). A grade signed before a FIDO withdrawal would keep
reading "backed by certified hardware" indefinitely: an overclaim that grows
silently. E records
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
retirement or replacement ends the binding. P avoids this for hardware
backing. Approvals are tracked separately as approval-service task
aweb-adrj.11. The `tpm` and `apple` finding is aweb-adrj.10.

### 10.5 Open with Juan: the definition of "physical key"

Juan's answer, relayed by oats-integration-coordinator and approval-service on
2026-11-28: "for now let's make it work". v1 keeps the shared approval-service
`certified_hardware` grade: certified (L1+), single-device and user-verified,
with platform authenticators included. The definition of "physical key" stays
open with Juan. An alternative, such as also requiring the MDS `attachmentHint`
to be external, would be a later, explicit change.

### 10.6 Follow-up: carriage in messages

Ordinary mail and chat carry the chain without evidence
(`docs/human-approval-architecture.md:161-162`), so hardware backing reads
`none` there until evidence carriage exists. A separate design will cover how a
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
| Statement P and its domain `aweb.human-hardware-backing/1` | B and E cannot express a claim that expires when eligibility lapses (§10.3) |
| `AttestationAssessment`, a private result of the same `check_registration` pass (§4.2a) | `RegisteredCredential` exposes no format, AAGUID, chain or root. This is an API addition, not a second verifier. |
| Issuer's private retained assessment, its committed-basis observation, and its re-evaluation job | Nothing retains it today. The key holder persists only the selector, public key, grade, snapshot digest and policy id (key-holder@16752b74 `enrollment.py:783-801`). awsign clears raw registration at activation. Public verifiers cannot see the AAGUID. Only the issuer can honour a withdrawal. |
| The P basis restricted to the batch profile (`aweb-attestation-batch-v1`) | `tpm`, `apple`, AttCA, AnonCA and mixed profiles have no established privacy (§2) |
| The verifier's `personhood` and `hardware_backing` results and wording | No existing field names who vouches, or reports hardware backing per link |
| The issuer's own pin installation | Required independence: the issuer never uses awsign's snapshot (`registration.py:228-234`) |

Not reused: awsign's metadata cache (independence), B as the carrier of the
claim (no lifetime), and the hosted sign-in credential (§10.2).

## 12. Acceptance evidence for the implementation

Following the lesson *vary independent assurance dimensions*
(`aweb/aweb-protocol-expert/lessons/vary-independent-assurance-dimensions.md@fbfa65f22efe`),
each test holds the authorising fact fixed and varies a property that must not
matter, and each test is paired with a valid neighbouring case:

- With a batch-profile `certified_hardware` credential and a valid P held
  fixed, vary custody (hosted or self-held), the sign-in method, email
  verification and team membership. Backing stays `current`.
- With a valid B holding only `passkey_uv` held fixed, vary everything else,
  including a hardware sign-in key at the hosted RP. Backing stays `none`.
- With an organisation's verified `kind=human` certificate held fixed, add or
  remove P, or let it lapse. Personhood stays `vouched` by that organisation
  throughout. Only backing changes.
- An agent link under a person with a valid P reads neither personhood nor
  backing. The person's link reads `vouched` and `current`.
- P past its `valid_until` reads `lapsed`. P one second before `issued_at`,
  P for another certificate digest, P whose `H_B` does not match, and P whose
  credential is `passkey_uv` in B each read `invalid`, with distinct reasons.
- P signed by a superseded controller key reads `invalid` with
  `issuer_superseded` when read now and the independently verified controller
  history is supplied, and `signature_invalid` without that history. The same
  P reads `current` when read as of a time inside its window under as-of
  Trust. A P signed by an arbitrary key reads `signature_invalid` even when
  history is supplied.
- Under option A (if chosen): a first sign-in confirmed by an eligible
  hardware credential commits the certificate and then publishes P. A pending
  attempt, and one confirmed only by a passkey, commit no certificate.
- Under option B (if chosen): an aweb.ai sign-in ID with its issuer condition
  unavailable reads `unknown` or `trust_input_unavailable`, never `vouched`.
- A FIDO withdrawal leaves the certificate unrevoked. Backing reads `lapsed`
  after `valid_until`. A newly enrolled current key that completes its own
  proof reads `current` again.
- A synthetic-vendor-root snapshot that adds an unscoped `REVOKED`, and one
  that adds a batch-scoped withdrawal (the existing test approach,
  approval-service `README.md:83-86`), stop the renewal of P only for the
  affected credentials.
- A `tpm` registration graded `certified_hardware` in B produces no P.
- A valid batch-profile `packed` fixture grounds P and is retained. A correctly
  signed `packed` chain whose MDS entry lists `["basic_full", "attca"]`, or only
  `attca`, keeps its B grade but grounds no P, and nothing is retained.
- Issuance shortcuts: a pending B with no committed E produces no P. In a
  mixed roster confirmed only by the passkey, the hardware credential produces
  no P until it completes its own confirmation. A committed basis carried
  through a recorded continuity transition keeps producing P. A bare identity
  rotation with no continuity evidence produces no P.
- A snapshot carrying a withdrawal for the basis model, with an
  `effectiveDate` before the would-be `valid_until`, produces no P. An
  unaffected model's renewal in the same snapshot gets the same `valid_until`
  as every other credential under that snapshot.
- A renewal that started under snapshot N, racing the installation of
  snapshot N+1, is discarded and redone under N+1. A renewal with no race
  commits.
- Delayed first P: B prepared under N, and the confirmation completed after
  N+1 was installed. P names N+1, and B still names N.
- Time-only cutoff: a decision whose wait crosses `valid_until`, or crosses a
  withdrawal `effectiveDate`, while both digests stay unchanged, publishes
  nothing.
- A body with `valid_until > issued_at + 31 days` reads `malformed`.
- `enrollment_proof`: a confirmation receipt by P's credential over P's
  `H_B` gives true. The same receipt beside a P for another `H_B`, a receipt
  by another credential in B, and an application receipt each give false or
  are not accepted.
- An expired pin stops every renewal, and the operator check exits nonzero.
- Status that cannot be read gives `trust_input_unavailable`, never
  `signature_invalid`.
