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
  everyone's. Juan decided option B (§8.2): aweb.ai gives an ID to everyone
  who signs in, and its people read personhood `unknown` unless a certified
  key backs them. aweb.ai declares this in a controller-signed **issuer
  statement** that verifiers read from the registry, never from the holder
  (§4.5).
- **Hardware backing is new, separate and checkable.** The issuer can sign a
  short statement, **P**: "this exact person ID, at this exact certificate and
  identity key, is backed by this certified hardware credential, until this
  date". P sits on top of the enrollment binding **B** that already exists,
  which the same issuer signs, at the approval service (awsign). P adds no
  second enrollment, no second attestation check and no second metadata
  loader. Any issuer may sign it. None is required to.
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
P is signed by the person's namespace controller under its current epoch, or
by a **hardware-backing signer** that the namespace's current issuer statement
lists (§4.5). The controller's key is found and checked the same way as for B
(approval-service@be53c0a `README.md:30-37,148-153`). P is the namespace's
statement. An identity parent (a human who issued this human) never signs it.

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

### 4.5 The namespace issuer statement

Option B (§8.2) needs a verifier to learn, for a given issuing namespace,
whether that namespace's `kind=human` certificates vouch on their own. The
holder must not be able to suppress the answer. A pilot whose namespace root
is held outside the service also needs a way to renew P without a human act
for each person. One controller-signed statement carries both.

`S_body`, closed:

| Field | Value |
|---|---|
| `version` | `1` |
| `namespace` | The exact namespace |
| `epoch` | The namespace's current epoch (`docs/id-certificates.md:317-339`) |
| `seq` | Starts at 1 and increases by exactly 1 with each new statement for this namespace, across epochs |
| `personhood` | `issuer_vouches` (the default meaning of `kind=human`) or `hardware_backing_required` |
| `hardware_backing_signers` | A list, possibly empty, of `{key: did:key, not_after: RFC 3339}` entries. Each key may sign P for this namespace and nothing else. `not_after` is at most 92 days after `issued_at`. |
| `issued_at` | The controller's clock time |

`S` = signature by the namespace controller's current epoch key over
`UTF8("aweb.namespace-issuer-statement/1\n") + canonical_json(S_body)`.

**Where it lives.** The registry stores and serves S with the namespace
record, together with its history, as it stores and serves other controller
acts. It has no authority over them (`docs/human-approval-architecture.md:229-234`).
The registry accepts a new S only if it verifies under the namespace's open
epoch key and `seq` is the previous value plus one. A namespace with no S is
served as `issuer_statement: null`. S is never carried by a holder, and a
verifier ignores any S a holder presents.

**Exact namespace only.** S applies to certificates whose `domain` is exactly
`namespace`. An ancestor's S never applies to a child namespace, whether the
child was delegated, inherited its TXT record, or is hosted by the same
service. The hosting provider's origin or domain never selects the issuer.
So aweb.ai's S covers aweb.ai's own IDs. An organisation's namespace that
aweb.ai hosts is covered only by that organisation's own S, and has none by
default.

**Epoch change.** After a controller rotation, the S signed under the
previous epoch no longer governs current readings. Until the new controller
signs a new S, the namespace's statement is `unavailable` (§5.1). This is the
same re-signing duty as for B after rotation.

**Rollback.** The registry is trusted not to hide S in the same way it is
already trusted not to hide a revocation in exact status reads. A verifier
that keeps state records the highest `seq` it has accepted for a namespace,
as servers do for team-key acts. It refuses a lower `seq`, and refuses
`null` after it has seen a statement. Each of those reads as `unavailable`.
A namespace returns to the default meaning only through a newer S that says
`issuer_vouches`, never through absence.

**Delegated hardware-backing signers.** The controller signs S rarely: when
the signer list changes, and at least every 92 days. Each listed key is
narrowly scoped:

- it can sign P, and nothing else. It cannot sign B, E, certificates or S;
- a P it signs is still subject to every §5.2 check. In particular, the
  credential must be `certified_hardware` in a controller-signed B. A leaked
  delegated key can therefore only extend or re-issue backing for credentials
  that the controller already bound as hardware. It cannot create a hardware
  claim for any other key;
- a P signed by a delegated key counts for a current reading only while the
  **current** S lists that key and `issued_at <= not_after`. Removing the key
  from S ends the current reading of every P it signed at once. Historical
  readings use the S in force at T (§5.5).

Holding a delegated signer key is a custody decision for the namespace's
owner. For awebai.org it is a decision for Juan (§8.1). Without a delegated
key, the controller signs every P itself.

## 5. How a verifier reads it

For each **human** link of a checked chain, the verifier reports two
independent facts: `personhood`, which is the issuer's vouching, and
`hardware_backing`, which comes from P. An agent link has neither. Its
responsible human's link carries its own. An agent never inherits a person's
reading, and an agent can never pass as a person. Neither fact changes the
message or chain verdict or its exit code (`docs/protocol.md:575-578`).

### 5.1 Personhood: the issuer's vouching, under the issuer's statement

For a human link whose certificate verified with `kind=human` under the
existing chain rules, the verifier reads the issuing namespace's issuer
statement (§4.5) from the registry that namespace's authority names. For
current readings, the read is fresh within the existing 60-second rule.
`personhood.issuer` is the checked issuing namespace.

| Statement read | `personhood.status` | `personhood.reason` |
|---|---|---|
| Registry answers `null` (no S), and the verifier has not seen one before | `vouched` | `issuer_default` |
| Valid S, `issuer_vouches` | `vouched` | `issuer_statement` |
| Valid S, `hardware_backing_required`, and `hardware_backing.status` is `current` (§5.2) | `vouched` | `hardware_backed` |
| Valid S, `hardware_backing_required`, and backing is `lapsed`, `none` or `invalid` | `unknown` | `hardware_backing_required` |
| The read fails or times out, S is from a superseded epoch, or the read is a rollback | `unknown` | `issuer_statement_unavailable` |
| S is malformed, or its signature does not verify under the open epoch key | `unknown` | `issuer_statement_invalid` |

The status is never `vouched` because a statement is missing, unreadable or
invalid. Only an authenticated `null` or a valid S yields it. An agent link
has no personhood reading. An organisation's namespace that publishes no S
reads exactly as it does today.

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
3. The signature verifies under independently obtained Trust. The signer is
   either the namespace controller's current epoch key, or a
   hardware-backing signer that the current S lists, with
   `issued_at <= not_after` (§4.5). If a trust input cannot be read, the
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
| `personhood.reason` | `issuer_default`, `issuer_statement`, `hardware_backed`, `hardware_backing_required`, `issuer_statement_unavailable`, `issuer_statement_invalid` |
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
| `unknown`, `hardware_backing_required` | `personhood unknown: <issuer> vouches only with a certified key` |
| `unknown`, any other reason | `personhood unknown: <reason words>` |
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
issuance, for people who sign in. While it is prototyped, that namespace is
awebai.org; it moves to aweb.ai when ready.

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
  namespace, not to aweb.ai. The organisation's vouching is the
  organisation's. An organisation may require hardware for its own people,
  as its own setting, by publishing its own S with `hardware_backing_required`.
- When FIDO withdraws a model, nothing is revoked. The reading shows
  "hardware backing lapsed", and the person can enrol a current key.
- The pilot runs the issuer side of §3: its own pin manifest, private cache,
  watcher, monitor and re-evaluation job. It depends on awsign running for
  enrollment (`docs/human-approval-architecture.md:452-453`).
- **Who signs, when the namespace root is held outside the service.** Under
  Juan's custody ruling F1, awebai.org's root and team keys are held outside
  the pilot. The controller (the outside holder) signs B at each person's
  hardware enrollment, which happens once per enrollment, and signs S. Monthly
  renewal of P then needs no human act per person: the pilot renews P with a
  hardware-backing signer key that S lists (§4.5). That key cannot sign B,
  certificates or S. Holding it in the pilot is a narrow custody change from
  F1, so it goes to Juan with that reason. If Juan declines, the outside
  holder signs every P renewal.

### 8.2 Decided: option B, an ID for every sign-in

Juan decided on 2026-11-28 (relayed by the main aweb coordinator and
approval-service): aweb.ai's issuer gives an ID to everyone who signs in, and
no authenticator is required to become a person. Personhood reads unknown
unless a certified key backs it. Organisations may require hardware as their
own setting. The definition of "physical key" stays open, with v1 on the
shared grade (§10.5).

aweb.ai therefore:

1. publishes S with `personhood: hardware_backing_required` **before** it
   issues the first sign-in ID. A `kind=human` ID issued before S exists would
   read `vouched` under §5.1;
2. issues a `kind=human` certificate to each person who signs in;
3. signs P, through the controller or a listed hardware-backing signer, for
   each person whose certified credential meets §4.2.

That person's link reads `personhood: vouched` (reason `hardware_backed`)
while P is current. Every other aweb.ai person reads
`personhood: unknown: aweb.ai vouches only with a certified key`. A lapse turns
`vouched` back into `unknown`, with "hardware backing lapsed". Nothing is
revoked.

**Released verifiers.** Verifiers released before §4.5 never read S. They
report a `kind=human` certificate without any personhood line, and they do
not render the issuer's vouching. The `personhood` reading exists only in
verifiers that implement this design. aweb.ai's own surfaces render
`unknown` from the first day.

## 9. Contract text this changes

Option B makes these identity-path changes. Each needs Juan's recorded
approval when it is implemented; the coordinator routes it.

- `docs/id-certificates.md:16-20`. Current text: "A human ID means one natural
  person, never a shared account. Its issuer vouches for that claim." Add: "If
  the namespace's current issuer statement says `hardware_backing_required`,
  the issuer vouches only while the ID's hardware backing is current. Otherwise
  personhood is unknown." The definition of a human ID stays as it is.
- `docs/human-assurance-contract.md:21-22` changes the same way.
- `docs/awid-sot.md` gains S: its body and domain, the registry's acceptance
  rule (open epoch key and `seq` + 1), the `issuer_statement` field and
  history on the namespace record, and the rollback rule.
- `docs/human-approval-architecture.md`, "Showing that an ID belongs to a
  person", gains P and S beside B and E, and the verifier result gains
  `personhood` and `hardware_backing` (§5.4).
- approval-service `docs/protocol.md` §8.2 and §8.4 gain the same result
  fields and wording, if the P verifier lives in the shared Python and Go
  verifiers.

**The "no new registry record" rule.** Approval-service `docs/protocol.md` §1
says the registry "neither records nor vouches for key custody or a
protection mode". §3 says "No new registry record is added" for requester
admission. S is a new record in the registry, so this design settles the
conflict explicitly. Both sentences are scoped to the approval protocol.
Enforcers, requesters and approvals need nothing in the registry, and the
registry learns nothing about custody, enrolled keys or approvals. S is none
of these. It is the namespace controller's declaration about its own
certificates, the same class of controller act the registry already stores
and serves without authority (`docs/human-approval-architecture.md:229-234`).
S names no person, credential, grade or custody. P and B stay out of the
registry, and the rule that a bare ID cannot be looked up for its grade
stands. **The approval-service owner should confirm this reading of its
rule.** If it does not, the alternatives in §10.7 are what remains, and all
of them were rejected for stated reasons.

## 10. Rejected alternatives and open points

### 10.1 Settled: an organisation vouches by its own conditions

Each issuer vouches by its own conditions (oats-integration-coordinator's
ruling, relayed by approval-service on 2026-11-28). An organisation's
`kind=human` certificate already means it vouches for its own people. So v1
adds no "self-attestation" basis to P, and organisation-issued humans never
read `unknown` because they lack P. P records only hardware backing.

### 10.1a Rejected: option A (a person ID only after hardware)

Under A, aweb.ai would commit a `kind=human` certificate only after a
basis-eligible credential completed the pending ceremony. A needed no issuer
statement. Juan chose B on 2026-11-28: everyone who signs in gets an ID, and
no authenticator is required to become a person.

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

### 10.7 Rejected carriers for the issuer condition

- **A new key in the `_awid` TXT record.** Released `aw` 1.36.58 and 1.36.59
  refuse any key other than `awid`, `controller` and `registry` during strict
  federation discovery (`cli/go/awid/federation_authority.go:259-276`,
  `sender_registry_discovery_failed`). One new field would break discovery
  of the namespace in every released client. The lenient parsers,
  `awid/src/awid/dns_verify.py:160-210` and Go `ParseAWIDTXTRecord`, hide
  this.
- **A separate DNS TXT name** (for example `_awid-issuer.<domain>`). It needs
  no registry record, but it fails in other ways. Without DNSSEC, an on-path
  attacker can forge an NXDOMAIN, and NXDOMAIN cannot be told apart from
  "none published", so suppression would silently yield `vouched`. DNS keeps
  no history for as-of readings. And nothing binds the record to the
  namespace epoch.
- **A file at a well-known HTTPS path on the domain.** The web origin's
  operator, possibly a hosting provider, would control both the condition
  and its absence. It has no history and no epoch binding.
- **A statement the holder presents.** The holder can leave it out, and the
  reading falls back to `vouched`.
- **A per-issuer rule built into verifiers.** It lets one operator govern the
  contract.
- **A separate namespace for sign-ins.** That namespace would still need to
  declare its condition, so it moves the problem without solving it.

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
| Namespace issuer statement S, `aweb.namespace-issuer-statement/1`, stored and served by the registry | Option B needs an authenticated condition the holder cannot suppress. No existing carrier can hold it (§10.7). |
| Delegated hardware-backing signers in S | Lets P renew monthly without a human act per person while the root stays outside the service. Using one is a custody decision (§8.1). |

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
- Issuer statement, with the `kind=human` certificate held fixed and only the
  statement varied:
  - registry `null`: `vouched`, reason `issuer_default`;
  - S `issuer_vouches`: `vouched`;
  - S `hardware_backing_required` with P `current`: `vouched`, reason
    `hardware_backed`;
  - the same with P `lapsed`, or no P: `unknown`, reason
    `hardware_backing_required`;
  - registry read failure or timeout: `unknown`, reason
    `issuer_statement_unavailable`;
  - S under a superseded epoch: `unknown`, reason `issuer_statement_unavailable`;
  - S with a bad signature: `unknown`, reason `issuer_statement_invalid`.
- Rollback: a verifier that has accepted `seq` 2 refuses `seq` 1 and refuses
  `null`, both as `issuer_statement_unavailable`. A new verifier that sees
  `seq` 3 `issuer_vouches` reads `vouched`.
- A holder-presented S, whether favourable or not, changes nothing. Only the
  registry read counts.
- Exact namespace: an organisation's namespace hosted by aweb.ai, or a child
  namespace delegated from aweb.ai, with no S of its own reads `vouched`,
  even though aweb.ai's S says `hardware_backing_required`.
- Registry acceptance: an S that is not signed by the open epoch key, or does
  not have `seq` equal to the previous plus one, is refused.
- Delegated signer: a P signed by a key listed in the current S is accepted,
  and a P signed by that key after its `not_after` is `signature_invalid`.
  After the key is removed from S, a current reading of its P is
  `signature_invalid`, and an as-of reading inside the earlier S's window is
  `current`. A delegated key's signature on B, E, a certificate or S is
  refused. A delegated P whose credential is `passkey_uv` in B is
  `binding_mismatch`.
- Ordering: an aweb.ai sign-in ID issued while the registry still answers
  `null` reads `vouched`. This is why S is published before the first ID
  (§8.2).
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
