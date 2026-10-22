# X-E2: encrypted group history re-share

Result, 2026-10-21: **the content-key transfer is feasible in Python and Go,
without rewriting the original sender's envelope**. The complete managed-session
journey remains dependent on P4/P5. This is the bounded acft.13 experiment, not an
enabled service or a frozen annex. Athena must review its exact SHA before a
managed encryption/re-share annex freezes; P0's deferred capabilities stay off.

The experiment adds no production imports, route, migration or advertisement.
The queued plan/P0 landing remains exactly `4fb28705`. Its [governing
contract](human-channels-contract-v1.md#membership-history-and-checkpoint-records) and [group history
rule](human-channels-contract-proposal.md) remain authoritative.

## What ran

The [reproducer](../server/tests/test_human_channels_e2ee_spike.py) starts real
local OSS HTTP, AWID application and PostgreSQL/Redis through the existing
`privacy_app` fixture. AWID executes its real registration/authority routes over
ASGI; OSS uses a listening HTTP server. Both Python and Go make authenticated
HTTP reads of the actual stored source/capsule. Go uses `NewWithIdentity` and
`Client.Do`, followed by its actual HPKE/AES/Ed25519 code. No fake client,
cryptography, authority response or membership-table insertion supplies the
result. Disposable identity provisioning is separate from membership changes.

```sh
SUITE_LOCK_FOCUSED=1 uv run --project server python -m pytest \
  server/tests/test_human_channels_e2ee_spike.py -q
go -C cli/go test ./awid -run '^TestHumanChannelsE2EESpikeVector$' -count=1
make test-vector-provenance check-a2a-copy-guardrails
```

The Python test invokes the Go HTTP reader with a temporary, private fixture.
The standalone Go command consumes the same public [experimental
fixture](vectors/human-channels-e2ee-spike.json) as the Python fixture reader.
It contains only explicitly public synthetic test key material. Generate a new
candidate deliberately with `uv run --project server python
scripts/spikes/human_channels_e2ee.py --write-fixture`; do not auto-regenerate it
as a test repair. Random ciphertext/UUIDs change, while assertions stay stable.

| Boundary | Observed result | Location |
| --- | --- | --- |
| Native source | Alice sends encrypted-v2 chat to Bob; Bob reads/decrypts the stored envelope over HTTP. Carol cannot read its session or open its old key wrap. | `test_real_http_native_source_and_authorized_capsule`; Go live-input test |
| Complete laboratory control chain | Both readers verify creation through add/bridge-readable epoch and removal, every preceding payload hash, pinned owner signature and each resulting native member's signed control/visibility consent before experimental wrapping. | `verify_chain`, `hcXChain` |
| Bridge-readable epoch | An experimental epoch includes all current recipients and the bridge wrap; both readers decrypt it as the bridge. Its consented state is `bridge_readable`, and the protected context names that epoch/head. | `encrypt_group`, `authenticate_group`, `hcXManaged` |
| Historical copy | Owner signs exact source hash/message/session, holder, recipient and current laboratory head. Holder sends a separate encrypted capsule. Carol verifies it and the original signature/hash/AAD/inner header, then reads the original plaintext with the transferred per-message key. | `open_reshare`, `hcXRun` |
| Original preservation | HTTP source envelope, capsule's original string and grant's digest agree; no recipient, key wrap, ciphertext or original signature changes. | Python HTTP read-back and Go original hash check |
| Removal | Fresh future content key, sender self-copy and only current recipient wraps. Removed Bob has no future wrap; Carol decrypts. Earlier bridge-readable history retains its original label/context. | `experiment`, Go future reader |
| Refusals | Missing creation, repeated/old epochs, wrong owner, missing consent, concealed bridge label, freshly signed bridge-wrap omission, wrong grant scope, removed holder and wrong CEK refuse in the applicable laboratory reader. Native readers refuse the experimental version. | Python negative cases; Go CEK/recipient/version checks |
| Current public service | Proposed membership endpoint is HTTP 404 and experimental encrypted version is HTTP 422. Separate native history copy succeeds, but Carol still cannot read the source session afterward. | Real HTTP test |

These results prove a cryptographic construction and a real native carrier.
They do **not** prove that current servers authorize managed membership, serve
join-time history, commit policy heads, or distribute experimental group
messages. The three-member epoch/removal is evaluated by the laboratory readers,
not fabricated in server participant rows. A copied message is not room admission.

## Candidate shape and recommendation

Recommend transferring **one old message's content-encryption key (CEK)** in a
new encrypted, holder-signed re-share artifact, under the explicit owner/delegate
audience/history grant. The recipient independently verifies the immutable
original sender's envelope and decrypts its original ciphertext. No signing key
or long-term X25519 private key is transferred. Existing envelopes commit to key
wraps in their signature/AAD: see
[`verify_e2ee_message_envelope_signature`](../server/src/aweb/e2ee_messages.py#L716)
and [`decrypt_e2ee_message`](../server/src/aweb/e2ee_messages.py#L732).
Appending a wrap to the original is not a permitted implementation.

The proof's history grant commits to:

- an experimental purpose/version, source session/message and SHA256 of the
  exact canonical original envelope;
- current verified policy head, exact recipient and currently authorized holder;
- an owner signature, separately from the holder-signed encrypted capsule.

The encrypted capsule binds that grant, the exact original envelope string and
its CEK. The recipient checks current holder/recipient eligibility before
accepting the transfer, and verifies original ciphertext/hash/header bindings.
A wrong key fails AEAD; forwarding unproven plaintext with an old signature is
not the construction. Multiple messages require independently bounded grants
and per-message keys; no session master key is introduced.

For future managed messages the laboratory candidate uses a **separate,
explicitly negotiated profile**, with `GroupContext` in the signed outer map,
AEAD associated data, encrypted inner header and inner-header hash. It carries
session, epoch/head, typed author and message identity. A bridge receives a wrap
for every message of its admitted epoch. The candidate's numeric version `3` and
`aweb.experimental.managed-chat.x-e2` name are experiment identifiers, not allocated
release wire constants. Legacy native-v2 projection/AAD/header bytes remain
unchanged. Unsupported peers must refuse; there is no plaintext or native-mode
retry. This follows [P0's deferred-profile boundary](human-channels-contract-v1.md#capabilities-and-failure-results).

The codec reuses actual native HPKE-wrap generation, then produces separate
experimental ciphertext with a fresh nonce. The provisional native ciphertext
is never sent. A production implementation would generate the final profile
once; the two-step laboratory construction is not a shipping API.

## Boundaries to resolve before freezing or enabling P5

1. **P4 public authority/commit seam is required.** The caller-provided laboratory
   chain is not a trusted current head. Production must verify the complete
   creation/ownership/delegation chain, inbound-policy/consent, identity authority
   and membership CAS against the public service's committed state. A stale
   prefix cannot authorize re-share after revocation. Two separately signed
   forks need the committed head/CAS, not whichever chain a sender offers.
   The experiment explores one owner and native speakers; it does not implement
   delegated changes, owner succession, rotation or guest authors. Those remain
   required P4/P5 cases, not scope reductions.
2. **Commit the history authorization.** The proof's detached owner grant is not
   a public service receipt or a committed `HistoryGrant`. P5 must bind its
   recipient, exact source message/range and current authorized holder to the
   committed history grant and original operation receipt. Recheck revocation
   and replay at acceptance/read, including removal/rejoin intervals. Re-share
   does not mint a new signature by the original author or change original
   audience/history metadata.
3. **A native mail carrier is a transport experiment only.** Shipping the capsule
   as ordinary mail would create ordinary mail notifications/usage and expose an
   opaque control body to old runtimes. P5 needs an explicit capability-gated
   re-share control operation/read projection, stable IDs and original receipts,
   preserving the committed session, authorization and after-commit rules. The
   proof's carrier does not bypass a missing membership API.
4. **Complete the managed profile before publication.** Freeze closed fields,
   canonical maps, author/bridge binding, algorithm/version domain separation,
   size limits and negative vectors in both languages. Include bridge guests,
   identity-authorized current encryption keys and unsupported-client behavior.
   The prototype's stable-DID bridge check is genesis-only; production must use
   the public registry/key assertion authority across rotation. Do not infer
   control or custody from a namespace string, token or caller-provided DID.
5. **Preserve attachment/history ACLs.** This minimum experiment has text only.
   P5 must retain immutable acfn descriptors and require the grant plus current
   authorized public byte reads for old attachments; possession of a message
   CEK alone does not authorize fetching retained bytes. Limits, revocation and
   deletion still apply. No new file store or private access is proposed.

P0 capabilities remain refused until those P4/P5 tasks and Athena's exact-SHA
annex review pass. This spike does not make the owner chain advisory, change J9,
introduce a new room model, or unblock managed-message emission by itself.

## Alternatives and cost

| Approach | Cost / limitation |
| --- | --- |
| Recommended: encrypted per-message CEK transfer with immutable original evidence | Works with an authorized current holder while the original author is offline. Adds the explicit re-share operation, grant/receipt/current-head checks and a carefully separate verification entry point; ordinary native decryption still refuses non-recipients. |
| Original author issues a new signed copy/attestation | Can reuse more native delivery behavior, but needs the original author/key online and explicit original-source binding. It is a new authored copy, not a modification of old key wraps. It does not satisfy offline-holder history without another mechanism. |
| Rewrite/append old wraps or transfer long-term keys | Refused: breaks original signature commitments or exposes unrelated history/future messages. |

The experimental fixture and readers are evidence for Athena, not the frozen
annex. P8 presence verification is independent of these remaining P4/P5 seams
and is next in the assigned order.
