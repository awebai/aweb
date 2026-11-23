# Verify an exported message

A recipient can export one received mail without acknowledging it:

```sh
aw mail show --message-id MESSAGE_ID --envelope > message.json
```

Anyone holding that file can check the signed author and the author's ID-tree
responsibility without an aweb identity, team, token, configuration or aweb server:

```sh
aw verify message.json
aw verify --json < message.json
cat message.json | aw verify -
```

Verification uses unauthenticated registry reads and DNS. It is independent of
an aweb messaging server and does not use an acting identity or write local
identity or trust state. Encrypted exports
carry ciphertext and can be verified without a decryption key. Plaintext exports
contain the signed message content; the recipient chooses whom to give it to.

`--envelope` requires an exact `--message-id`; it cannot export a conversation.
It always prints one JSON document, including without `--json`. A message lacking
its original signed bytes cannot be reconstructed from display fields for export.

## Export document

The v1 wrapper has these fields:

| Field | Meaning |
|---|---|
| `v` | Exactly `1`. |
| `type` | Exactly `"aweb.message-envelope"`. |
| `signed_payload` | The original signed JSON string, unchanged. |
| `signature` | Its existing message signature. |
| `signing_key_id` | Its existing signing-key selector, when present. |
| `encrypted_envelope` | The original encrypted v2 envelope, instead of the preceding three fields. |
| `id_chain` | The optional adjacent ID-chain presentation, unchanged. |
| `evidence` | Optional per-link evidence collection, reported independently of the message/ID-chain verdict. |

The initial collection is `{"v":1,"links":[{"certificate":"sha256:…","statement":E,"receipt":C}]}`,
where E is the issuer-signed human creation statement and C is its optional raw
creation receipt from the shared approval protocol. Each entry names the exact
checked ID certificate. The report separates issuer authentication, raw proof,
currentness and continuity. Without C it says "issuer states"; a checked creation
proof says "created with" for passkey UV, or "issuer attests certified hardware;
creation proof checked" for hardware. Hardware grade authenticates the issuer's claim; it
does not mean this verifier inspected private device attestation. Unsupported
profiles and malformed evidence inside valid JSON do not change the message or
ID-chain verdict or exit status. Transition/adoption profiles are not implemented
by this initial human-creation reader. An evidence body with a `transition` member
reports "evidence profile unsupported", with unknown continuity, rather than
invalid evidence. Initial creation without a transition must name a subject key whose computed
stable ID equals the person ID; mismatch is `creation_key_inconsistent`. This
consistency check is local and requires no registry reader.

The `human_enrolled_later` profile reports "can approve since T (issuer's
statement), grade G (issuer's statement)". Its optional confirmation receipt is
checked separately. Later enrollment never adds a creation claim; an identity
with no enrollment still has its chain checked and reports "no evidence".

People prepare their identity with `aw id human init`, using the
passphrase-protected OS keychain at a terminal. An operator can hand them an
issued certificate to complete with `aw --human ID --human-domain DOMAIN id human
register FILE`. Approved issuance uses `id human add`, which returns a pending
intent for the new person; it does not enroll them. The person runs `id human
enroll --issuer URL` for an existing ID, or adds `--intent FILE` for a new ID,
then registers and confirms their approval key in the named browser service.
The signed intent supplies that service; `--approval-origin` is an optional
equality pin. Repeating the command resumes its saved enrollment.

`aw --human ID --human-domain DOMAIN id proof --message-file FILE --out proof.json`
exports the person's signed message, chain and saved evidence. The recipient
runs plain `aw verify proof.json` on another machine. The identity key stays in
the OS keychain; the proof contains public evidence and no private key.
The outer export rejects duplicate members,
including escaped or case-insensitive names for the same field. Unrelated unknown
outer fields and malformed JSON remain invalid.

An enforcer's `428 needs_human` response can be handled by `aw id request` using
`--approval-origin`, `--approval-requester`, `--approval-admission` and
`--approval-record`. The descriptor and admission files contain the caller's
public protocol data; the selected identity signs the service submission/polls
and the receipt presentation to the original enforcer. The private record keeps
canonical R before submission and C before presentation. `--approval-resume`
uses that original R, caller and deadline rather than asking for another act.
An approval receipt does not itself grant an application effect.

The sender's key and stable ID come from the signed content. Display labels,
server-projected sender IDs and earlier verification statuses are not inputs.
The adjacent chain remains outside the signed message format, as required by
[ID certificates §5](id-certificates.md#5-presentation-binding-and-verification-result).
The command uses the existing message-signature, DID-continuity and ID-chain
verifiers; this wrapper introduces no new signature or ancestry algorithm.

## Results and registry selection

The text result reports the nearest human, no human, unknown, invalid or
unavailable, with the reason. `--json` retains `aw who`'s shared result:
`outcome`, `human_id`, `identity_valid`, `kind` and `reason`, plus the subject
`id`, `domain` and, when presented and verified, `chain`. Invalid proof has
`outcome:"unknown"` and `identity_valid:false`. Missing proof has null validity;
failed required lookups give unavailable and never establish a human or kind.
A valid root-to-agent chain without a human reports `no_human` and kind `agent`.
Getting a nearest human establishes responsibility, not team membership,
resource access or how that human's key was used.
The signed From address is a claim by the signer, not a verified address, and
is therefore absent from the result.

Exit status is `0` for a valid proof (`nearest_human` or `no_human` with
`identity_valid:true`) and a normal unknown/no-chain answer, `1` for invalid
proof (`identity_valid:false`), and `2` for unavailable evidence or unreadable
input. A nonzero verification result still prints one result document under
`--json`; diagnostics go to stderr.

The chain's domain selects its own DNS authority and status registry. Every
global sender is checked for enrollment through independent public key reads:
its signed address selects the key registry. An addressless proof uses its
presented leaf certificate's domain for DNS discovery under the same authority
checks. Without an address or chain, an explicit `--registry` or the default
public registry supplies that route.
Only fresh, subject-bound enrollment evidence selects the ID-tree domain, and
a presented chain in another domain is invalid with `domain_mismatch`.
Every certificate inside a chain must also belong to that same domain (R3).
Omission of an enrolled sender's chain does not bypass its current registration.

For the selected identity home's own namespace, a recorded non-default
registry supplies the origin when the `_awid` record omits its registry field.
If `--registry`, `AWID_REGISTRY_URL` or the TXT record names a different
origin, the command refuses and names both origins. When this rule selects
the registry for a presented chain, global key and continuity reads use that
origin too. Otherwise `--registry ORIGIN` fills the DNS default as before.
Registry transport trust is checked independently under the operator's
registry trust settings.
An unavailable DNS root or registry, or a root that no longer agrees with DNS,
cannot produce a valid result. A report is a check against current public
evidence, not a historical proof of a message's delivery time.
A global ID's continuity is only as current as the registry its signed address
or the recorded, explicit or default route selects. The verifier cannot detect
that registry serving an older log.
