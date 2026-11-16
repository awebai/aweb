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

Verification uses public registry reads and DNS; it is independent of an aweb
messaging server, rather than disconnected from the network. It neither selects
an acting identity nor writes local identity or trust state. Encrypted exports
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
invalid evidence. Initial creation without a transition must name the first key
in that ID's independently verified public log; a different first key is
`creation_key_inconsistent`, and an unavailable log is reported as unavailable.
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
its signed address selects the key registry, or an explicit `--registry` or the
default public registry supplies that route when the signed sender is an alias.
Only fresh, subject-bound enrollment evidence selects the ID-tree domain, and
a presented chain in another domain is invalid with `domain_mismatch`.
Every certificate inside a chain must also belong to that same domain (R3).
Omission of an enrolled sender's chain does not bypass its current registration.

`--registry ORIGIN` has the same restriction as `aw who`: it supplies a registry
when the domain's `_awid` record names none (the built-in default counts as none),
and cannot override a different registry named by DNS. It also explicitly selects
a private self-hosted registry. Ordinary registry transport requires HTTPS;
the disposable real-service journey permits HTTP through development mode only.
An unavailable DNS root or registry, or a root that no longer agrees with DNS,
cannot produce a valid result. A report is a check against current public
evidence, not a historical proof of a message's delivery time.
A global ID's continuity is only as current as the registry its signed address
or explicit/default key route selects; this stateless outside verifier cannot detect that
registry serving an older log.
