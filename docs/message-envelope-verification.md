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

The chain's domain selects its own DNS authority and registry. A global sender
without a presented chain is checked for enrollment through public key reads:
its signed address selects the key registry, or an explicit `--registry` or the
default public registry supplies that route when the signed sender is an alias.
Only fresh, subject-bound enrollment evidence selects the ID-tree domain.
Omission of an enrolled sender's chain does not bypass its current registration.

`--registry ORIGIN` has the same restriction as `aw who`: it supplies a registry
when the domain's `_awid` record names none (the built-in default counts as none),
and cannot override a different registry named by DNS. It also explicitly selects
a private self-hosted registry. Ordinary registry transport requires HTTPS;
the disposable real-service journey permits HTTP through development mode only.
An unavailable DNS root or registry, or a root that no longer agrees with DNS,
cannot produce a valid result. A report is a check against current public
evidence, not a historical proof of a message's delivery time.
A global ID's continuity is only as current as the registry its chain domain
or signed address selects; this stateless outside verifier cannot detect that
registry serving an older log.
