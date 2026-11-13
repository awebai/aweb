# Protected owner log-key signing

`team.log-key.sign`, variant `default`, is an additive team-controller catalog
act. It uses the same exact-request B2 commitment, live B3 approval and receipt
path as the other protected acts. A changed log key changes who can read future
local logs; this act is never unattended. Re-signing after controller replacement
is also a new live act. Exact receipt recovery does not make a new signature.

The protected CLI uses the same retained-request handoff as the other acts:

```sh
aw team admin log-key sign --record public-log-key.json --protected-profile signer.json --approver did:aw:<human> --out signed-log-key.json
aw team admin log-key resume <operation-id> --protected-profile signer.json --out signed-log-key.json
```

The sign command reads only the public record, public profile and requester
identity. It does not load a controller key. Resume uses the exact saved request
instead of a replacement record file. The CLI verifies the committed bytes and
signature against the profile pin using the shared AWID log-key helpers, writes
the signed public record, then removes its saved request. A failed write or
invalid receipt retains the request. Explicit offline and external-attachment
routes remain separate and cannot be combined with the protected route.
Native/browser and installation qualification of this addition are still pending.

The ordinary protected envelope names the exact configured scope and uses the
profile's request origin as `audience`. Its `subject` has exactly:

```json
{"team_id":"demo:example.org","key_id":"sha256:<derived-key-id>","public_key":"<public-X25519-key>","created_at":"2026-11-12T00:00:00Z"}
```

`public_key` is exactly 32 public X25519 bytes in unpadded standard base64.
`key_id` is the existing E2EE encryption-key ID calculation: `sha256:` followed
by unpadded standard base64 of SHA-256 over `aweb-e2ee-v2 encryption-key` plus LF
plus the raw public key. `created_at` stays exactly as requested, in canonical
UTC seconds. The subject team must equal the scope's controller authority.
The log private key remains on the owner's reading machine/keychain; no private
log key, caller signature or generic signing bytes enter this request.

The signer injects `v=1` and its independently current, pinned `team_key_did`.
The complete approval freezes all six unsigned record fields. Signing bytes are
exactly `aweb.log-key/1` plus LF plus canonical JSON of
`{v,team_id,key_id,public_key,created_at,team_key_did}`. No owner-act envelope is
added around this existing record encoding.

The shared receipt retains `result.signing` (padded standard base64 of these
exact bytes) and `result.signature` (padded standard base64 of the 64 signature
bytes). The CLI must verify the retained request, prefix, canonical bytes and
profile authority, then materialize the existing seven-field record with an
unpadded standard base64 signature. Installation still verifies the record
against the host's own team certificate; a response cannot replace that trust.
Signing alone does not claim that the record was installed.

The original frozen catalog is unchanged. Its explicit additive selector and
classification are in `docs/vectors/human-assurance-log-key-v1.json`. The same
operation table and approval engine consume the base and extension.
