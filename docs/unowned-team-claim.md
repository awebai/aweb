# Fully unowned team claims

A member credential authenticates the requester. A claim requires a separate
artifact signed by the team's current registry controller. The admitting host
supplies the canonical team and the prospective owner's normalized email and
username. The host owns account authorization and rechecks ownership under its
final locks.

From the machine with the team controller key, produce the artifact with
`aw id team claim-human-request`. Use the prospective owner's username and email.

```sh
aw id team claim-human-request --namespace acme.com --team research \
  --username owner --email owner@example.com > controller-claim.json
```

The command reads the local team controller key and writes JSON. The prospective
owner submits it from an existing member's identity home within five minutes.

```sh
aw claim-human --username owner --email owner@example.com \
  --controller-claim-file controller-claim.json
```

Both commands trim and lowercase the supplied username and email. The member
signs the submission, and the host verifies the artifact against the current
registry controller. Without the flag, `aw claim-human` uses its existing
member-authenticated request.

The Python `awid.unowned_team_claim` module and the Go `awid` package implement
the canonical artifact. Their shared [team-control request vector](
vectors/team-control-requests-v1.json) pins the signed bytes and the purpose
boundary with ordinary import. The top-level object has
exactly `request`, `signer_did_key`, and `signature`. The canonical UTF-8 JSON
`request` is the Ed25519 preimage and has exactly these text fields:

- `operation` is `claim_unowned_team`.
- `awid_team_id` is the canonical team with surrounding whitespace removed.
- `email` and `username` are supplied by the account owner and signed verbatim.
- `timestamp` is the supplied signed time with surrounding whitespace removed.

`signer_did_key` names the integrity key. `signature` is unpadded standard Base64.
`read_unowned_team_claim` accepts JSON bytes or text, or a parsed object. The
reader rejects extra or duplicate fields, trailing JSON, an incorrect operation,
and serialized input above 16 KiB.

`aweb.unowned_team_claim.verify_unowned_team_claim` verifies the artifact and its
exact target and original signed timestamp, then uses the shared fresh registry
read and key pin to compare the signer with the current controller. The checked
result holds the immutable artifact and verified controller key. The host calls
`require_target` before ownership effects to recheck the target and original
timestamp after waiting for its locks.

The shared controller reader returns 404 `awid_team_not_found` for a confirmed
missing team, 503 `team_control_authority_unavailable` for an unavailable read,
and 422 `registry_response_unusable` for invalid registry data. Claims
preserve these outcomes and the existing key-pin refusal. A malformed claim,
incorrect target, and wrong current controller return 422 with the distinct
codes `team_control_artifact_invalid`, `team_control_target_mismatch`, and
`team_control_controller_mismatch`. Signature and timestamp refusals use the
shared controller error codes.
