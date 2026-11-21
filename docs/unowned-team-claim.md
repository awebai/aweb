# Fully unowned team claims

A member credential authenticates the requester. A claim requires a separate
artifact signed by the team's current registry controller. The admitting host
supplies the canonical team and the prospective owner's normalized email and
username. The host owns account authorization and rechecks ownership under its
final locks.

`awid.unowned_team_claim` owns the canonical artifact. The top-level object has
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
and 422 `team_control_registry_data_invalid` for invalid registry data. Claims
preserve these outcomes and the existing key-pin refusal. A malformed claim,
incorrect target, and wrong current controller return 422 with the distinct
codes `team_control_artifact_invalid`, `team_control_target_mismatch`, and
`team_control_controller_mismatch`. Signature and timestamp refusals use the
shared controller error codes.
