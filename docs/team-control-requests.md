# Team-control request signatures

The Python `awid.team_control_requests.TeamImportRequest` verifier accepts the
released `aw id team import-request` preimage for ordinary BYOT import. Its
canonical UTF-8 JSON has exactly these six fields:

- `operation` is `byoidt_import`.
- `awid_team_id` is the supplied canonical team, with surrounding whitespace removed.
- `organization_id` and `team_id` are the supplied selectors with surrounding whitespace removed. An absent selector becomes an empty string in the preimage.
- `dry_run` is a boolean.
- `timestamp` is the supplied time with surrounding whitespace removed.

The request object retains its original nullable selectors. Use
`signing_bytes()` to obtain the preimage and
`verify_signature(signer_did_key=..., signature=...)` to verify the controller
signature against the independently obtained key. The SDK test verifies the
exact bytes and signature pinned by the released Go command's import test.

The preimage covers selectors and the timestamp. It has no audience or nonce.
The signed body can be replayed while its timestamp is within 300 seconds of
the verifier's clock. See [checked import admission](team-control-admission.md)
for controller freshness and roster checks.
