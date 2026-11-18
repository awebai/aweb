# CLI contracts for orchestrators

Use `--json` and the process exit status. Human error sentences remain useful
for operators, but machine consumers should read codes rather than classify
sentences. The acting identity follows [identity selection](cli-identity-selection.md).

## Recorded initialization and membership

`aw id status --team T --json` reads the selected home's recorded state without
network access or credential renewal. It returns:

- `signing_key_present`, `identity_present`, `identity_registered`, `did`,
  `stable_id`, `address`, and `alias`;
- `certificate_present` and `certificate_id` for the selected team;
- `workspace_bound`, `workspace_id`, and `service`;
- `partial_init: {present, stage}` and `pending_hosted_accept`;
- `registry_status` and `mint_complete`.

`partial_init.stage` is `absent`, `identity_prepared`, or `response_received`.
The response exposes marker presence and stage, never its contents. For global
identities, `registry_status` is recorded `registered`, `pending`, or `unknown`;
local membership uses `not_applicable`. `mint_complete` requires a key, identity,
registration where applicable, team certificate, and workspace binding, with no
unfinished initialization marker. It proves recorded completion, not live
registry freshness. Missing state is incomplete; corrupt or unreadable state
fails with a repair instruction.

`aw id team list --json` always includes `registry_url`, `aweb_url`,
`certificate_id`, and `workspace_id` strings on every membership. Absent values
are empty strings. These are recorded coordinates, without discovery or network
validation. `aw id cert show --team T --json` selects T even when another team is
active, including the legacy certificate layout when no teams state exists.
`aw workspace status --json` always includes `team`, including `[]` for a
singleton workspace.

`aw check --online --json` retains the doctor report and exits nonzero if a
check fails. `aw doctor` remains a report command. `aw init --join-from SOURCE
--join-team T --identity-home FRESH --name NAME` performs the invite and join in
one process without returning its token. FRESH must be explicitly selected and
free of existing identity credentials or workspace bindings; an inherited identity home is never an implicit creation destination.

## Validation

These identity-independent commands use the existing CLI or SDK owner and make
no network requests:

```sh
aw validate alias NAME --json
aw validate team-id NAME:DOMAIN --json
aw validate team-server-url URL --json
```

They return `kind`, `input`, `valid`, and `canonical`; the URL command also
returns its signing `audience`. Invalid input exits nonzero. The team-ID command
uses the SDK input normalization rule, not a stricter signed-field profile.
Canonical URL validation establishes format, not permission to connect to a
destination. The signed record vectors are
[`team-server-record-v1.json`](vectors/team-server-record-v1.json).

## Refusal codes

The existing JSON error envelope carries `error.code`, `error.message`, and,
for service refusals, `http_status`, `detail`, and `reason` where available.
Service registration preserves the service's own refusal code as `error.code`
and `reason`; unrecognized codes are retained. Service codes remain owned by
the service, rather than becoming a universal CLI vocabulary.

| CLI code | Meaning and action |
| --- | --- |
| `invite_not_created` | Team creation completed without an invite; follow the retained `--admission-team-id` alternative in the message. |
| `alias_conflict` | A membership already holds this alias; recover that membership or choose another alias. |
| `outcome_unknown` | A write may have applied; inspect the recorded operation before retrying. |
| `controller_key_missing` | The required controller key is unavailable here; use the installation or key-holder command in the message. |
| `team_name_taken` | The registry pins this team to another controller; restore that key or choose another team name. |
| `grant_not_found` | The selected team has no such grant; run grant list in that team and identity home. |
| `team_server_record_missing` | No signed service record is published for this team; its controller must register the service. |
| `invalid_alias`, `invalid_team_id`, `invalid_team_server_url` | Correct the input using the validation command's remedy. |

The aweb service registration owner is
[`service_registration.py`](../server/src/aweb/routes/service_registration.py).
Its current refusals include `service_url_mismatch` (select the team's service),
`awid_team_not_found` (register the team), `awid_team_controller_mismatch`,
`invalid_controller_signature`, and
`invalid_controller_timestamp` (repair controller selection, key or signing
time), and `validation_error` (correct the request). Consumers may give unknown
codes a generic remedy while displaying the code. Consumers may also encounter
`awid_team_missing_controller`; preserve that code and repair the controller
configuration. Federated mail/chat errors have a separate
[owner-published reference](federation-error-reference.md); they are not the team
registry or service-registration vocabulary.

## Wake readiness

`aw wake status --home HOME --min-daemon-version VERSION --json` adds a
`readiness` object while retaining the existing status fields. Without `--home`,
`readiness` is an array with one verdict per reported instance. The minimum
version is caller policy. Each verdict returns `home`, `ready`, `code`, `reason`,
`daemon_version`, `updated_at`, `last_inspect_at`, and `advisories`.

A ready verdict has code `ready`. Non-ready codes are:

| Code | Condition |
| --- | --- |
| `daemon_unavailable` | Control failed; `control_error` retains the error. This does not prove process absence. |
| `daemon_not_running` | Status reports the daemon stopped. |
| `daemon_version_unknown`, `daemon_outdated` | Version cannot establish the caller's requirement. |
| `home_not_registered` | No saved registration or live row for HOME. |
| `registration_mismatch` | Live delivery, primary identity, binding set or pending/conflicting registration differs from the saved registration. |
| `foreign_grant_home` | A grant seat receives through another grant home. |
| `stream_not_connected` | A registered receive stream is not live and admitted. |
| `worker_not_running`, `worker_error` | Delivery worker stopped or reports an error. |
| `paused`, `binding_error`, `inspection_failed` | Paused delivery, binding refusal or failed inspection. |
| `endpoint_unusable`, `session_waiting` | Endpoint cannot accept agent input, or awaits a person/session action. |
| `status_timestamp_unknown`, `observation_invalid` | Missing snapshot timestamp, future observation or inspection after the snapshot. |

`observation_aged` (over 30 seconds), `observation_unproven` (missing inspection
or readiness evidence), and `inspection_pending` are advisories. Age alone
never makes an idle healthy receiver fail. The query does not force inspection
or certify recent observation, delivery, or consumption. Fix registration drift
by idempotently registering the caller's current binding facts again.

## Invite planning and cancellation

`aw team invite --preflight --team-id T --json` and
`aw id team invite --preflight --team-id T --json` use the same authority plan
as minting. They return `team_id`, `kind` (`hosted` or `controller`),
`expiry_known`, and `expires_at`, without creating a token, secret, child invite,
or identity key. An unknown expiry is an empty string; consumers display the
returned expiry rather than infer a lifetime. Mint output includes `invite_id`
and `expires_at`.

`aw id team revoke-invite --invite-id ID --json` locally cancels an unused
controller enrollment. It makes no network request. `status` and `code` are
`cancelled`/`invite_cancelled`, `absent`/`invite_absent`, or
`already_used`/`invite_already_used`. An absent record is idempotent and may
represent a used legacy invite. An established consumed record exits nonzero;
it is never reported as successfully cancelled. A linked child invitation is
voided, or its missing/already-issued disposition is reported. Consumption
retains a secret-free record and its original lifetime metadata.

Cancellation does not revoke an issued certificate. `next_step` names
`aw id team remove-member` for that separate controller-authorized operation.

## Retirement and owner log access

For retirement results, retained credentials and controller-only retries, see
[orchestrator cleanup](orchestrator-integration.md#stale-local-identity-workspace-cleanup). Complete retirement
requires `alias_released: true`, not merely `identity_deleted: true`.

Sealed logs use the existing owner reader described in
[configuration](configuration.md#local-message-logs):
`aw log read FILE... --json` accepts explicit file paths and emits decrypted
entries as JSON lines. It needs the owner's encrypted log keys in the local
keychain and an interactive passphrase for every distinct key encountered.
There is no automatic agent access or stdin/passphrase flag. Retain unreadable
boundaries: the reader can emit a readable prefix and then fail. A recorder
must not advance past unreadable input or infer whole-source success from that
prefix. Decrypted entries remain untrusted input.
