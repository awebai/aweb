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
returns its signing `audience`. Invalid input exits nonzero. Alias validation
uses the enrollment rule, which lowercases and trims a nonempty name and
rejects `/`. The team-ID command
uses the SDK input normalization rule, not a stricter signed-field profile.
Canonical URL validation establishes format, not permission to connect to a
destination. The signed record vectors are
[`team-server-record-v1.json`](vectors/team-server-record-v1.json).

## Refusal codes

The machine-readable CLI code list is
[`cli-integration-codes-v1.json`](vectors/cli-integration-codes-v1.json).
It also names invite inspection states and wake verdicts. It does not replace
the registry's or service's own open refusal vocabulary.

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
| `certificate_persistence_incomplete` | Registry issuance succeeded but its recipient copy could not be saved; retain the key and fetch the exact certificate named in the recovery command. |
| `certificate_rollback_pending` | The exact issued certificate could not be revoked during rollback; keep the recipient home and ask the team controller to revoke it. |
| `retirement_receipt_unavailable` | The CLI could not lock or write the retirement receipt; retain the identity home and repair the receipt destination before retrying. |
| `workspace_cleanup_incomplete` | The service did not confirm cleanup of the exact workspace and local identity; reconcile it before revoking the certificate. |
| `invite_issuance_pending` | Issuance is attempted or unknown; keep the exact recipient and record, check online, and resume the retained certificate. Offline cancellation leaves its child untouched. |
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
| `daemon_not_running` | Status reports the daemon stopped, or the control dial finds no listener and the state lock has no owner. A failed dial still appears in `control_error`. |
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
and its known `expires_at`.

Controller invites expire after 24 hours by default. `--expires 48h` selects
a different controller lifetime, up to `720h` (30 days); hosted overrides are
refused because their service owns expiry. Controller preflight computes the
same default or requested lifetime without creating anything. Saved invitations
without an explicit expiry use their creation time plus 24 hours. Native
acceptance reads routing and lifetime from the saved issuer record, never from
unsigned token hints. Unknown or expired invitations refuse with
`invite_unknown_or_expired` and the issuer-reissue action. An attempted issuance
always takes precedence over age and retains its exact recovery record.

`aw id team revoke-invite --invite-id ID --json` locally cancels an unused
controller enrollment. It makes no network request. `status` and `code` are
`cancelled`/`invite_cancelled`, `absent`/`invite_absent`, or
`already_used`/`invite_already_used`. An absent record is idempotent and may
represent a used legacy invite. An established consumed record exits nonzero;
it is never reported as successfully cancelled. A linked child invitation is
voided, or its missing/already-issued disposition is reported. Consumption
retains a secret-free record and its original lifetime metadata as soon as native
registry issuance succeeds, before later recipient writes. A failed recipient
write therefore leaves a used invite and an active certificate, with a recovery
command for that exact certificate.

Before submitting a native certificate, acceptance durably saves its exact signed
bytes, recipient identity home and selected registry inside the existing invite
record. Its shared recovery header reports `attempted`; it is neither unused nor
consumed. `ConsumedAt` is set only after confirmed exact issuance. A failed or
unknown confirmation write keeps the attempt. Offline cancellation refuses an
attempt with `status: attempted`, `code: invite_issuance_pending`, and a retained
linked-child disposition. Its complete `next_step` command includes the original
recipient `--identity-home`, also returned as `identity_home`, when the fence is
readable. Unknown progress is also refused. A definite refusal
of the original registration restores the unused invite and its original token;
an uncertain write or refusal of a later replay does not.

`aw id team check-invite --invite-id ID --json` inspects the existing record and,
when it retains a certificate, reads that certificate's status at its recorded
registry. It returns `state`, `code`, `certificate_id`, `identity_home`,
`registry_url` and `next_step`, without a token or private key. A failed check
exits nonzero. An absent certificate after an uncertain submission does not
clear the attempt or authorize cancellation: the earlier write may still finish.
Unfenced inspection reports `unused`, `expired` or `consumed` from the shared
lifecycle owner, including a validated `expires_at` when available. Unknown
lifecycle evidence is a refusal, not unused state. A revoked certificate returns
an empty `next_step` and a `message` requesting a new invitation from its issuer;
nonempty recovery steps are complete commands rather than guessed issuer homes.

`aw --identity-home HOME id team resume-invite --invite-id ID --json` requires
the original recipient key and home and resumes that same certificate, member
and registry. It never creates another certificate or recipient. An
already-registered reply is successful only when the fetched certificate is
identical and its exact team status is active. Confirmed effects complete local
installation without resubmitting. A stored registry URL records routing, not
private-network admission; the same explicit administrative pin is still needed.

The controller's existing bearer is suspended outside the public issuance
payload while attempted, leaving the released `secret` field empty. Released
acceptors therefore refuse to mint another certificate while ignoring the new
metadata. Confirmation removes both bearer copies. The payload shares the
`RecoveryProgress` version/state header with identity recovery, but retains public
membership proof rather than recipient key custody. No extra journal is created.

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
