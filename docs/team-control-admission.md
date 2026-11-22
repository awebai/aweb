# Checked team-control admission

Ordinary BYOT import follows the [onboarding contract](byot-onboarding-contract.md#optional-hosted-projectionimport).
A fresh controller request authorizes checking live registry facts for import.
The signature covers the signed selectors. The verifier acquires the roster from AWID.

The verifier uses the host's borrowed `CertificateAuthorityContext`: its configured
registry client, database and TXT resolver. It reads the controller through the
native key admission owner. Callers recheck the original signed time and exact
targets under final locks before effects. The host authorizes its accounts and
organizations. Global binding, identity kind and member authentication keep
their existing owners.

A signed request can be replayed while its timestamp is within 300 seconds of
the verifier's clock. It has no audience or nonce. Keep the signed body private
and generate one close to submission.

## Ordinary import

`aweb.controller_import.verify_controller_import(*, context, request:
TeamImportRequest, controller_signature: str) -> VerifiedControllerImport`
consumes the [shared released request](team-control-requests.md). It reads the
team and complete certificate list through the SDK's public fresh operations,
and fences the snapshot with a second independently admitted controller read.
The verifier imports nothing when registry evidence is unavailable or invalid.
Embedding routes using the native error adapter preserve these outcomes:

| Evidence | Status and code | Operator action |
| --- | --- | --- |
| AWID confirms the team is unregistered | 404 `awid_team_not_found` | Select a registered team or register it before importing. |
| Controller or roster read fails | 503 `team_control_authority_unavailable` or `team_import_evidence_unavailable` | Retry when the registry can be read. |
| AWID returns invalid team or certificate data | 422 `registry_response_unusable` | Ask the registry operator to correct the team record before importing. |

The adapter logs invalid registry evidence at error level. The released
`aw id team import-request` command only prepares the signed body. The
provider receiving that body returns the import outcome.

The immutable batch retains `request`, `controller_signature`,
`verified_team_did_key`, typed registry `team`, complete `certificates` tuple
and `members` tuple. Original organization/local-team selectors, dry-run flag
and timestamp remain in the request; the factory accepts no roster input.
Revoked certificates remain in the planning snapshot. Only nonrevoked rows of
an apply request yield `VerifiedControllerImportMember`; a preview yields no
native admission inputs. Planning/conflict counts use the same snapshot.

Each member input retains `request`, `controller_signature`,
`verified_team_did_key` and exact typed SDK `certificate`; `team_id` derives
from its signed canonical team. Certificate fields are `certificate_id`,
`member_did_key`, `alias`, `identity_scope`, `member_did_aw`, `member_address`,
`issued_at` and `revoked_at`. Both result types expose `require_freshness()`.
No signed member artifact or fingerprint is implied. Independent fresh global
binding/kind observations are still required by their existing owners.

The sole native constructor's consumer takes the distinct `controller_import=`
input, rejects contradictory/mixed proofs and rechecks the admitted key under
the team lock. Projection remains its work: exact planned agent/workspace IDs,
always ensuring the workspace, preserving reused profile/repository/host/path.
Pending custodial activation remains the actual-artifact generation path.
