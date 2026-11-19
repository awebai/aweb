# Checked team-control admission

Ordinary BYOT import follows the [onboarding contract](byot-onboarding-contract.md):
a fresh controller request authorizes reading live registry facts for import.
The shared signature covers the selectors, not supplied roster rows. Fully
unowned ownership claims follow Antares132d7fc6 and coordinator0597a38a: a
member-authenticated request identifies the asker; the current controller's
artifact authorizes the claim for the exact normalized account.

Both operations use `aweb.team_control_authority.TeamControlAuthorityContext`
(the identical borrowed `CertificateAuthorityContext`). They use the configured
registry client, database and TXT resolver. The factory reads the controller
fresh through the single native key admission owner. Original signed timestamps
keep the existing absolute 300-second window and are rechecked after acquisition.
Hosts recheck original time and exact targets under final locks before effects.
Account/organization authorization, global binding/kind and member request
authentication remain with their existing owners.

## Ordinary import

`aweb.controller_import.verify_controller_import(*, context, request:
TeamImportRequest, controller_signature: str) -> VerifiedControllerImport`
consumes the [shared released request](team-control-requests.md). It reads the
team and complete certificate list through the SDK's public fresh operations,
and fences the snapshot with a second independently admitted controller read.
Registry absence, unreadability or malformed facts import nothing.

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

## Fully unowned claim

`aweb.unowned_team_claim.verify_unowned_team_claim(*, context, claim,
target: UnownedTeamClaimTarget) -> VerifiedUnownedTeamClaim` uses the
shared `read_unowned_team_claim` artifact schema and signature owner.
`claim` accepts the shared artifact, its JSON bytes/text or parsed object.
The frozen target carries `team_id`, `email` and `username`; account values
are normalized by the account owner and compared verbatim.

The checked result retains `artifact` and `verified_team_did_key`.
`require_target(target=...)` rechecks exact account/team and original signed
time after lock waits. Cloud verifies before account/organization or registry
effects, creates/reuses the exact email and revalidates its unowned/account
state through existing ownership locks. The result is distinct from generation
and ordinary member request proofs.

The producer writes the shared artifact as JSON to stdout:

```sh
aw id team claim-human-request --team research --namespace example.com \
  --username owner --email owner@example.com > controller-claim.json
aw claim-human --email owner@example.com --username owner \
  --controller-claim-file controller-claim.json
```

The producer loads the locally held team key and uses the shared CLI target/time
helper and artifact signer/serializer. Its output does not establish the signer
is still current. Submission still needs a member credential; the shared carrier
checks integrity/targets/time, and Cloud decides authority.

## Expected refusals

`aweb.team_control_error_transport.install_team_control_error_handlers(app)`
and `team_control_error_response(error)` own the expected HTTP mapping for
native/outer hosts and middleware respectively. They preserve
`{"detail":{"code":...,"message":...}}` responses.

Malformed claim, target mismatch, invalid signature, stale/invalid timestamp,
wrong current controller and a controller change during import return 422
with distinct `team_control_*` codes and a regeneration instruction.
Unknown controller returns 503 `team_control_authority_unavailable`; missing
or unreadable import roster returns 503 `team_import_evidence_unavailable`.
An enforced key-pin refusal is converted by the common acquisition phase using
the existing `team_key_unverified_exception()` owner: 401 with its unchanged
`team_key_unverified` detail and administrator/retry instruction. It does not
become unknown evidence or an internal 500.
Cloud owns missing-artifact 403 `claim_controller_required` for fully unowned
teams. The organization-owned signup lane retains its own guard.
