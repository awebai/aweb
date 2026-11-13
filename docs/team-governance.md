# Typed team governance

This consumer is being implemented under the signer catalog. The typed values
and codecs described here are present; the effect store, admission, host/CLI
mounts and execution evidence are not complete. Registering a codec does not
enable a supported signing or mutation route.

Team ownership and the controller's permitted operations are separate records
from installed-app administrators, ordinary membership, passkey credentials and
the controller's public key. Neither record grants an agent human governance
powers. Changing either requires the catalog's exact live approval.

Both changes use the existing `aweb.owner-act/1` format and opt-in vocabulary,
not a new signature scheme or a sign-bytes endpoint. Existing app, contact and
hook receiver allowlists do not gain these acts.

| Act | Exactly these subject members |
| --- | --- |
| `team.owner.change` | `team_id`, `old_owners`, `new_owners`, `expected_revision` |
| `team.controller-permissions.change` | `team_id`, `old_permissions`, `new_permissions`, `expected_revision` |

Owner values are arrays of stable `did:aw` identifiers. Permission values are
arrays of exact `operation/variant` catalog entries for the team-controller
key. Arrays have at most 64 distinct strings, ordered by code point. No wildcard
or implicit future variant exists. Owner identity syntax is not proof of human
kind, current membership, consent, or an enrolled working credential: admission
must independently check those facts as required for this exact effect.

Permissions constrain the selected controller, rather than assigning roles to
the caller. Listing a live-floor operation never removes its approval
requirement; listing an unattended operation never supplies a root endorsement
or widens its admission bounds. Namespace and human-identity operations cannot
be added to a team controller's permissions.

Owners and permissions share one revision, a positive portable JSON integer.
An effect must hold the current record in its original transaction, require
both the exact revision and the corresponding old values, then increment the
revision once. A change to either set invalidates an act prepared against the
older revision, even if the other set did not change. The last owner cannot be
removed. Revisions cannot overflow the portable integer range.

The pure `GovernanceState` transition validates values and expected state; it
is not admission evidence and performs no write. The consumer must additionally
admit current owner/controller authority and the exact approved operation,
preserve the original deadlines through its last await, and commit state,
single-use consumption, exact-result receipt and governance audit together.
Bootstrap remains a distinct operator-authorized initial action; these changes
must not create a record on a miss or reuse an installed-app administrator row.
