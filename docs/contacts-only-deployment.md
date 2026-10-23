# Contacts-only delivery deployment

For aweb-ackf and aweb-ackh, qualify the OSS server and Cloud normalizer as one
candidate. Release coordinator owns publication and embedded package pins. Do
not route strict contacts-only traffic to an old replica: old code interprets
`contacts_only` as `team_and_contacts`, including during a rolling deployment.
Enable strict provisioning only when every serving replica enforces it.

Migration 037 first converts existing legacy `contacts_only` agent rows to
`team_and_contacts`, preserving their previous effective behavior, then widens
the CHECK. Existing differing membership policies need no unification migration:
delivery uses the strictest valid policy across all non-deleted rows for the
exact `did:aw`. Retired rows still count. The next identity-authorized PATCH
sets every live row uniformly. New memberships inherit the effective policy.
Any missing or invalid row policy refuses delivery with migration-required;
confirm the deployment's read-only mixed-policy inventory before release.
Connecting a global identity into a new team also refuses with migration-required
while any live membership has a missing or invalid policy. Support must resolve
that migration state before retrying the new-team connection.

Cloud must use the public `aweb.inbound_modes` services rather than a second
mode table or locking algorithm. `effective_inbound_mode(db, did_aw)` reads the
identity policy. Within a caller transaction, `for_share=True` locks all rows
in stable order for delivery; `for_update=True` locks before checking mutation
authority. `set_identity_inbound_mode(tx, did_aw, mode)` locks and updates all
live rows; the caller must establish identity-level authority in that same
transaction. The lock options are mutually exclusive. A provisioning default
is used only if there are no existing rows, never for missing policies.

A self-custodial or BYOD identity sets its own policy with a signed request
whose global identity binding authentication has verified;
Cloud team owners cannot change it. For a custodial identity, only owner/admin
of the organization owning its address namespace may act on its behalf, with
custody and namespace ownership checked under lock. New identity provisioning
defaults remain caller-owned; acke explicitly retains `team_and_contacts`.
Cloud's legacy unconsumed contacts-only invites intentionally create strict
recipients at consumption; already-consumed identity recovery is unchanged.

Clients must verify that a requested mode was applied. A successful response
from an older server may contain a downgraded value. The B2 CLI compatibility
change and the OATS steward's explicit post-create assertion are required parts
of the combined acceptance; neither a 200 response nor an unpublished local
source override establishes release qualification.
