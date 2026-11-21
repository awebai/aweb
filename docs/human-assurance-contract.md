# App authorization transition notes

The [human approval architecture](human-approval-architecture.md) is the target
reference. The candidate-only in-tree signer, root approval and unattended
admission commands have been removed. Root approval and unattended admission
through a key holder are not built. Team admission works as in the stable
release.

Application passkeys, exact-act approvals, owner acts and credential/session
handoffs remain until the application gates move to awsign. Their current
contracts are [owner acts](owner-act.md), [owner-act delivery](owner-act-delivery.md),
[human-role holders](design/human-role-holders.md),
[handoff wire](design/handoff-wire.md) and the
[shared passkey/approval API](../naapp-lib/README.md). Those documents retain the
application's holding, membership, UV, original-transaction, replay, recovery,
notification and credential-retirement requirements. This transition file does
not provide a signer API or a second approval-service protocol.

## Independent facts and authorities

Login proves account access. A verified `kind=human` ID certificate records
that its issuer vouches for one person. A passkey assertion with user
verification (UV) proves use of that enrolled credential with its UV factor.
None alone proves that a person understood an act. The current B3 verifier
does not distinguish software from hardware authenticators or establish
hardware attestation. Stronger requirements need explicit policy and tests.

Ancestry answers who is responsible; it grants neither membership nor resource
access. Membership is team-controller authority. An address is
namespace-controller authority. Custody says who can use a private key. A
verified nearest human, account association, team owner, role holder and
credential holder are distinct facts and must not substitute for one another.
For a human leaf, the responsible human is the leaf itself.


## App sessions: direct-child preparation, H's own login

For app `session` purpose, use the app's own B3 LOGIN and explicit Allow; there
is no protected-service LOGIN or H-signed intermediary start. The paired wire
delta is [handoff-wire section 1a at 27169df70](https://github.com/awebai/aweb/blob/27169df70f04aae137d214697ffd1155e11a64e2/docs/design/handoff-wire.md).
This changes only session-start admission, not human signing or governance.

A current agent member Q whose freshly verified chain has H as its **direct**
human parent may prepare H's app-session start. Q signs team-auth v2 with Q's
OWN current team certificate, and sends Q's chain in `X-AWID-ID-Chain` using
the existing encoding. The signed start body preserves aw's purpose, scope,
client_key, redirect_uri and verifier_sha256; scope.principal is H. The body
carries no certificate of H: `holder_certificate` is refused with HTTP 400
`handoff_invalid` on every start. The factory loads H's certificate from the
exact holding's retained evidence. It never substitutes for Q's team-auth
admission. A registered non-member laptop is refused; this change adds no
possession-proof app start surface.

Before creating a handoff the app verifies Q's chain for Q's registered did:aw
and the key authenticated by team-auth, with the existing status bound of
60 seconds, current head and no revoked edge. Q's own leaf certificate must
have H as its direct issuer, and that issuer's own verified kind must be human.
A deeper descendant with the same nearest human does not qualify. The app
independently verifies H's retained holding certificate under the current team
key for the installation's team and member_did_aw=H, current published/unrevoked
membership, H's own human
kind and H's exact current holding. Retain H's certificate as session evidence.
Q's ancestry authorizes preparing this request only: it is never H's LOGIN,
membership, holding, session, resource grant or exact-act approval.

A supplied `holder_certificate` is 400 `handoff_invalid`; an ineligible direct
edge is 403 `scope_not_signer`. Missing, renewed, replaced or otherwise unusable
retained membership evidence is `principal_not_member`, and H's failed own-kind
check is `principal_not_human`. Q can neither supply nor refresh that evidence.
aw explains that the app's retained membership record is not current and names
the H-signed credential-start refresh in the handoff wire reference. Unavailable chain/certificate
status is 503 `principal_status_unavailable`, not a manufactured mismatch.
Other existing handoff refusal rules remain. The page records/displays
`requester: {id,address,key_fingerprint}` separately from H before H's app-RP
UV LOGIN and the separate explicit Allow. Only aw's in-memory ephemeral key,
verifier preimage and single-use loopback code can collect the existing result.
The resulting session is H's, with its exact holding and current membership
checks unchanged. No other purpose, including `credential`, gains this
same-signer exception. A Q-not-H session is **loopback only**:
`return: user_code` refuses with HTTP 400 `handoff_invalid` before any handoff
is created, whether or not the forbidden certificate field is also present.
H's own same-signer fallback is unchanged.

aw derives H from Q's installed direct-parent chain and shows both identities.
ID creation, team admission and application authorization remain separate.
Ordinary ID creation and parent/child exchange are documented in
[id certificates](id-certificates.md); ordinary membership still needs a
certificate under the team's admitted key.
