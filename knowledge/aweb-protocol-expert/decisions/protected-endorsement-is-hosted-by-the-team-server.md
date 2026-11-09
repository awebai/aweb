---
type: Decision
title: Protected endorsement is hosted by the team server
description: A self-hosted team's protected human confirmation of an endorsement runs on the team's own aweb server as a first-party human-role host that reuses naapp-lib's B2, B3 and delivery stages; logs, AWID, a new approvals app, aw on localhost and an app installation were rejected. Only the controller's act binds the endorser passkey, never H's own key. Direction approved and host ruled; contract proposed, not landed.
tags: [decision, human-confirmation, endorsement, passkeys, owner-acts, self-hosting]
timestamp: 2026-11-09
---

A protected endorsement of a deployment identity needs a fresh, user-verified
passkey confirmation that must not depend on any installed app. This decision
records where that ceremony runs, and why the obvious alternatives fail.

**Status (2026-11-09):** the operator approved the direction on 2026-11-09,
and the host (the team server, "S1", over an app installation, "S2") and the
passkey binding (H4 reuse) were ruled in review. Both acceptances are
**source-reported**: the source reported them by aweb mail, and the harvester
cannot read those records. The contract text is a proposal under review
(aweb-acwd.11) and is not on main; it is not accepted until it lands.

# Decision

The ceremony host is the team's aweb server, acting as a **first-party
human-role host**:

- one fixed declaration shipped with the server and known to `aw`: `app_id`
  `team-server`, role `endorser`. There is no manifest and no install;
- an installation id derived per team, not registered;
- the existing human-role acts added to the server's own owner-act vocabulary,
  for that app and installation only;
- naapp-lib's B2, B3, console sessions, handoff and delivery stages reused as a
  library. There is no second WebAuthn verifier and no second copy of the
  delivery checks.

Every self-hosted team already runs this server, so no new service becomes
mandatory, and an operator who never uses protected endorsement configures
nothing.

# Binding the endorser passkey

Only the team controller's `human-role.designate` act binds the endorser's
passkey to H, after a fingerprint comparison over a channel H's custodian does
not control. H's own key never binds a credential to H. B3 claims no
attestation, so a custodian holding H's key could otherwise enrol a software
authenticator and produce user-verified assertions without H's gesture, which
collapses "protected" into plain human-key issuance. This is the "who
authorizes the binding" rule of `docs/design/human-role-holders.md` ("Why this
keeps the boundaries").

The obvious bootstrap, "H's key enrols H's passkey", was proposed for this
design and caught independently by three reviewers. Check every new credential
binding against that rule, however small the binding looks: the bootstrap
passes a superficial row check and still breaks the guarantee.

**Stated residual, not designed past:** when one custodian holds both the
controller key and H's key, the binding adds nothing; that custodian can bind
any authenticator. The contract states this as a limit of protected
endorsement. Do not design a mechanism to close it without a new ruling (see
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)).

# Rejected

- **logs as host.** Endorsing an identity would require an installed audit app
  with its own configuration and hook binding, and logs has no B2. It would
  also turn an audit store into an approval origin.
- **AWID as host.** AWID is the shared public verifier. A human ceremony there
  makes the registry an approval service, and the hosted registry is not a
  path that avoids Cloud.
- **A new approvals app.** It would be a mandatory new service for every team.
- **`aw` verifying its own browser ceremony on localhost.** The verifier would
  be the signer's own machine, so the record is self-attested: plain
  human-key issuance. Every local process shares the localhost relying party,
  so the page shown cannot be trusted.
- **An app installation as host (S2).** Every self-hosted team would have to
  install an app before it could endorse anything.

This composes independent authorities in the same way as
[owner binding needs independent authorities](/aweb-protocol-expert/decisions/owner-binding-needs-independent-authorities.md):
personhood, identity signing and credential provenance stay separate, and none
substitutes for another.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-09; notes/self-hosted-endorsement-origin.md.
The proposed contract is `docs/design/human-confirmation-from-aw.md`,
"Endorsing a deployment identity", at `eec0340db` on a review branch. The
binding rule is in `docs/design/human-role-holders.md` on main at `9a54c7392`.
The rejected hosts are recorded only in the source's note, not in the contract
text.
