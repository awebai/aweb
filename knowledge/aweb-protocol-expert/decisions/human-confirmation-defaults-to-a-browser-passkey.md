---
type: Decision
title: Human confirmation defaults to a browser passkey
description: Protected naapp operations started from aw are confirmed by default with a browser passkey ceremony on the app's human origin, so platform, phone and synced passkeys all qualify; a terminal security key under rp.id aweb: is optional and never part of default acceptance, a plain human-key signature is never an approval, and a native-only profile was rejected. Ruled, not yet on main.
tags: [decision, passkeys, webauthn, naapp, approvals, human-identity]
timestamp: 2026-11-08
---

Ruled by the operator; the ruling was relayed to the source seat by mail on
2026-11-08. The acceptance is **source-reported**: the harvester could not
read the record.

**Status:** ruled direction. The design that applies it is on a review
branch and not on aweb main at 06e61e395. The other open questions of that
design are not covered by this ruling and are not recorded here.

# Decision

- **The default gesture is a browser passkey.** When `aw` starts a protected
  naapp operation, it opens a passkey ceremony in a browser on the app's human
  origin. Touch ID, Windows Hello, a phone and password-manager passkeys all
  qualify. A browser used only for the gesture is enough; the human does not
  need to work in the browser otherwise.
- **A terminal security key is optional.** A credential under the non-web
  rp.id `aweb:`, used from the terminal, may be offered. It is never required
  and never part of default acceptance: a naapp accepts it only where an owner
  explicitly bound it. Keeping the two profiles apart needs the rule in
  [without attestation, only the bound rp_id separates credential profiles](/aweb-protocol-expert/lessons/without-attestation-only-the-bound-rp-id-separates-credential-profiles.md).
- **A plain human-key signature is not an approval.** It does not prove a
  fresh human gesture, so it is not offered as one.
- **A notice-only email contact stays where a role declares it.** Roles that
  declare one (in the secrets app, owners and issuers) keep an email contact
  for notices. It never carries an enrolment or approval link.

# Rejected

**Native-only confirmation**, which required a security key for the gesture.
It excluded platform and synced passkeys, which are what most humans have.

# How to apply

A future design of approval UX starts from the browser ceremony. It does not
reopen a security-key requirement or propose human-key approvals. Changing
either needs a new ruling from the operator.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/no-attestation-means-rp-id-separates-profiles.md.
The earlier native-only proposal was never accepted knowledge, so this
supersedes no concept.
