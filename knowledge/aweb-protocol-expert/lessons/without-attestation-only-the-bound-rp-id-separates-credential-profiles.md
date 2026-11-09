---
type: Lesson
title: Without attestation, only the bound rp_id separates credential profiles
description: A relying party that requests no attestation cannot tell a browser from a native CTAP client, because the client writes clientData and picks the rp.id, so a registration record or a client-kind flag is not a check; two credential profiles stay apart only when the binding act names the credential's rp_id and every assertion is verified under that rp_id alone, which the authenticator enforces through rpIdHash.
tags: [lesson, passkeys, webauthn, naapp, attestation, authority]
timestamp: 2026-11-08
---

The naapp passkey verifier requests no attestation. Registration checks the
challenge, the origin, the RP ID and user verification, and nothing about the
authenticator or the client. A native CTAP client can choose any rp.id and
write any `clientData` origin, so it can also produce a registration that
looks like a browser registration.

# What cannot separate profiles

- **A "registered in a browser" record.** Without attestation it proves
  nothing about the client that made it.
- **A client-kind flag.** It is the client's claim, not evidence.

A design that "keeps native credentials out of the browser profile" through
registration provenance believes in a check it does not have.

# What does

- **The authenticator's rpIdHash.** The authenticator computes the rpIdHash
  itself and puts it in every assertion. A credential created under one rp.id
  cannot answer an assertion verified under another: a credential created
  under `aweb:` cannot answer one verified under the app's hostname, and the
  reverse.
- **So the binding names the rp_id.** The act that binds a credential to a
  holder names the credential's rp_id, and the app verifies every assertion
  for that holding under that rp_id only, never under "any accepted" rp.id.
- **An optional profile is then accepted only where it was bound.** This is
  what keeps the optional terminal key out of default acceptance in
  [human confirmation defaults to a browser passkey](/aweb-protocol-expert/decisions/human-confirmation-defaults-to-a-browser-passkey.md).

**Status:** on aweb main at 06e61e395 there is one profile. The RP ID is the
app origin's hostname, and retained proof requires the retained rp_id to equal
that hostname. The rule matters once a second profile exists. The binding
design that applies it is under review and is not recorded here.

**Elimination route.** When a second profile lands, the rule belongs in tests:
an assertion from a credential bound under one rp_id must be refused when
verified under the other, in both directions.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/no-attestation-means-rp-id-separates-profiles.md.
Checked against aweb main 06e61e395:

- `naapp-lib/src/aweb_naapp/runtime/passkeys/webauthn.py`: registration
  verifies challenge, origin, RP ID and user verification, with no
  attestation check.
- `naapp-lib/src/aweb_naapp/runtime/passkeys/rp.py`: the RP ID is the
  origin's hostname.
- `naapp-lib/src/aweb_naapp/runtime/passkeys/proof.py`: retained proof
  requires the retained rp_id to equal the retained origin's hostname.
