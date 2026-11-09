---
type: Lesson
title: Passkey challenges bind no app or origin
description: The B3 approval and login challenge preimages commit to the approval, candidate, nonce, policy, purpose and request hash but not to the app or its origin, so under a per-app browser RP ID the browser's attested origin is what isolates apps; a profile that shares one credential across naapps through a native client moves that isolation into one client rule, pinned origin and no redirects.
tags: [lesson, passkeys, webauthn, naapp, confused-deputy, authority]
timestamp: 2026-11-08
---

The B3 challenge preimages, `aweb.approval-challenge/1` and
`aweb.passkey-login/1`, commit to the approval, the candidate subject, the
nonce, the policy, the purpose and the request hash (login: nonce, scope and
subject). They do not commit to the naapp or its origin. Reading the preimage
fields shows this. It does not show that something else was carrying the
isolation between apps.

Under a per-app browser RP ID that something is the browser. The browser
writes `clientData.origin` itself, and the verifier derives the RP ID from that
origin's hostname and re-checks both. An assertion one naapp collects cannot be
replayed at another.

# How to apply

- **A shared credential profile moves app isolation into the client.** A
  profile that lets one credential serve several naapps (for example a
  non-web RP ID such as `aweb:`, with a native client writing `clientData`)
  has no browser-attested origin. The client must then:
  - set `clientData.origin` to the installation's pinned human origin;
  - fetch challenges from, and post assertions to, only that origin;
  - follow no redirects.
- **Without that rule a naapp can relay another naapp's challenge.** It
  redirects the client to the other naapp's challenge endpoint, the human
  signs, and it forwards the assertion. Nothing in the preimage would show
  the switch.
- **Retained evidence says less under such a profile.** It proves "this
  credential signed this challenge, with the client reporting origin X". It
  does not prove a browser-attested origin, and it must not be described as
  if it did.
- **Do not fix this by adding an app field to the preimage.** The existing
  constructions are frozen ("keep the existing constructions unchanged" in
  `docs/hook-events.md`). A changed construction is a new versioned
  construction and a contract change, not a field addition.
- **Elimination route.** When a native client exists, the pinned-origin and
  no-redirect rule belongs in that client's tests: a redirect to another
  origin must be refused, not followed. Until then, this lesson is the only
  guard against designing a shared profile without it.

**Status:** no shared or native profile is on main. The profile that surfaced
this (a non-web RP ID serving every naapp) is a proposal awaiting the
operator's rulings, and this lesson does not record it as decided. The
property of the preimages holds whatever that ruling is.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/designation-act-binds-the-credential.md.
The redirect relay was found in security review of that proposal and fixed
before it was ACKed. Checked against aweb main 06e61e395:

- `docs/hook-events.md`, "Challenge and covered request": the field sets of
  the approval and login preimages, with no app or origin field.
- `naapp-lib/src/aweb_naapp/runtime/passkeys/proof.py`: the retained-proof
  check derives the RP ID from the retained origin and requires it to equal
  the retained RP ID.
