---
type: Decision
title: Receipts carry no credential digest
description: An audit receipt names a human-role credential by a random opaque reference the authorization row retains, never by credential_sha256, because a security key under the shared rp_id aweb: has the same digest in every app and a digest in readable receipts would link one holder across apps; matching still recomputes the digest privately. Specified on a review branch, not yet on main.
tags: [decision, privacy, audit, receipts, human-role-holders, passkeys]
timestamp: 2026-11-10
---

**Status (verified 2026-11-10):** specified in
`docs/design/human-role-holders.md`, "What the credential audit retains", at
de9434ce1 on a review branch, not on aweb main. The source reports two
reviewer ACKs; that is agent review, not a human acceptance.

# Decision

- A designate or replace receipt, and a containment receipt that revokes the
  credential, carry as `resource_ref` a random opaque reference. The
  authorization row retains it from the designate or replace, as a completion
  link's reference does for an enrolled key.
- The receipt never carries `credential_sha256`. The authorization row keeps
  the digest, and containment recomputes it from the stored credential to
  find the row. That match is private to the app.

# Why

`credential_sha256` covers the credential id, the public key and the
`rp_id`. The optional terminal security-key profile uses the non-web `rp_id`
`aweb:` in every app, so the same key has the same digest everywhere. Receipts reach readers of the
hook and audit logs. A digest there would let any reader of two apps' receipts
join one holder's activity across them.

# Rejected

**The digest as `resource_ref`.** It looks natural: the row already holds it,
the signed act commits to it, and no extra column is needed. It was first
accepted in review and withdrawn once the `aweb:` case was raised. Web
passkeys are scoped per origin and so differ by app, which hides the problem
until the shared `rp_id` is considered.

# How to apply

Before putting any digest or derived identifier in a receipt, log or other
record readable beyond the app, ask whether its inputs are the same in every
app. If they are, use a per-holding random reference and keep the digest for
private matching.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-10; notes/human-role-audit-identifiers.md.
The rule and its stated reason were checked in the design text at de9434ce1.
The withdrawn acceptance comes from the source note.
