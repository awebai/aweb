---
type: Decision
title: A holding with no notice contact refuses self-service credential changes
description: A holding with no effective notice contact refuses the holder's own passkey add and replace with no_notice_contact, because the owner-side governance event does not reach the holder the attack harms; such holdings change credentials only through the owner's controller recovery. Frozen in a contract on a review branch, not yet on main.
tags: [decision, security, credentials, notices, passkeys, human-assurance]
timestamp: 2026-11-11
---

**Status (verified 2026-11-11):** frozen in `docs/human-assurance-contract.md`
at 584d76c9c on a review branch, not on aweb main. Ruled by the security
reviewer with the server lane; the proposing seat first argued the opposite
and withdrew.

# Decision

- A holding with no effective notice contact refuses current-passkey add and
  replace with `no_notice_contact`, before any challenge and again under the
  effect lock. A pending-only contact counts as none.
- Such a holding changes credentials only through the owner's controller
  recovery (`human-credential.replace`), which stays available. No role
  declaration, mailbox resolver or delivery subsystem is added to get around
  the rule.

# Why

A stolen passkey with its user-verification factor can add a credential;
notices give detection, not prevention. The notice exists so the holder, the
victim of the theft, learns that a credential was added. The
`post-governance-hook` event goes to the team owner, who sees "credential
added" with no way to know it was fraudulent, so it is not a holder-side
detection channel. Refusing is cheap: a no-contact holder who loses a device
goes through controller recovery, and a holder such as a reader is easy to
re-designate.

# Rejected

- **Treating the owner-side governance event as enough detection for
  no-contact holdings.** Argued in review, then withdrawn.

# How to apply

When a detection argument names a channel, check who receives it. Detection
must reach the party the attack harms.

Related: [a credential-cap change records policy.changed](/aweb-protocol-expert/decisions/credential-cap-change-records-policy-changed.md),
from the same credential work.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-11; notes/no-contact-holding-refuses-self-credential-change.md.
The refusal, its timing and the controller-recovery path were checked in
`docs/human-assurance-contract.md` at 584d76c9c. The rejected argument and its
withdrawal come from the source note.
