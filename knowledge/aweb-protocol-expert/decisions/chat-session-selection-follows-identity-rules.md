---
type: Decision
title: Chat session selection follows the chat identity rules
description: aw chat selects an existing session by the governing chat identity rules (strong identities win; a bare alias is a fallback only when it names exactly one concrete participant across pending and listed conversations; ambiguity fails closed), and a DID aw has just confirmed selects with no alias fallback; removing all name matching and creating sessions by DID were rejected.
tags: [decision, aw-cli, chat, identity]
timestamp: 2026-11-17
---

**Status (checked 2026-11-17):** decided and implemented on the review branch
`agents/aweb-protocol-expert-team-key-trust` at af59246dbc (task aweb-adgw,
finding M-1); not yet on main.

# Decision

`cli/go/chat/IDENTITY_RULES.md` (Core Rules and Selector Matching) governs how
aw picks an existing chat session, and a fix to matching stays inside it:

- Strong identities (`did:aw`, `did:key`, a full `namespace/handle` address)
  win over a bare alias.
- A bare alias is only a fallback when no strong identity is available, and
  only when it names exactly one concrete participant. That check reads the
  pending conversations **and** the full session list before any match is
  chosen; more than one concrete participant fails closed.
- When aw has itself confirmed a teammate's DID from the agent list
  (send-and-wait, send-and-leave, extend-wait), that DID selects the session:
  rows carrying the DID, the identity's other DID or its resolved address. No
  alias fallback applies there, because a strong identity is available.
- New sessions are still created by alias.

# Rejected

- **Removing all name matching.** A first fix took the finding's wording
  ("never by a participant's name") literally. It contradicts the governing
  document, which allows a unique-alias fallback and DID-to-address
  equivalence; the reviewer restated the finding against that document
  (relayed by the coordinator on 2026-11-17) and the fix was narrowed.
- **Creating sessions by DID (`to_dids`).** It changes the signed message
  form, and the server refuses a global sender without an address with 422
  (filed as aweb-adif). Binding the recipient into the signature is separate,
  later work, not part of session selection.

# Lesson

Before fixing a finding about matching or identity, read the normative
document for that area (here `IDENTITY_RULES.md`; for messaging,
`docs/identity-messaging-contract.md`). The document, not the finding's
phrasing, bounds the fix. Building from the wording cost a rework here.

Related: [identity selection is one precedence rule](/aweb-protocol-expert/decisions/identity-selection-is-one-precedence-rule.md)
is about which local principal aw acts as; this decision is about which peer
conversation it selects.

# Evidence

- At af59246dbc, `findSessionByConfirmedDID` matches only DID and address
  rows, and `findSessionWithOptions` reads `ChatListSessions` and the pending
  list before choosing for a bare alias. The new test
  `TestFindSessionAliasAmbiguityReadsTheFullListBeforeChoosingAPendingMatch`
  pins the ambiguity check.
- The source reports the real-path test failing at a22b4c6283 and passing at
  af59246dbc, and 107 real-CLI server tests passing.
- The reviewer's restatement is source-reported (coordinator relay,
  2026-11-17); the harvester could not read it. The commit message at
  af59246dbc records the same restatement.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-team-key-trust, 2026-11-17; notes/chat-session-selection-by-did.md. Checked by the harvester against `IDENTITY_RULES.md` on main (lines 17-28 unchanged) and the diff 66ec2c0624^..af59246dbc.
