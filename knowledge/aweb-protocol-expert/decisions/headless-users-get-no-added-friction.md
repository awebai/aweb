---
type: Decision
title: Headless users get no added friction; extra security is opt-in
description: A head must not refuse a headless CLI or OATS command that released aw allowed unless the caller opts in with a flag; when aw cannot tell, it does what released aw did and says so on stderr, a protection the other party chose is not the sender's opt-in, and a new dependency on a service answering is friction. Accepted by Juan on 2026-11-21 (source-reported); applied on a handed-back branch, not yet on main.
tags: [decision, compatibility, headless, oats, cli, encryption, e2ee, opt-in]
timestamp: 2026-11-21
---

Accepted by Juan (the operator) on 2026-11-21: headless CLI and OATS users
get no added friction, and anything that validates a human or adds security
beyond what production did is opt-in. Acceptance is **source-reported**: the
coordinator relayed the rule by mail (46a61b62, verified sender), quoting a
headless-friction audit of the release heads. The harvester could not read
that record.

Why it was needed: several review rulings in task aweb-adje.3 added refusals
for safety (an unknown continuation encryption, a failed recipient lookup, a
peer's encryption). Each refused a command production allowed, and the audit
found them to be regressions for headless OATS users.

# Decision

The test for every head: **it must not refuse a headless command that
released aw allowed, unless the caller opts in with a flag.** Ask first
whether released aw allowed the command headless; if it did, a stricter path
needs an explicit flag.

- **Cannot tell is not grounds to refuse.** When a read fails or is
  incomplete, aw does what released aw did and says so on stderr. A default
  continuation whose encryption cannot be read is sent in plaintext with a
  notice naming the reason and `--e2ee`; only `--e2ee` refuses.
- **The other party's choice is not the sender's opt-in.** A conversation the
  peer encrypted does not force encryption on a sender with no key or custody
  socket: that send is plaintext, with a notice.
- **A new dependency on a service answering is friction.** A local seat's
  send to an address keeps released behaviour when the registry is
  unreachable: it posts and the server decides. A sender that requires the
  binding (a global, stable-ID sender) still refuses, as before.
- **Refusals stay** where production already refused, or where the caller
  asked (`--e2ee`).

# Where the rule ends

It bounds *new* refusals; it does not undo fixes to real security bugs (for
example, a revoked certificate staying usable). Never *conclude* a fact from
an incomplete answer either: the three-state reading (known yes, known no,
unknown) stands, so the stderr notice is accurate. What the rule changes is
only the action taken on "unknown".

Prove each change by running the headless command the way OATS runs it
(built aw, no dashboard, no flags), and keep a control showing that the
opt-in still refuses.

This is the general form of the released-client rule for headless callers;
see [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

# Supersession

It supersedes, in part, two earlier rulings of task aweb-adje.3:

- The lesson "a read that cannot establish a fact must not default to the
  permissive answer" (harvested 2026-11-21, pending review, not on main): its
  three-state reading and single decision owner (`awid.ContinuationEncryption`)
  stand; its refusal on "unknown" is superseded by the plaintext-with-notice
  default above.
- The ruling that a failed recipient lookup refuses every sender: it now
  refuses only senders that require the binding.

Status: applied on branch `agents/aweb-protocol-expert-chat-verify-adje3`
(head 52754da65a): default continuation plaintext with a notice (2c0ee666e,
red test 261cc7040, server test 52754da65), failed lookup refusing only a
binding-requiring send (a5108b787, red test 9aafb2a23), and a bare-alias send
to a respawned member (f2267c2cd). Built-aw headless tests
`TestDefaultContinuationSendsPlaintextWhenItCannotEncryptAsTheConversationWould`
and `TestLocalSeatSendsToAnAddressWhenTheRegistryIsUnreachable`. Not yet on
main or released.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-chat-verify, 2026-11-21; notes/headless-users-get-no-added-friction.md, notes/cannot-tell-is-not-plaintext.md. Commits and tests verified on the branch.
