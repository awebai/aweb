---
name: code-review-discipline
description: Practices to apply when taking a code-review assignment. Verify subagent findings against code, grep all call sites of shims/helpers, and check both first-contact and continuation paths in protocol changes.
---

# Code review discipline

Load this skill at the start of any code review assignment. The lessons here
come from real misses that shipped close to deploy and were caught by either
another reviewer or a subagent's second pass.

## Subagent confidence is uncorrelated with correctness

Running a `code-reviewer` subagent for a "second set of eyes" is cheap and
sometimes catches what the primary reviewer missed. It also sometimes produces
wrong-premise findings with confident framing. Banked data points from the
aweb-aaou federation review chain:

- One subagent pass returned **0 valid findings out of 5** — every finding was
  a wrong-premise about tool names or registration patterns that didn't exist
  in source.
- Another subagent pass returned **2 valid findings** — both were real misses
  the primary reviewer hadn't caught.

The subagent's confidence in BOTH cases sounded the same. Confidence is not a
signal of correctness.

**Practice**: when a subagent surfaces a finding, treat it as a LEAD, not a
conclusion. Open the actual file at the claimed line, verify the claim against
code, then decide whether to act. If the subagent claims "X is missing,"
`grep -n X` first. If the subagent claims "Y is wrong," read Y in source first.
Subagent output gets verified-against-code with the same scrutiny as any other
review claim — including findings that match your own intuition.

This applies symmetrically: the subagent's wrong findings AND its valid
findings both need code-level verification before they shape your review
output.

## Shim/helper adoption requires grep-all-call-sites

When a code change introduces a helper that other code SHOULD route through
(an authentication wrapper, a federation shim, a fail-closed gate, a logging
hook), reviewing the helper's factoring is necessary but not sufficient. The
factoring being correct DOES NOT prove that every site needing it actually
uses it.

Concrete miss from the aweb-aaou review chain:

- `mcp_federation_request` shim introduced to let MCP tools call into route
  helpers for federation outbound. Shim factoring reviewed and signed off as
  correct — the abstraction shape, the dependency-injection seam, the call
  conventions all checked out.
- BUT: only the FIRST-CONTACT branches of `mcp/tools/mail.py` and
  `mcp/tools/chat.py` were updated to use the shim. The CONTINUATION branches
  (conversation_id / session_id paths in the same files) still called
  `deliver_message` and `send_in_session` directly, bypassing federation
  entirely.
- Result: a remote first-contact federated correctly via MCP, but the reply on
  the same conversation silently dropped to the sender's local DB. Recipient
  never saw it.

**Practice**: when reviewing a change that introduces a helper, grep ALL call
sites that PLAUSIBLY need it, not just the call sites visible in the diff. A
diff showing one branch updated does not prove the other branches were
considered:

```bash
grep -rn '<helper_name>' <relevant tree>     # all uses of the helper
grep -rn '<old_direct_call>' <relevant tree> # all direct calls the helper
                                              # was supposed to replace
```

The diff shows what changed; grep shows what should have changed. The
difference is the review gap.

## First-contact vs continuation as a review checkpoint

When reviewing a protocol or wire-format change, almost every flow has two
stages:

- **Establish** stage: first-contact, session-create, connect, handshake.
- **Extend** stage: continuation, reply, in-session message, refresh, retry.

Reviewers naturally focus on the establish stage because that's where the new
contract is most visible — first-contact carries the full envelope, the
expensive checks (signature, cert, address resolution) all fire there. The
extend stage gets less attention because it usually reuses state established
earlier ("the conversation is already authorized; we just append to it").

This asymmetry is where wire-protocol changes most often leak. A federation
contract that handles first-contact correctly but drops continuation isn't
"federation that works minus a small edge case" — it's federation that LOOKS
like it works in development but fails the first time a real user replies.

**Practice**: explicitly check BOTH stages when reviewing any change involving
sessions, conversations, or stateful protocols. Use a two-column checklist
mentally:

| concern | first-contact path | continuation path |
| --- | --- | --- |
| signed_payload binding | verified? | verified? |
| target re-resolution | verified? | uses stored route? |
| auth / cert presentation | verified? | verified or scoped-not-required? |
| fail-closed on missing input | verified? | verified? |
| dispatched via shim/helper | verified? | verified? |

If either column has a blank, the review isn't done yet.

## When to load this skill

- Taking a code-review assignment that involves a wire protocol, an
  authentication change, or a new dispatch shape.
- Running a `code-reviewer` subagent and considering whether to act on its
  findings.
- Doing a "fresh eyes" pass on your own work because a customer-blocker or
  near-miss surfaced.
- Reviewing a multi-commit bundle where a helper was introduced in one commit
  and consumed in subsequent commits.
