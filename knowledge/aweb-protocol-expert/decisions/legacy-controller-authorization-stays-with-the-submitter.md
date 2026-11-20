---
type: Decision
title: Legacy controller authorization stays with its submitter
description: While legacy controller request signatures omit body or destination fields, a separate key holder constructs and submits the exact typed request itself and never returns reusable HTTP authorization to its caller; a transport pin is not a signed audience. Accepted SDK boundary; not yet implemented.
tags: [decision, security, key-custody, controller-auth, sdk, compatibility]
timestamp: 2026-11-15
---

# Decision

- **The holder submits.** When controller keys move behind a separate key
  holder, a request authorized by a legacy controller signature is
  constructed and submitted by the holder, inside its own transport. The
  application asks for a closed, typed operation and receives the operation's
  result, or an allowed signed object. It never receives the request's
  authorization headers.
- **A transport pin is not a signed audience.** A registry origin configured
  in the holder constrains where the holder sends a request. It adds nothing
  to what the signature binds, so it does not make a returned header safe.
- **Signed objects and authenticated HTTP requests are separate interfaces.**
  An object signature that fully binds its bytes may be returned to the
  caller; an HTTP authorization that leaves request fields unsigned may not.

# Why

Some legacy controller signatures cover only claims such as domain, name and
operation. They leave the request body, and for some formats the destination,
unsigned. A header handed to the application after the holder approves one
typed operation can be paired with a different body or sent to another
registry, and still authenticate. Separate key storage plus a typed callback
would then export a broader signing capability than the reviewed operation:
process isolation alone does not bound authority the signature does not bind.
A characterization test of the real SDK header constructors against the real
controller verifier shows one legacy `create_team` signature authenticating
both after its body's visibility changes and after its origin changes, while
the covering request format refuses a changed body, path, method or audience.

# Rejected

**A header-returning signing callback.** Extracting a holder that signs and
returns HTTP authorization to the caller, on the belief that separate key
custody plus typed input preserves the boundary. With formats that omit effect
fields it does not.

# Scope and status

- This is a compatibility constraint, not approval of weaker request binding.
  The legacy wire stays unchanged in this architecture because
  [released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md);
  repairing the legacy formats belongs to a separate format finding.
- Returning headers, or moving submission out of the holder, needs a new
  ruling grounded in the actual signed fields and replay rules, as
  [accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
  requires. A typed SDK callback is not that evidence.
- The characterization proves an authentication boundary only. It tests no
  registry mutation, holder deployment isolation or caller eligibility, and
  the holder seam itself is not implemented. The characterization commit
  (8edda3a7c, `awid/tests/test_controller_signing_characterization.py`) is on
  a source branch, not on main, as of 2026-11-15.
- It applies the request-bound-signature direction of
  [one principal and one policy per request](/aweb-expert/decisions/one-principal-and-policy-per-request.md)
  to a legacy under-bound format without superseding it, and complements
  [the signed request target is the external path](/aweb-protocol-expert/decisions/signed-request-target-is-the-external-path.md).

**Acceptance: source-reported.** The source reports that a reviewer's
disposition was relayed by the OSS coordinator on 2026-11-15, and that the
coordinator then accepted the SDK design revision carrying the explicit
destination-pin versus signed-audience limit. The harvester could not read
those records; message identifiers and reviewer names are omitted.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-membership, 2026-11-15; notes/legacy-controller-authorization-stays-with-the-submitter.md.
