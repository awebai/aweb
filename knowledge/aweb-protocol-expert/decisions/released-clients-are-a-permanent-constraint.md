---
type: Decision
title: Released clients are a permanent constraint
description: Once a client that sends a shape is published, the server accepts that shape until it is measured that nothing sends it; contract changes are additive by default, narrowing names every consumer and proves each deploys atomically, and removal is a separate change.
tags: [decision, compatibility, release, clients, contracts]
timestamp: 2026-11-18
---

Decided on 2026-07-27 after a chat mark-read change made a new field required
and explicitly rejected the old one. Every published client sent the old field;
deploying the server would have broken every installation with no client-side
diagnostic. The process had been followed, not ignored: the cross-repository
guidance said to pick one format when both sides deploy atomically, which is
true for a server and its bundled hosted application and catastrophic for
published clients, which never deploy atomically with anything. A running agent
keeps its loaded module until it restarts, which for a long-lived agent may be
never. The operator's frame: shippability, the ability to release without
breaking anything in the field, is paramount.

# Decision

- A released client is a permanent constraint. The default is additive: a new
  accepted shape may be added; an existing one is not rejected.
- Narrowing requires naming every consumer that sends the shape and proving each
  deploys atomically with the change.
- Removal is its own change, gated on measuring that nobody sends the old shape.
- The atomic-deploy principle applies only across the server and its bundled
  hosted application and is not generalised.

The `cross-repo-change` skill carries the procedure; this concept records why
it exists.

# Where the rule ends (October 2026)

Rulings and review misses from October 2026 mark the edges of the rule.

- **Malformed is refused; an equivalent encoding is kept.** An identifier
  ending in a line break violates its own frozen alphabet, so it is refused with
  no measurement first and no compatibility branch (security reviewer,
  2026-10-17: "Refusing it is the fail-closed fix"). The trap is an anchored
  regex checked with `match`, which accepts a trailing newline; use a full
  match. A base64 payload with a trailing newline decodes to identical signed
  bytes, so it was deliberately left alone: tightening it "would narrow a
  released route".
- **Unreleased contracts are re-frozen in place.** When nothing deployed
  produces or consumes a contract, it is changed in place, with no parallel
  version (secrets coordinator, 2026-10-21, on the operator's no-backward-
  compatibility rule). The precondition is evidence that nothing deployed uses
  it.
- **Narrowing is not only a schema change.** Contract prose that says "reserved
  for" or "only" can narrow an existing family's meaning for consumers the
  author did not look at. Reusing another surface's request model as "read-only
  selector data" ran that model's validators and imposed its 64-character limit
  on a released MCP selector. Compare the accepted inputs at every new
  constructor boundary, and enumerate the existing consumers before writing a
  contrastive sentence.
- **Implicit behaviour is part of the contract.** Removing a side effect a
  host gets without asking, such as per-request outbox recovery for a mounted
  app, is narrowing too: keep the default and add an explicit opt-out, never a
  new duty stated in a docstring. See
  [removing an implicit side effect is a contract change](/aweb-protocol-expert/lessons/removing-an-implicit-side-effect-is-a-contract-change.md)
  (2026-11-04).
- **A persisted in-flight record is a consumer too** (2026-11-16). A released
  client may have saved an operation that already applied remotely, and it
  resumes that record after an upgrade. A new authorization fact added for
  newly started operations must not default to false when the old record
  lacks it: that silently turns the old retry into a different operation.
  Keep three states, absent, false and true. Absent preserves the decision the
  old client made, resending its original request or using its saved
  response. Partial output already installed locally does not prove the
  operation changed kind; it may be that operation's own result. A fresh read
  of current local state may fill the gap only for records with no retained
  provenance, and never overrides an explicit one. Before adding such a fact,
  inventory every private record a released client persists, not only its
  wire requests. The elimination route is a regression test built from the
  published writer's exact record shape, never one written by the new code
  under review, covering resend and saved response, each with and without
  installed partial output. Evidence: a review on 2026-11-16 found a
  candidate that defaulted an `aw` 1.36.58 pending hosted-invite creation,
  which records no key-mint or source-parent fact
  (`cli/go/cmd/aw/hosted_invite_creation.go` at `aw-v1.36.58`), to a
  membership-only join; b9304e1350 keeps absent provenance as the original
  creation (on the source's review branch, not on main, as of 2026-11-18).
  The review ruling is source-reported; no human acceptance is claimed.
  OKF proposal from aweb-protocol-expert/aweb-protocol-expert-person-parent,
  2026-11-18; notes/inflight-recovery-is-a-compatibility-consumer.md.
- **A dated exception, by the operator.** On 2026-10-20, relayed by the naapps
  and secrets coordinators, the operator waived the additive default for the
  naapp install surfaces, released aw clients included, on the premise that no
  deployed client used them yet (asserted, not measured): install requires manifest bytes "with no wait for measurement", and
  serving is v2-only. The waiver named those surfaces and excluded server
  deploy-seed configuration. It does not repeal this rule or authorise other
  narrowing; any other exception needs its own explicit ruling.

Provenance for this section: harvested 2026-10-25 from seats
`aweb-protocol-expert-agent-activity` (security reviewer d86327c5 and
286a1c12), `aweb-protocol-expert-secrets-design` (coordinator b0a11ceb; note
`contrastive-wording-can-narrow-unrelated-consumers.md`),
`aweb-protocol-expert-awid-service-bypass` (note
`read-only-models-can-narrow-other-surfaces.md`) and
`aweb-protocol-expert-app-team-api` (relay d2d20b38 citing naapps d5b68684;
scope confirmed by the seat in 67414d9a).
