---
type: Decision
title: The requester owns the terminal approval proof
description: After a decision the requester keeps the full request and raw approval receipt, and the approval service keeps only a minimal audit plus the raw assertion until the original deadline; less central retention never permits discarding the bytes independent verification needs. Source-reported delegated architecture ruling; the receipt format is a draft.
tags: [decision, architecture, approval, privacy, proof, custody]
timestamp: 2026-11-15
---

The approval service sees acts from every organisation that uses it. This
decision moves custody of the finished proof away from it.

# Decision

- **Full acts stay at the service only while pending.** Once the human
  decides, the requester owns the full request and the raw approval receipt.
- **The service keeps a minimal audit.** After the decision it keeps digests,
  the person, the time and the outcome. It keeps no history of the acts.
- **Bounded recovery of a lost response.** A digest cannot rebuild a raw
  assertion, so a lost HTTP response would otherwise need a new approval. The
  service therefore also keeps the raw assertion, bound to the request digest
  and the original requester, until the original deadline. The requester
  already holds the act bytes and rebuilds its receipt from them. This needs no
  central act history, no new approval and no network client in the enforcer.
- **Expiry ends availability, not validity.** When the deadline passes the
  service stops offering the assertion. A proof the requester saved stays
  valid historical evidence.

# Why

A central archive of acts would expose act data the service does not need,
across organisations, and would invite an implicit history service. Moving
ownership to the requester keeps independent verification without that
archive.

# What it does not change

This changes who holds the proof, not the guarantee.
[Accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
still holds: a reviewer with the approver's public key can check an approval
later without trusting the service. That needs the raw assertion and the exact
signed bytes, so the requester must keep them. Minimising what the service
retains is not permission to discard verification bytes anywhere, and it does
not approve deleting existing evidence or define a receipt format.

Keep the decision transaction and network delivery apart: the decision can
commit while its response is lost in transit. The bounded raw-assertion slot
exists for that gap.

The requester who keeps this proof is the caller that carried the request,
as [the caller carries the enforcer's approval request](/aweb-protocol-expert/decisions/the-caller-carries-the-enforcer-approval-request.md)
records. This refines the separation of approval, application enforcement and
key custody accepted the same day; it does not restate that split.

# Status and acceptance

**Source-reported delegated architecture ruling.** The source reports that the
coordinator relayed an architecture acceptance of the approval-service split
and six rulings on 2026-11-15, one of them requester-owned receipts with
minimal service retention, and a later consolidation that keeps only the raw
assertion with its digest and requester binding until the original deadline.
The source reports that the approval library's owner independently identified
the same byte-retention and transaction-versus-delivery constraints. This is
not a direct human record and the harvester could not read it. No
implementation, wire format or runtime evidence is claimed.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-signer-embedding, 2026-11-15; notes/requester-owns-terminal-approval-proof.md.
