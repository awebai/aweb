---
type: Decision
title: Human governance requires protected signing
description: Human and controller governance acts are signed by one shared OSS protected signer that keeps that authority out of agent reach and enforces a fixed floor of live passkey approval of the exact act; agents keep bounded unattended work, and no second certificate kind is introduced.
timestamp: 2026-11-11
---

Approved by the operator on 2026-11-11. The acceptance is **source-reported**:
the aweb coordinator relayed it to the `servers` coordinator by mail, naming the
exact approved texts. No reviewer can read that record, and it is not an
independently witnessed record by the operator.

The canonical detail of this decision is the customer-agent-servers concept in
Bookshelf. This concept is a pointer with the rationale a coordinator needs. It
does not repeat the operation matrix and does not claim that anything is built,
deployed or migrated.

## Decision

- **One protected signer, shared.** A single OSS implementation, used by hosted
  and independently operated deployments alike, holds human and controller
  signing authority outside anything an agent can read or use.
- **A fixed governance floor.** A governance act needs live passkey approval of
  that exact act. A deployment may add checks but cannot configure the floor
  away.
- **Agents keep bounded unattended work.** Agents act under their own
  identities. An ordinary endorsed deployment root and its unattended
  descendants remain. Endorsing a root with a bare saved token, and keeping raw
  controller custody on a deployment where workers run, do not.
- **Separate authorities stay separate.** Identity ancestry, team membership
  and resource grants are independent of each other and of this signer.
- **No new identity kind.** The signing authority is protected; a second
  certificate kind is not introduced.

## Why

If a worker can read the person's or the controller's credential, human
approval means nothing. A saved login token, or a human key behind a passphrase
the same user account can capture, lets an agent act as the person. An exposed
team controller can appoint another owner even when the human keys are
protected. The recipient's consent does not constrain a stolen controller.

So the authority itself is what gets protected. Automating membership is not a
reason to hand controller authority to agents. One shared implementation keeps
the hosted and self-hosted authority rules from drifting apart.

## Rejected

- Endorsement by a bare saved token.
- Raw controller custody where agents can reach it.
- Treating protected confirmation as unnecessary for root attribution. The
  `servers` coordinator proposed this earlier the same day and then withdrew
  it. It never reached this base.
- A separate certificate identity kind for governance.

This decision applies [preserve capability boundaries through adapter
changes](preserve-capability-boundaries-through-adapter-changes.md): having
access to a credential is not authority to govern. Changes to it are the
operator's call ([scope belongs to the operator](scope-belongs-to-the-operator.md)).

Evidence: OKF proposal from coordinator/servers, 2026-11-11; notes/protected-human-governance-decision.md.
