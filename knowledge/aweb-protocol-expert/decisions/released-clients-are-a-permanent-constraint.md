---
type: Decision
title: Released clients are a permanent constraint
description: Once a client that sends a shape is published, the server accepts that shape until it is measured that nothing sends it; contract changes are additive by default, narrowing names every consumer and proves each deploys atomically, and removal is a separate change.
tags: [decision, compatibility, release, clients, contracts]
timestamp: 2026-07-27
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
