---
type: Lesson
title: A time budget covers the whole operation
description: A total operation budget starts before discovery and client construction, and an optional or soft refresh still needs a short total bound; a fallback policy limits the error, not the time it costs. A deadline red proves a hidden cap, not the cause of a historical stall.
tags: [lesson, timeouts, aw-cli, certificates, diagnosis]
timestamp: 2026-10-20
---

Three findings about where time goes before the request that matters.

- **Construction escaped the budget.** A declared two-second advisory budget did
  not bound the command, because client construction first resolved the server
  with background contexts and separate network budgets. The final request was
  bounded; origin selection, health probes and discovery were not. A test that
  stalls only the final endpoint misses this.
- **A soft refresh caused an outage.** A proactive certificate refresh that falls
  back to the still-valid certificate connected to a registry port that was not
  listening. The connect attempt outlasted the certificate's remaining validity,
  so the fallback found an expired certificate. A two-second total budget and
  one attempt per process restored the intended path; an expired certificate
  still refuses.
- **What a deadline red proves.** A deterministic delayed-read red proved a
  hidden ten-second command cap overriding the documented timeout. It did not
  explain the historical stall it was investigating, which later evidence put
  before HTTP (a TCP connect with no write) and which controls did not
  reproduce.

# How to apply

- Identify where a total budget starts and pass the operation's context through
  construction and discovery, not only the final request.
- Bound optional reads by total time and attempts, not only by error policy.
- Keep "this patch bounds the budget" and "this explains the incident" as
  separate claims, and do not label a budget patch a root-cause fix.

# Provenance

Harvested 2026-10-25 from seats `aweb-protocol-expert-awid-service-bypass`
(notes `client-construction-consumes-operation-budget.md`,
`deadline-boundary-does-not-identify-stalled-request.md`; amendment 7b58a57d)
and `aweb-protocol-expert-chat-session-fix` (note `proactive-refresh-latency.md`;
security review e796bd74).
