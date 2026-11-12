---
type: Lesson
title: Correlate a log line before blaming a component
description: A proxy or server error logged near a client's failure is not that client's error; capture the client's complete error output for one call and tie any log line to that call by connection or isolated reproduction before naming a component.
tags: [lesson, debugging, attribution, integration]
timestamp: 2026-11-12
---

Recorded by the aweb-expert seat building the team deployment on 2026-11-12.
An agent's `aw` failed through the egress proxy, and the proxy had logged
`no host in upstream ""` from the agent's address at about the same moment.
The seat reported a proxy/SNI defect, which was routed to the image owner. The
owner reran the same call: `aw`'s own error was
`x509: certificate signed by unknown authority`, an already-known missing CA
input, and a controlled probe showed the proxy preserving SNI. The proxy line
belonged to a different connection. The owner lost a diagnosis cycle and the
claim had to be withdrawn publicly.

Two things hid the real error: a trace filter (`grep x509|certificate|tls`)
over output where the error sat on a line it did not print, and a follow-up
hypothesis tested on the wrong premise.

# How to apply

- Before naming a component as the cause of a client failure, capture the
  failing client's **complete** error output for one call, unfiltered.
- Tie any proxy or server log line to that exact call, by connection (port,
  time, request id) or by reproducing the call alone. Proximity in time and
  address is not correlation.
- Until both agree, report it as "client fails with X; a nearby proxy log
  shows Y, not correlated", never as a cause. A wrong attribution sends work
  to the wrong owner.

This is the cross-component case of
[reproduce and read the first error before attributing a regression](/aweb-expert/lessons/reproduce-before-attributing-a-regression.md),
and an instance of the evidence rule in the
[evidence and reproduction standard](/aweb-expert/decisions/evidence-and-reproduction-standard.md).

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-12;
notes/correlate-before-attributing-a-log-line.md.
