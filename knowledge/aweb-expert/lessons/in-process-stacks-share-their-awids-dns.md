---
type: Lesson
title: In-process stacks share their AWID's DNS, and network guards cover DNS
description: An in-process component that builds its own AWID client needs that AWID's domain verifier as well as its transport, because live ID-chain evidence looks up _awid.<domain> through the verifier and falls back to real DNS; a test that guards only HTTP cannot see that lookup.
tags: [lesson, testing, awid, dns, egress, decision]
timestamp: 2026-11-11
---

When the coordination server observes a connecting member's identity kind, its
AWID registry client fetches live ID-chain evidence. That needs `_awid.<domain>`
namespace authority, which the client looks up through its `domain_verifier`;
with none it uses real DNS. Wiring an in-process server to its AWID with only
`awid_transport` therefore looks complete until an evidence-dependent path runs.

Two places it bit, both on 2026-11-11:

- An in-process coordination fixture injected the AWID's fake `example.com`
  authority into the AWID's own dependency override and the test client, but
  not into the server's AWID client. The server got no TXT record, the evidence
  was unavailable, and `/v1/connect` answered 503: 31 setup errors in one router
  suite.
- A server unit test guarded HTTP with a failing mock transport and expected
  `evidence_unavailable`. It passed for the wrong reason: the outcome came from
  a real `_awid.example.com` lookup that the transport guard could not see. The
  candidate gate's DNS egress guard caught it ("TEST DNS EGRESS DENIED").

# Decision

`create_app` and `running_server` take a library-mode `domain_verifier` beside
`awid_transport`, refused in standalone mode. The coordination fixture passes
one that answers what its AWID's override answers, and "no record" otherwise:
one DNS world for every in-process component, and no test reaches the network.

- **Rejected: a test-only mutation of the built client** (setting its private
  verifier attribute). A visible parameter is a sturdier seam.
- **Why it does not widen trust:** the library host already chooses
  `awid_transport`, so it already picks the registry; supplying the `_awid`
  answer is power held by the same party.

The ruling came from the team's authority reviewer, an agent review, and is
source-reported. **Status** (checked 2026-11-11): the fixes are 29e308efd and
bfbefd3f2 on aweb-expert branches; neither is on main at 7f4be32fa.

# How to apply

- Any new in-process component that builds its own AWID client (a server, an
  app runtime) gets both the transport and the DNS verifier of the AWID it
  talks to.
- A test that guards the network guards DNS too (make
  `dns.asyncresolver.resolve` fail), and any client a test builds gets an
  explicit domain verifier. A guard that cannot see a lookup is the kind of
  harness [that must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).
- The gate's DNS denial log names no test. To attribute a denied lookup, a
  small pytest plugin that records the running node id on
  `dns.asyncresolver.resolve` finds it in a focused run.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-11;
notes/in-process-server-needs-awid-dns.md. Commits 29e308efd and bfbefd3f2
checked by the harvester; the reviews and the ruling are source-reported.
