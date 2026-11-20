---
type: Decision
title: The release gate is one composed stack built from the candidate wheels
description: Each repository's tree passes its own gate once; the release step then runs the cross-repository journeys against one stack of the OSS server, awid and the hosted service at exact hashes, with the OSS packages installed from the candidate wheels, and OSS publishes exactly those bytes only after that gate is green.
tags: [decision, release, testing, gates, oss, cloud]
timestamp: 2026-11-10
---

Proposed and confirmed by the operator on 2026-11-10, in a session with the
`aweb-expert-testing-servers` seat: compose the OSS server, awid and the hosted
service at the right hashes and test that, because it prevents shipping an OSS
release that breaks the hosted service. The acceptance is source-reported (a
session the harvester could not read), not verified.

# Decision

The release path is:

1. Each repository's tree passes its own gate once. The result is reused from
   the tree-keyed ledger, not rerun at release.
2. The release step builds one composed stack at exact hashes: the OSS server,
   awid, and the hosted service with the OSS packages installed from the
   candidate wheels. Nothing in it comes from PyPI, from an editable install or
   from mounted source.
3. The cross-repository journeys (the hosted user journey and the OSS user
   journey) run against that stack.
4. Exactly those bytes are published.

OSS does not publish until the composed gate is green. An OSS release must not
break the hosted service; that priority is the operator's.

# Why

- It tests the bytes that ship. The 1.27.49 release (2026-11-09/10) published
  an rc2 that passed the OSS gate but could not be installed, because the gates
  ran against an editable awid. This applies
  [a test result belongs to the bytes that ran](/aweb-expert/lessons/a-test-result-belongs-to-the-bytes-that-ran.md)
  at release scale.
- It removes the RC publish, hosted pin and finals chain, which existed only to
  put exact OSS bytes in front of the hosted service, and the duplicate full
  gates it ran. That release took about 7 hours with failures (RC about
  90 minutes, publish, hosted gate, finals about 80 minutes), against the
  operator's 45-minute release budget.

# Rejected

- **Publish an RC to PyPI, pin the hosted service to it, then gate the finals
  again.** Serial and duplicated, and it ships before the hosted service has
  proven the release.
- **A composed stack built from source mounts.** It hides unreleased
  dependencies: the editable-source blind spot that produced the uninstallable
  rc2.
- **Using the composed stack in place of each repository's unit and backend
  suites.** Weaker; those suites still run once per tree.

# Boundary

The composed stack lives on the hosted side, which consumes OSS. OSS release
tooling consumes only its verdict and carries no hosted internals, per
[OSS and Cloud are separate teams](/aweb-expert/decisions/oss-and-cloud-are-separate-teams.md).

# Status and open questions

As of 2026-11-10 this is a decision, not yet built (aweb-acww C3/C4). Open:

- Whether the journey scripts can target an external stack is unverified; each
  currently starts its own compose project.
- Federation journeys need several servers.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-10; notes/composed-release-gate.md.
