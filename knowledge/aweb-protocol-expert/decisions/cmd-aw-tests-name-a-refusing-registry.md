---
type: Decision
title: cmd/aw tests name a refusing registry
description: The cmd/aw test package sets AWID_REGISTRY_URL to a loopback port that refuses, in place of any host value, so a test that names no registry cannot reach DNS discovery or the public registry; only a test whose subject is the no-registry behaviour clears it, with a one-line reason, and keeps its traffic local. Ruled; implementation on a review branch, not on main.
tags: [decision, testing, registry, egress, cmd-aw]
timestamp: 2026-11-20
---

The operator ruled that a cmd/aw test must never reach the internet, whatever
the product does. The ruling was relayed by the OSS coordinator and is item 11
of the R2 composition. This acceptance is source-reported.

**Status:** ruled. The test-side change is commit 338ded10e6 on a review
branch, awaiting the operator's acknowledgement. It is not on main at
c42ad775a.

# Decision

- The cmd/aw test package sets `AWID_REGISTRY_URL` to `http://127.0.0.1:1`, a
  loopback port nothing listens on. It replaces any value from the host.
  In-process tests and child `aw` processes inherit it.
- A test inherits that value. It never clears the variable to avoid the
  host's value.
- A test whose subject is the product's behaviour with no registry named
  clears it in that test, with a one-line reason. Examples are defaults, an
  identity's own `registry_url` deciding, DNS TXT values that omit the
  registry, and hosted onboarding. That test still keeps all its traffic
  local, through a fixture resolver or a local server.
- No other test clears it.

# Why

Leaving the registry unnamed in a stand-in test is not neutral: it selects the
internet. A product change on the R2 composition (ee45af6ed9) added a registry
read to creation, the team's current-key check. From then on every cmd/aw
test that named no registry did a DNS `_awid` lookup and then reached
`api.awid.ai`. They stayed green, because an unavailable read is tolerated and
leaves the key "unconfirmed". Only the egress guard's receipt showed it: 111
denied connections in one package run.

Naming any registry skips discovery: `DiscoverRegistry` returns the fallback
registry URL without a lookup (`cli/go/awid/registry_resolver.go`, verified on
main at c42ad775a). That is why a refusing URL closes both the DNS lookup and
the public registry.

# Adding or changing such a default

Measure the whole package under the egress guard before and after. A default
changes behaviour for every test that relied on its absence. Here the measured
runs, local and without services, were:

- base R2 b5ddfcbd1d: 111 denied, 46 failures;
- the default alone: 17 denied, 12 more failures, all of them tests of the
  no-registry branch;
- head 338ded10e6: 0 denied, the same 46 failures, which depend on services.

The 12 new failures are the evidence that each clear in those tests is the
test's subject.

The guard sees HTTP(S) proxy traffic, not DNS. A denial count of zero does not
prove that no lookup happened; naming a registry is what prevents the lookup.

# Relation to other concepts

This confirms and extends [tests exercise the real
authority](tests-exercise-the-real-authority.md): stand-in tests cannot show
the real authority, and here they also hid egress.

**Open point.** That decision says a test that only tests a mock or the
harness is deleted. The change adds a test that pins this harness property,
as the existing harness environment tests in the package do. The source raised
this with the coordinator and it is not settled. The decision above does not
depend on that test.

Method used to find the source: [attribute test egress per test and bisect
by tree](../lessons/attribute-test-egress-per-test-and-bisect-by-tree.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-aw-tests-1,
2026-11-20; notes/cmd-aw-tests-name-a-refusing-registry.md,
notes/creation-key-read-falls-back-to-the-production-registry.md. The
harvester verified that 338ded10e6 exists on a review branch and is not on
main, and read the `DiscoverRegistry` fallback on main.
