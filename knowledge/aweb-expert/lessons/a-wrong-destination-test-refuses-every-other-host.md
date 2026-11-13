---
type: Lesson
title: A wrong-destination test refuses every other host
description: A test for a bug that sends data to the wrong host must not send it there on its failing run; inject a transport that forwards only the expected host and refuses and records every other, and know that _awid-learned registries use the pinned client and that a namespace with no _awid record resolves to api.awid.ai.
tags: [lesson, testing, awid, registry, egress]
timestamp: 2026-11-13
---

The bug in aweb-acxc.95 was that `aw id team add-member` registered at aw's
default registry, the public api.awid.ai, instead of at the team namespace's
own registry. The obvious test points DNS at a local server, runs add-member and
asserts that the POST arrived. Before the fix, its RED run would have repeated
the incident: a team certificate POSTed to the public registry. See
[aw's default registry is production](/aweb-expert/lessons/aw-default-registry-is-production.md).

What worked: give the command's registry client a transport that forwards only
the expected registry host to a local server, and refuses and records every
other host. The RED run then failed with the public host refused, and nothing
left the machine. The guard also makes the GREEN run stronger: it asserts that
the right registry got the write and that no host was refused.

# How to apply

- When the bug is "it sends to the wrong place", the test's transport allows
  only the right place. A guard that lets the wrong destination through makes
  the RED run the incident. It is also a harness that
  [must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
  the refused-hosts record is what lets it name the property.
- **A registry learned from an `_awid` record is reached through the pinned
  client**, which takes public https only and does its own DNS lookup, so an
  injected transport does not reach it. In a test, route it to a local server
  with `TrustRegistryOrigin("https://<fictional host>")` on the registry client.
  The registry is still chosen from the TXT record.
- **A namespace with no `_awid` record resolves to api.awid.ai by design**
  (`DiscoverAuthoritativeRegistry`). "Unresolvable" means the DNS lookup failed,
  not that no record exists. A test that serves no record therefore points the
  command at production.

# Elimination route

A shared `cmd/aw` test helper for a registry client confined to named hosts
would make this the default for every registry-destination test. Until it
exists, `cli/go/cmd/aw/id_team_add_member_registry_test.go` is the worked
example.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/failing-test-must-not-egress.md. The harvester checked these on main at
6f96418ad: the fix 5580a351d and the test 548d00cea, whose transport refuses
and records every other host and whose cases use `TrustRegistryOrigin`; the
pinned-client rule in `cli/go/awid/registry_pin.go`; and the no-record default
in `cli/go/awid/registry_dns.go` with its test. Source-reported: the refused RED
run, the mutation checks, and the reviews (agent reviews, not human
acceptance).
