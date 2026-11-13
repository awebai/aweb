---
type: Lesson
title: aw's default registry is production
description: An aw command that falls back to registry.DefaultRegistryURL reaches the public registry at api.awid.ai unless AWID_REGISTRY_URL names another, so a test lane with internet access silently sends identity writes to production; pin the registry for every aw command and cut the lane off the internet.
tags: [lesson, testing, awid, registry, egress, deployment]
timestamp: 2026-11-13
---

Some aw commands take `--registry` or resolve a namespace's registry from its
`_awid` record. Others use `registry.DefaultRegistryURL`, which is
`https://api.awid.ai` unless `AWID_REGISTRY_URL` is set. In a test lane with
internet access, those commands leave the lane and write to the public
registry. Nothing in the lane notices. The only signal is an unexpected answer
from the real registry.

On 2026-11-11 a compose lane being brought up ran `aw id team add-member` with
no `AWID_REGISTRY_URL`. The lane was on the default bridge network, so the
command sent a throwaway team certificate to api.awid.ai, which refused it with
a 404.

# How to apply

- **In a lane or test stack, pin the registry for every aw command.** Set
  `AWID_REGISTRY_URL` to the lane's registry wherever aw runs. If aw runs in a
  container whose image does not accept that variable (the OATS agent image
  does not; see `deploy/team/OPERATIONS.md`), set it on the aw command itself.
- **Cut the lane off the internet.** Declare the lane's default network
  `internal: true`. Image pulls and builds run in the Docker daemon, outside
  that network, so they still work. Then a missed pin fails inside the lane
  instead of writing to production. The candidate gate has an egress guard for
  this reason; an ad hoc compose lane has none unless it declares one.
- **A command that writes for a namespace resolves that namespace's
  registry.** It uses `DiscoverRegistry` on the namespace's domain, as
  `aw id team add-member` has done since aweb-acxc.95 (merged as 6f96418ad).
  Other `aw id team` paths on main at 6f96418ad still read
  `registry.DefaultRegistryURL`, so the lane pin is still needed.
- **To test a fix to the destination, use a test that cannot reach the wrong
  one.** See
  [a wrong-destination test refuses every other host](/aweb-expert/lessons/a-wrong-destination-test-refuses-every-other-host.md).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/lane-aw-defaults-reach-production.md. The harvester checked these on
main at 6f96418ad: the default constant in `cli/go/awid/registry_dns.go`; the
`DiscoverRegistry` calls in add-member; the remaining `DefaultRegistryURL`
reads in `cli/go/cmd/aw/id_team.go`; and the agent image's refusal of the
variable in `deploy/team/OPERATIONS.md`. The lane incident, the 404 and the
lane fix are source-reported.
