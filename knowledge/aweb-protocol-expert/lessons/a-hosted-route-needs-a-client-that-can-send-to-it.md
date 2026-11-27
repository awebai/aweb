---
type: Lesson
title: A hosted route is only a journey if a released client can send to it
description: A design step of the form "agent X does Y with aw against the service's route" must name the pinned command, how it selects its credential and what it sends; aw's hosted invite mint picks its credential by the target team and its request has no team field, so an admin-team-only member cannot invite into another team, whatever the route accepts, and a step the client cannot express is a named dependency.
tags: [lesson, design, clients, aw, hosted, invites, credentials]
timestamp: 2026-11-27
---

A hosted bootstrap design said that the first invitation into a team is made
by the admin team's root agent, with `aw`, against the service's invitation
route. That read well and was not executable. Review found it.

The released `aw` hosted invite mint (`cli/go/cmd/aw/hosted_invite_mint.go`)
resolves its client and credential from the target team before it contacts
the service. It does this with the team override, using the target that
`resolveTeamInviteTargetAt` in `cli/go/cmd/aw/id_team.go` resolves. The
`CreateSpawnInvite` request carries no team field. The service therefore never
sees "admin credential, other team as target". A member of the admin team
only has no credential for the target team, so it cannot make that request,
whatever the route would accept. The step became a named dependency: an `aw`
command and a route that authenticate the inviter separately and bind the
exact target, with a test that refuses an unrelated team's credential.

# How to apply

- For every design step that gives a client work against a hosted route,
  name the exact pinned command.
- Read how that command selects its identity and credential, and which fields
  its request carries.
- If the released client cannot express the step, the step is a named
  dependency. It is not yet a journey.

This is the design-side form of
[identity and routing review needs the real client](/aweb-expert/lessons/identity-and-routing-review-needs-the-real-client.md),
which covers review evidence. Both follow from
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md).

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-27; notes/hosted-path-needs-the-client-that-calls-it.md.
The design was reviewed against source and is not built. The harvester checked
the credential selection and the request shape at aweb main 39b3f0911.
