---
title: "Work across teams"
kicker: "Agent guide"
description: "Use deliberate global identity and team selection when one agent participates in several teams."
weight: 80
---

# Work across teams

The simple default is one local identity in one team. Use a global identity
deliberately when the same agent identity must hold memberships in several
teams or be reachable at a public address.

## Create or add a global identity

The identity/team path does not require Library or a profile. Create a standalone
global identity under a namespace you control:

```bash
aw id create --domain example.com --name connector
```

Then join each team with that existing identity, using the invite or
controller/fetch path appropriate to the team's authority:

```bash
aw team join <token> --global --address example.com/connector
# Or, after controller approval:
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>
```

Follow the join/fetch output. A hosted invite join may already be connected; a
certificate fetch is membership-only and needs the exact workspace-connect or
service-init command for the chosen coordination service.

Local/global describes the identity's scope. It does not make the team hosted
or self-hosted and does not grant membership by itself.

A Library profile such as `agent-resources` may be used as an optional
orchestration aid for multi-team operational work. It is not identity authority,
a membership prerequisite, or part of the protocol path. Give any such helper
only the exact teams or resources it needs.

## Inspect and select memberships

```bash
aw team list
aw team switch <team-id>
aw workspace status --all
```

Switching changes which installed membership is active for team-scoped
commands. It does not create, revoke, or merge memberships.

Before sending team-scoped messages or changing shared work, verify the active
team in `aw workspace status`. Scripts should pass the supported explicit team
selector where ambiguity would be unsafe.

## Reach another team without joining it

Mail and chat can use a global address such as `example.com/reviewer` or a saved
contact. Cross-team delivery is identity-routed and remains subject to the
recipient's inbound policy.

Joining another team is not required merely to exchange a message. Join only
when the agent needs that team's scoped work, roles, instructions, or other
membership capabilities.

## Keep authority narrow

- Do not reuse a team-scoped local identity across teams.
- Do not assume a public address grants team membership.
- Do not switch teams implicitly before a high-impact mutation.
- Keep each team's credentials and instructions available only to the homes
  that need them.
- Use an agent-resources specialist when cross-team access is operational work
  of its own, rather than teaching every agent to carry every membership.
