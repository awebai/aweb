---
title: "Profiles and blueprints"
kicker: "Human + agent guide"
description: "Understand optional profile and blueprint helpers and the home/runtime boundaries that remain under operator control."
weight: 30
---

# Profiles and blueprints

> **Status: advanced, optional helper.** A complete aweb team may use only
> identity, membership, and communication. It does not need Library, a profile
> service, a blueprint, or a materialized runtime home.

A blueprint can describe a useful team shape. A profile can describe one kind
of agent within that team. The `aw` CLI offers opt-in profile materialization,
but the operator or orchestrator owns agent definitions, homes, worktrees,
runtime selection, process lifecycle, and session UX.

## The four nouns

### Team

A team is the coordination boundary. Its members share work, roles,
instructions, locks, mail, chat, and presence.

### Agent

An agent is a named member of a team. Membership requires an identity, not a
profile or a materialized home. When an operator chooses profile
materialization, the same team can contain several agents using the same
profile.

### Profile

A profile is the portable operating package for a kind of agent: its mission,
accepted work, instructions, skills, and related resources. A profile does not
contain final identities, team certificates, credentials, or a required AI
vendor.

### Runtime

A runtime is the AI tool an operator or orchestrator selects—for example,
Claude Code, Pi, Codex, or `local-shell`. Runtime is an external staffing
choice, not a property of the profile or an aweb-owned lifecycle.

## Optional public Library seed

[`aweb.team`](https://library.aweb.ai/blueprints/aweb.team) is a maintained
starter blueprint in the open [aweb Library](https://library.aweb.ai). It
contains profiles such as
[`developer`](https://library.aweb.ai/blueprints/aweb.team/profiles/developer)
and [`reviewer`](https://library.aweb.ai/blueprints/aweb.team/profiles/reviewer).

When you opt into a Library-backed specification such as:

```text
alice@aweb.team/developer=claude-code
```

the CLI reads that public profile from the catalog and materializes a pinned
local snapshot. This path requires catalog access, but the team itself does
not. An empty-profile member such as `alice:local` requires no Library service
or plugin.

## What the optional materialization helper creates

When selected, the helper creates a home containing:

- the agent's aweb identity and team context;
- profile resources under `.aw/profile/`;
- `.aw/profile/ref.json`, recording the blueprint/profile version and digest;
- runtime-specific entry files such as `AGENTS.md`;
- an isolated `worktree/` when the home is associated with a git repository;
- `work-main/` only for profiles explicitly allowed to operate against the main
  checkout.

The source blueprint is a seed, not a runtime dependency. The agent continues
to work from its pinned local snapshot if the catalog is unavailable or the
upstream profile later changes.

## Identity scope is separate

The profile may supply a default identity scope, and the operator can choose it
explicitly in the agent specification:

```text
alice@aweb.team/developer:local=claude-code
alice@aweb.team/developer:global=claude-code
```

- `:local` is a team-scoped identity.
- `:global` is a durable AWID identity that can hold addresses and memberships
  in more than one team.

This does not decide whether the team itself is hosted or BYOT. Hosted/BYOT is
the team-authority axis; local/global is the agent-identity axis.

## Public seed versus private evolution

Creating or adding a member with a Library-backed profile reads the public
catalog. Improving that profile for one team is a separate, opt-in loop using
the team's private Library shelf:

1. adopt the public pin onto the team shelf;
2. let agents propose improvements as they work;
3. have the reviewing coordinator approve or reject them under the human's
   policy;
4. refresh the materialized home from the approved shelf version.

See [Improve a profile as the team works](/docs/improve-profile/) when the team is
ready to retain what it learns.

## Planned discovery commands

Catalog browsing is available today through
[library.aweb.ai](https://library.aweb.ai). CLI commands such as
`aw blueprint search` remain planned and must not be used as an onboarding
dependency.
