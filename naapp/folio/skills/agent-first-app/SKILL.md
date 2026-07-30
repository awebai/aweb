---
name: agent-first-app
description: Use when building an app where AI agents are the users: agent-first product design, BYOT/AWID team-certificate auth instead of accounts, no-signup services, team-scoped data, and server-plus-recipes application surfaces.
---

# Build an agent-first app

Load this before turning "build an app for agents", "build a BYOT app", or
"make an app for agent teams" into code. Its job is to stop the classic
mistake: building auth the old way.

## The inversion, in three lines

- The **agent is the user**.
- A valid AWID team certificate **is being signed in**.
- You ship a **server and exact recipes**, not a client agents must install.

The normal web-app reflex is backwards here. There is no signup button
because the caller already has identity, team membership, and signing tools.
Your service is a relying party.

## What you do not build

Push back if the plan includes:

- signup or onboarding accounts;
- OAuth, API keys, sessions, password reset, or dashboard write auth;
- per-user account records as the security boundary;
- a bespoke SDK/client that duplicates `aw id request --team-auth`.

Build this instead:

- one request-bound team-certificate verifier — load
  `skills/team-cert-verification/SKILL.md` for that boundary;
- team-scoped data keyed only from the verified certificate `team_id`;
- structured errors: 401 fail-closed for auth, 402 with `limit`, `current`,
  and `max` for caps;
- team-unit billing: the human appears once to pay, not to authenticate;
- free-tier caps from day one so no team is grandfathered into uncapped use.

## Agent-first surface checklist

Before you call the product usable by agents:

- Document recipes only after running them verbatim from a fresh workspace.
- Provide a plain-text `/llms.txt` twin for agents that fetch instead of
  browse.
- Make the landing page read like the terminal session it documents: shell
  comments explain, commands are individually copyable, and stop points are
  explicit.
- Do not add "copy all" when the sequence has human or controller stop
  points.
- Prefer append-only versions with verified attribution when the domain
  allows it; agent teams need auditability more than clever editing.

## Process: SOT first

Write the source of truth before writing features. It should name the
product contract, authority model, auth envelope, data model, API, validation
strategy, milestones, and non-goals. `docs/sot.md` is the worked example in
this repo.

Validation is part of the spec, not a cleanup task. Load
`skills/byot-e2e-validation/SKILL.md` while designing the auth and e2e
surface. Before any public claim, run a customer-shaped probe: fresh
directory, released `aw`, documented commands verbatim.

## Repo map lives elsewhere

Do not duplicate the repo map here. The agent-first pattern and copy/adapt/
replace map belongs in `docs/agent-first.md`. Link to that path from product
or README work and coordinate with whoever is editing it.
