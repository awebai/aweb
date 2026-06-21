---
title: "Launch readiness"
kicker: "Product SOT"
description: "What must be true before Aweb launches and is shown to VCs: the first polished AI-team wedge, acceptance criteria, sequencing, and explicit deferrals."
weight: 27
---

# Launch readiness

This is the source of truth for the launch epic:

> `default-aaas`: Launch readiness: AI team control plane wedge.

The goal is not to finish the whole aweb/anapp vision before launch. The goal is
to prove one company-facing wedge so clearly that a customer and a VC both
understand why Aweb exists.

## 1. Launch promise

The launch promise is:

> Aweb is the control, coordination, and audit plane for AI coworkers across
> whatever runtime your company already uses.

The customer reason to care:

> Without Aweb, agents become scattered chats, local scripts, forgotten context,
> unsafe tool access, and unreviewable work. Aweb turns them into a managed AI
> team that can be assigned work, use company apps safely, coordinate, learn,
> and leave a signed audit trail.

The first launch wedge is engineering teams:

> Run an AI dev team without losing control.

## 2. Launch bar

Launch is ready when the first 10 minutes work:

1. A human creates a company/team from a first-party engineering blueprint.
2. Aweb shows the proposed agents, profiles, apps, permissions, approvals, and
   runtime bindings before anything sensitive happens.
3. The human applies the blueprint.
4. The human adds or starts coordinator/developer/reviewer agents using native
   `aw` commands.
5. The team connects to real work: tasks/messages plus GitHub/dev where
   available.
6. A real task is assigned.
7. The human watches the agents coordinate in a workroom.
8. Sensitive actions require approval.
9. The signed audit trail shows who did what, through which app, under which
   authority.
10. At least one durable learning proposal can be produced and reviewed.

The launch demo must use real Aweb behavior, not a scripted mock. It can be a
curated path, but every visible action should correspond to real state.

## 3. VC bar

VCs do not need every future app. They need evidence for four claims:

1. **Problem**: companies will use many agents across many runtimes, but raw
   agents lack identity, permissions, coordination, memory, and audit.
2. **Wedge**: Aweb makes one useful team shape work better than raw
   Claude/Codex/ChatGPT alone.
3. **Platform**: once identity, authority, coordination, app grants, and audit
   exist, every agent-facing app becomes easier and safer to adopt.
4. **Business**: usage grows with valuable hosted agent actions; billing can be
   simple bundled mutation quota, with identity/network basics kept free.

The VC demo should show the same launch path as customers, then zoom out to the
platform:

```text
one polished AI dev team
  -> same control plane works across runtimes
  -> same app/grant/audit rails support more anapps
  -> same blueprint/profile model supports more company functions
```

## 4. Execution principles

- Build the wedge before the marketplace.
- Make first-party blueprints excellent; they are product, not samples.
- Native `aw` support must orchestrate existing primitives, not create a second
  control plane.
- Launch with local/git blueprints; `library.aweb.ai` is not required for wedge
  v1.
- `aw agent start` is a thin local launcher, not a hosted runtime service.
- Audit covers Aweb-mediated actions, not arbitrary filesystem or shell effects
  that happen outside Aweb-controlled tools.
- Agents should use secrets through `secrets.aweb.ai`, app-native actions,
  `aw do`, or approved runners; raw secret values should not be returned to
  agents.
- Use customer language: AI coworkers, control, coordination, signed audit
  trail, approvals, apps agents can use.
- Keep protocol language for docs and developers: AWID, MCP, A2A, app
  manifests, signed envelopes, BYOT.

## 5. Workstreams

### L1. Positioning and homepage

Outcome: a visitor understands the product in under 30 seconds.

Required:

- one clear homepage message:
  "Aweb is the control, coordination, and audit plane for AI coworkers";
- one primary call to action around creating or seeing an AI team;
- a concrete engineering-team use case, not abstract protocol copy;
- screenshots or live views of agents, work, approvals, and audit;
- copy that translates technical primitives into customer benefits.

Acceptance criteria:

- homepage explains why a company wants a control plane for AI coworkers;
- homepage does not lead with AWID/MCP/A2A/anapps;
- first viewport makes clear that humans create/manage teams and agents use
  apps;
- demo path and signup/onboarding path match the product wedge.

### L2. First-party engineering blueprint

Outcome: a company can start from a high-quality AI dev team blueprint.

Required:

- `blueprint.yaml` for the engineering team;
- coordinator, developer, and reviewer blueprints;
- each profile has mission, responsibilities, app requests, approval needs,
  runtime hints, and done criteria;
- realistic defaults for tasks/messages/GitHub/dev;
- reviewable code artifacts only where they add real value;
- sample workflows for issue triage, implementation, review, and handoff.

Acceptance criteria:

- `aw blueprint inspect` can summarize the team before install;
- the capability diff is understandable to a human;
- applying the blueprint creates a pinned installed snapshot;
- the first assigned engineering task does not require a long custom prompt to
  make the team useful;
- profile/blueprint/library-profile remain one concept.

### L3. Native `aw` setup path

Outcome: setup is boring, fast, and recoverable.

Required commands:

```bash
aw blueprint inspect <source>
aw blueprint apply <source> --team <team> [--target <dir>]
aw team create <team> --from <source>
aw agent add <name> --profile <profile> --runtime <runtime> [--worktree] [--start]
aw agent status
```

Required behavior:

- dry-run plan before mutation;
- idempotent enough to resume or inspect after failure;
- no private keys or generated `.aw` identity state written into committed
  profile resources;
- app grants use existing app-grant rails;
- team/identity creation uses existing control-plane/core APIs;
- installed profiles are pinned artifacts;
- effective permissions are team grant intersect profile request intersect
  per-agent override intersect approval policy.

Acceptance criteria:

- one command creates the engineering team from the first-party blueprint;
- one command adds a new local developer/reviewer agent;
- failure leaves inspectable state and a clear recovery path;
- no second team-setup system is introduced.

### L4. Local runtime launcher

Outcome: local agents can be started without hand-building homes, worktrees, or
tmux sessions.

Required:

- local Claude Code launcher;
- local Codex or Pi launcher if available;
- optional tmux supervisor;
- instance home creation;
- profile binding;
- team certificate/config installation;
- worktree creation for developer profiles;
- status/stop/restart/logs or enough equivalent state for the demo.

Acceptance criteria:

- `aw agent add developer --runtime claude-code --worktree --start` lands the
  runtime in the right home/worktree;
- `aw agent status` shows useful runtime state;
- launcher is local-only and thin; no hosted runtime service is implied.

### L5. Workroom dashboard

Outcome: the human can see and manage the AI team.

Required:

- agents and runtime bindings;
- active work/tasks;
- messages/activity stream;
- app activity;
- approvals;
- errors/blockers;
- signed audit trail;
- basic usage/cost if available.

Acceptance criteria:

- a human can answer "what is each agent doing?";
- a human can approve or reject sensitive actions;
- agent/app activity links to the underlying task/message/audit record;
- dashboard presents one human-facing site, not a scatter of app pages.

### L6. Agent operating surface

Outcome: agents have a simple way to know who they are, what they can do, and
what to work on.

Required:

```bash
aw whoami
aw agent profile show
aw work ready
aw work claim <ref>
aw app list
aw mail/chat
aw memory propose ...
```

Acceptance criteria:

- an agent can discover identity, team, profile, work, apps/scopes, approvals,
  and escalation path;
- the same state powers both human workroom and agent tools;
- MCP/custodial agents receive only the effective tools allowed by grants and
  profile requests.

### L7. Signed audit trail

Outcome: Aweb has a visible governance differentiator.

Design source: [`audit-logs-app-sot.md`](audit-logs-app-sot.md).

Launch audit is scoped to Aweb-mediated actions. It should sign and render the
authority and outcome of actions that cross Aweb surfaces. It should not claim
to sign arbitrary filesystem edits, raw shell commands, browser clicks, or model
reasoning that happen outside Aweb-controlled tools.

Required event classes:

- identity/team changes;
- app grants and approval-policy changes;
- task assignment/claim/completion;
- messages or coordination events used in the demo;
- app actions;
- human approvals;
- emitted app events where applicable.
- `aw do` and secret-mediated actions where included in the demo.

Acceptance criteria:

- workroom shows a readable signed audit trail;
- each important event has actor, team, app/action, target, timestamp,
  authority/approval, result, and signature/envelope where applicable;
- audit distinguishes signed Aweb-mediated facts from agent-reported activity;
- docs and task scope preserve the target where a customer can later self-host
  `logs.aweb.ai` against hosted Aweb core through a scoped audit export/feed;
- customer copy uses "signed audit trail" or "reviewable record", not only
  "logs" or "traceability".

### L8. Hosted MCP and custodial path

Outcome: non-local runtimes are first-class enough to explain and demo.

Required:

- hosted custodial identity creation/selection;
- OAuth or connector grant to bind an external runtime;
- MCP server exposing the effective app tools for that custodial identity;
- secret tools expose refs/handles and secret-mediated actions, not raw secret
  values;
- dashboard visibility that this agent/runtime is part of the team;
- clear UX distinction between local runtime, hosted MCP runtime, and future
  hosted runner.

Acceptance criteria:

- ChatGPT/Claude.ai-style agent can connect through hosted MCP and see allowed
  tools;
- no raw key management is required from that external agent;
- app tools reflect team grant/profile/per-agent policy.
- custodial MCP agents can request approved secret use but cannot call a
  general `secrets.get_value` tool.

### L8.5. Secrets and `aw do`

Outcome: agents can use approved secrets without seeing them, and humans get a
signed record of the mediated action.

Design source: [`secrets-aw-do-sot.md`](secrets-aw-do-sot.md).

Required:

- `secrets.aweb.ai` owns secret refs, metadata, policy, and access checks;
- local agents use `aw do` to run commands that need secrets;
- `aw do` injects secrets into the child process without returning the values to
  the agent;
- stdout/stderr are redacted before being returned;
- the signed audit trail records actor, team, secret refs/versions, approval or
  policy, action/command template, result, and output hashes/redacted excerpts;
- hosted MCP agents use app-native actions or runner-mediated secret use, not
  raw value reads.

Acceptance criteria:

- demo includes one secret-mediated local command or a clearly implemented
  app-native secret use path;
- agent-visible output never includes the secret value;
- audit shows that the secret was used without logging the secret value;
- custodial MCP surface exposes secret refs/request-use, not `get_value`.

### L9. Minimal learning loop

Outcome: Aweb shows that company knowledge can compound.

Required for launch:

- an agent can produce a durable learning proposal;
- a human/coordinator can review it;
- approved learning can be represented as local/git-backed memory or profile
  change.

Not required for wedge v1:

- full `library.aweb.ai`;
- hosted profile editor;
- public marketplace;
- automatic propagation to other teams.

Acceptance criteria:

- demo includes one learning proposal after real work;
- proposal is reviewable, attributed, and connected to the task that produced
  it;
- docs explain that `library.aweb.ai` later generalizes this into company-level
  promotion and reuse.

### L10. Demo, proof, and sales materials

Outcome: customers and VCs can understand the value without reading docs.

Required:

- a repeatable demo script;
- one real dogfooded task transcript/evidence package;
- homepage screenshots or live demo path;
- concise pitch deck narrative;
- pricing and packaging summary;
- security/trust summary;
- launch readiness checklist.

Acceptance criteria:

- demo can be reset and rerun;
- demo output includes real tasks/messages/audit records;
- pitch explains wedge, platform expansion, and business model in plain
  language;
- no critical claim depends on unreleased marketplace/library/hosted-runner
  functionality.

### L11. Packaging and pricing story

Outcome: launch and VC conversations have a simple commercial model.

Required:

- one-page pricing and packaging summary;
- clear hosted mutation definition;
- free identity/network basics in the story;
- paid tiers that raise bundled hosted mutation quota and team/company limits;
- no separate A2A capability gate unless explicitly changed by Juan;
- dashboard usage/quota if available, or a clear demo explanation if not.

Acceptance criteria:

- the pricing story can be explained in one minute;
- customers understand what is free, what is metered, and why paid usage grows
  with useful hosted agent actions;
- VC materials connect usage to customer value without overpromising billing
  implementation.

## 6. Suggested sequencing

1. Freeze the launch demo narrative and exact first task.
2. Build the engineering blueprint/blueprints to product quality.
3. Implement `aw blueprint inspect/apply` for local dirs.
4. Implement `aw team create --from` as a wrapper over existing primitives.
5. Implement `aw agent add/start/status` for local runtime.
6. Make tasks/messages/dev or GitHub sufficient for one real workflow.
7. Build the workroom view around the demo path.
8. Expose the signed audit trail in the workroom.
9. Add secret-mediated execution proof through `aw do` or app-native secret use.
10. Add hosted MCP/custodial proof path, including secret refs/request-use
    without raw value reads.
11. Add minimal learning proposal.
12. Write pricing/packaging story.
13. Polish homepage/demo/pitch.
14. Run the full demo from a clean environment until it is boring.

## 7. Explicit deferrals

Do not block launch on:

- public marketplace;
- broad `library.aweb.ai`;
- hosted agent runners;
- arbitrary hosted secret-backed command execution before a runner exists;
- many vertical blueprints;
- visual profile editor;
- full app ecosystem;
- all restructuring milestones;
- perfect billing automation beyond a credible pricing/quota story;
- full enterprise admin surface.

## 8. Launch risks

### Setup feels fragile

Mitigation: prioritize native `aw` setup commands over agent-followed setup
skills.

### Blueprint is too generic

Mitigation: make the engineering blueprint opinionated and dogfooded on real
work.

### Dashboard looks like infrastructure

Mitigation: workroom is centered on agents, work, approvals, and audit.

### Scope expands back into core

Mitigation: `aw` commands orchestrate existing primitives; new domain semantics
belong in apps.

### Hosted/nontechnical story is unclear

Mitigation: show custodial MCP as the near-term answer; hosted runners are
future.

## 9. Readiness checklist

- [ ] Homepage message and demo CTA are aligned with launch promise.
- [ ] Engineering blueprint installs cleanly from local source.
- [ ] Blueprint inspect/apply/team-create path is implemented.
- [ ] Agent add/start/status path works for local runtime.
- [ ] Workroom shows agents, work, activity, approvals, and audit.
- [ ] One real dogfooded task completes through the team.
- [ ] Signed audit trail is visible and understandable.
- [ ] Hosted MCP/custodial path is demonstrable.
- [ ] Secret-mediated action path is demonstrable without exposing raw secret
      values to agents.
- [ ] Minimal learning proposal is demonstrable.
- [ ] Demo script can be reset and rerun.
- [ ] Pricing/quota story is explainable in one slide.
- [ ] Deferrals are explicit and not accidentally promised.
