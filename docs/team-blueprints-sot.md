---
title: "Team blueprints and agent profiles"
kicker: "Product SOT"
description: "How companies create and operate AI teams from blueprint repos, blueprints, app grants, runtime bindings, and signed audit trails."
weight: 26
---

# Team blueprints and agent profiles

> **SUPERSEDED — NON-AUTHORITATIVE.** This profile/team-builder product
> narrative does not set current direction and must not generate new work.
> Verified current materialization and runtime facts will be consolidated into
> focused advanced contracts and guides; this competing SOT is then removed.
> Until that consumer migration completes, treat every product-direction claim
> below as historical.

This was the source of truth for a product surface intended to let a company
start using aweb quickly:

> A human points aweb at a blueprint repo or directory. Aweb inspects it, shows
> the proposed AI team, copies blueprints into the customer's team/repo,
> connects agents to runtimes and apps, and opens a workroom where humans can
> assign work, approve sensitive actions, watch progress, and keep a signed
> audit trail.

This document supersedes the older "blueprints are repos of souls" framing.
The old mechanism is still useful: identity-free agent bodies are copied into
the customer's repo and symlinked from runnable instance homes. The product
vocabulary changes:

- external/customer-facing: **agent profile** or **blueprint**;
- internal/legacy implementation: **soul** may remain as a directory name until
  migration is worth doing;
- composition unit: **team blueprint**;
- authority unit: **team app grants**, not profile-owned app installs;
- learning surface: **library.aweb.ai**, an app, not a new core layer.

The goal is not to invent a new abstraction. It is to productize the pattern we
already dogfood in blueprint repos such as `../aweb-team-dev-simple/`: make it
explicit, inspectable, installable, versioned, permission-aware, and supported
by the CLI and dashboard.

`aw` support must orchestrate existing core/control-plane primitives, not create
a parallel control plane. Team creation, blueprint application, app grants,
identity creation, role/instruction installation, and runtime binding should be
composed from the same primitives the rest of aweb uses.

## 1. Customer promise

The product promise is:

> Put AI agents to work across your company without losing control.

More specifically:

> Aweb lets companies turn scattered AI tools into managed AI coworkers that can
> be assigned work, use company apps safely, coordinate with each other, and
> leave a verifiable record of what happened.

Why companies need this:

- agents are scattered across Claude Code, Codex, ChatGPT, Copilot, n8n,
  internal scripts, and future hosted runners;
- each runtime has its own context, tool wiring, and failure modes;
- humans need to know who did what, what changed, which system was touched, and
  which approval allowed it;
- agents need shared work queues, app access, instructions, profiles, and event
  subscriptions;
- companies need signed audit trails for legal, security, compliance, and
  operational review.

Do not lead the customer with AWID, MCP, A2A, app manifests, BYOT, or signed
envelopes. Translate them:

- AWID -> verified agent identity
- MCP -> connect agents from Claude, ChatGPT, Copilot, and other clients
- A2A -> open agent interoperability
- app manifests -> apps agents can use
- BYOT -> keep your company's keys and control
- mutation quota -> included agent actions

## 2. Product objects

### Company

The billing, admin, and human governance container. A company owns teams,
installed apps, billing, quotas, hosted identities, and audit policy.

### Library app (`library.aweb.ai`)

The company's canonical, versioned operating knowledge for agents, delivered as
a cert-authed app.

It contains profiles, skills, playbooks, memory, policies, app recipes, evals,
and glossary/context that should be reused across teams. In the shipped
materialization path, the public catalog read is independent from the private
team shelf:

```text
public blueprint profile (for example aweb.team/developer)
  -> aw local materialization into agents/instances/<name>
     -> optional later adoption/evolution through the library.aweb.ai shelf
```

`library.aweb.ai` is **not** live mutable role text, and it is not part of
aweb core. It is a versioned source of truth with diffs, approvals, provenance,
rollback, and promotion flows. Public materialization does not require the
Library plugin or a private shelf; teams opt into the shelf when they want the
profile proposal/approval/update loop.

Core's job is only to enforce identity, team authority, app grants, installed
pins, and runtime facts. The library app produces versioned artifacts and
promotion proposals. It should reuse the app install/grant and pinned digest
rails, not create a parallel catalog or authority system.

For dev-heavy customers, the library may be backed by a git repo. For
non-technical customers, aweb hosts the library app but keeps the same
semantics: versioned, reviewable, promotable, and rollbackable.

### Team

A managed group of agent identities with roles/profiles, app grants, work
queues, event subscriptions, runtime bindings, and audit trails.

A team is **not** a process topology. It is not "a bunch of Claude Codes in
tmux." Claude Code in tmux, Codex in worktrees, ChatGPT through MCP, n8n
workflows, and future hosted runners are all runtime bindings for agents in a
team.

### Team blueprint

A repo or directory that describes a useful AI team shape: profiles, suggested
apps, capability requests, runtime hints, workflows, launch instructions, and
human-facing explanation.

A blueprint is a **seed, not a dependency**. Applying a blueprint materializes a
pinned local snapshot into agent homes. The customer owns and evolves the
installed copy. For the 1.30.0+ launch path, `aweb.team` is the single maintained
seed blueprint; the older development/support seed refs were folded into that
catalog entry and should not be used in new docs.

### Agent profile

An operating package for one kind of AI coworker.

This is the same concept as a **blueprint**. Do not create separate schema or
storage concepts for "agent profile", "blueprint", and library profile
entries. A blueprint is the packaged form of an agent profile.

It can include:

- mission and responsibilities;
- instructions;
- skills and app skill references;
- code artifacts and helper scripts;
- workflow templates;
- event subscription requests;
- required app capabilities;
- escalation rules;
- memory policy;
- evals/checklists;
- done criteria and metrics.

A profile says "what this agent is for and what it needs." It does not itself
grant authority.

### Agent

A named identity in a team, usually bound to one installed profile and one or
more runtimes. Examples: `coordinator`, `developer`, `reviewer`,
`marketing-researcher`.

### Instance

A live runnable home for an agent/profile binding on a specific machine or
runtime. Current local instances are directories with `.aw` state, materialized
profile files under `.aw/profile/`, harness entry files such as `AGENTS.md` (and
`CLAUDE.md` for Claude Code), and local skills/artifacts copied from the profile
payload. Hosted custodial MCP identities and future hosted runners are runtime
bindings for the same agent/profile model.

Instance directories are runtime state. Profiles are operating assets.

### Runtime binding

Where an agent runs:

- Claude Code local;
- Codex local;
- Cursor/local CLI;
- ChatGPT or Claude.ai through hosted MCP;
- n8n or external workflow systems;
- Microsoft Copilot or other enterprise runtimes;
- future aweb-hosted runners.

The same profile can bind to different runtimes if the required apps and
capabilities are available.

### App

A domain surface agents can use: messages, tasks, dev, GitHub, Linear/Jira,
Folio, secrets, KPI, logs, etc.

Apps are installed at the team level. Profiles request capabilities from apps.

### Team app grant

The authority record that says a team may use an app with specific scopes. This
is the unit that controls external system access, app state, quota, and
subscriptions.

### Profile capability request

A profile's declaration of what it needs to be useful, for example:

- GitHub pull request read/comment;
- Tasks read/update;
- Messages send;
- Secrets read with approval;
- subscribe to `task.assigned`;
- subscribe to `github.pull_request.opened`.

Requests are not grants. The effective agent capability is:

> team app grant INTERSECT profile request INTERSECT per-agent override
> INTERSECT approval policy.

### Workroom

The human dashboard for a team: agents, active work, messages, tasks, app
activity, approvals, cost, errors, and signed audit trail. This is the primary
human-facing surface after setup.

### Signed audit trail

The legally and operationally useful record of important agent and app events:
identity, app, action, target, approval, result, timestamp, and signed
credential where applicable.

For launch, the signed audit trail covers Aweb-mediated actions. It should not
claim to sign arbitrary filesystem edits, shell commands, browser clicks, model
reasoning, or other side effects that happen outside Aweb-controlled tools. The
workroom may show agent-reported activity, but it is not signed audit unless it
crosses an Aweb authority surface.

Use "signed audit trail" in customer-facing language. Use "traceability" only
for technical/debugging audiences.

Core owns the signed audit facts. A hosted or self-hosted logs app owns views,
search, retention, export, and compliance workflows. Customers should
eventually be able to self-host audit/logs while using a hosted aweb service,
through a scoped audit export/feed. The former application-specific audit/logs
proposal is not part of public aweb authority.

### Secret-mediated execution

Agents should use secrets without seeing raw secret values.

`secrets.aweb.ai` owns secret refs, policy, and access checks. Local agents use
`aw do` to run commands that require secrets; `aw do` resolves approved secret
refs, injects values into the child process without returning them to the agent,
redacts output, and writes a signed audit event. Custodial MCP agents use
app-native actions or runner-mediated secret use; they receive secret handles,
not values.

The former application-specific secrets/action proposal is not part of public
aweb authority.

## 3. Authority model

The core rule:

> Teams install apps. Profiles request capabilities. Agents receive only the
> effective intersection.

Profiles must never silently install apps, widen team grants, create external
tokens, or subscribe agents to arbitrary data streams. A profile can declare
what it needs; the team/control plane decides what is allowed.

Example:

```yaml
profile:
  id: code-reviewer
  required_apps:
    github:
      scopes:
        - pull_request:read
        - pull_request:comment
    tasks:
      scopes:
        - task:read
        - task:update
    messages:
      scopes:
        - chat:send
        - mail:send
  subscriptions:
    - app: github
      event: pull_request.opened
      filter:
        repo: current
    - app: tasks
      event: task.assigned
```

Install/apply UX must show a capability diff:

```text
Code Reviewer requests:
  GitHub: pull_request:read, pull_request:comment
  Tasks: task:read, task:update
  Messages: chat:send, mail:send
  Events: github.pull_request.opened, tasks.task.assigned

Team currently grants:
  GitHub: pull_request:read
  Tasks: task:read, task:update
  Messages: chat:send, mail:send

Missing:
  GitHub: pull_request:comment

Choose: approve grant / deny / require human approval
```

This is the setup simplifier: the user does not have to invent the tool policy
from scratch, but authority is still explicit.

## 4. Blueprint contents

A blueprint is a directory. Recommended shape:

```text
profile.yaml
instructions.md
skills/
  <skill-name>/SKILL.md
app-skills.yaml
subscriptions.yaml
permissions.yaml
workflows/
  <workflow>.md
artifacts/
  scripts/
  templates/
evals/
memory/
docs/
decisions/
```

Only `profile.yaml` and `instructions.md` are required for v1.

### `profile.yaml`

Example:

```yaml
schema_version: 1
id: code-reviewer
name: Code Reviewer
version: 0.1.0
summary: Reviews code changes for correctness, tests, security, and product fit.
runtime_hints:
  preferred:
    - codex
    - claude-code
accepts_work:
  - review_pr
  - inspect_diff
  - review_test_failure
required_apps:
  github:
    scopes:
      - pull_request:read
      - pull_request:comment
      - contents:read
  tasks:
    scopes:
      - task:read
      - task:update
  messages:
    scopes:
      - chat:send
      - mail:send
approval_required:
  - merge_pr
  - deploy_prod
  - read_secret
subscriptions:
  - app: github
    event: pull_request.opened
  - app: tasks
    event: task.assigned
skills:
  local:
    - skills/code-review/SKILL.md
  app:
    - app: github
      skill: review-pr
artifacts:
  - path: artifacts/scripts/review_diff.py
    kind: helper_script
evals:
  - evals/review-quality.yaml
```

### Code artifacts

Profiles may include code artifacts, but classify them:

1. **Static artifacts**: skills, templates, checklists, docs. Allowed.
2. **Local helper scripts**: code an agent may run in its workspace. Allowed
   with provenance, review, and local execution boundaries.
3. **Service components**: long-running daemons, webhooks, app adapters. These
   should usually be apps, not profile code.
4. **App skills**: instructions for using installed apps. Prefer references to
   app-published canonical skills where possible.

The install UX must show code artifacts distinctly from text/instructions.
Community profile code should be reviewed like dependency code.

## 5. Team blueprint contents

A blueprint composes profiles into a useful team.

Recommended shape:

```text
blueprint.yaml
README.md
profiles/
  coordinator/
  developer/
  reviewer/
apps.yaml
permissions.yaml
runtimes.yaml
workflows/
docs/
skills/
examples/
```

Example `blueprint.yaml`:

```yaml
schema_version: 1
id: engineering-dev-team
name: Engineering AI Team
summary: Coordinate AI agents to ship code changes with review and audit.
profiles:
  - id: coordinator
    path: profiles/coordinator
    default_agent_name: coordinator
  - id: developer
    path: profiles/developer
    default_agent_name: developer
  - id: reviewer
    path: profiles/reviewer
    default_agent_name: reviewer
recommended_apps:
  - messages
  - tasks
  - github
  - dev
approval_policy:
  require_human_approval:
    - github.merge_pr
    - github.create_release
    - secrets.read
runtime_options:
  local:
    - claude-code
    - codex
  hosted_mcp:
    - chatgpt
    - claude
```

A blueprint must not contain `.aw` state, DIDs, addresses, certificates, invite
tokens, private keys, customer API keys, generated worktrees, or final hosted
identity state.

## 6. Source, installation, and ownership

### Sources

V1 accepts:

```bash
aw blueprint inspect ./aweb-team-dev-simple
aw blueprint inspect github.com/awebai/aweb-team-dev-simple
```

Planned (hosted-catalog discovery — **not in the shipped CLI yet**; today use
`aw blueprint inspect` with a path, `github.com/...`, or a blueprint ref like
`aweb.team`):

```bash
aw blueprint search engineering
aw blueprint inspect aweb/engineering-dev-team
```

The hosted catalog is discovery, not ownership. A catalog entry points to a
source, version, digest, required apps, capability requests, and docs.

### Inspect/create/add

Inspecting a blueprint/profile pack shows the plan. Creating a team and adding
profile-bound agents use the shipped team and agent runtime verbs.

### Getting started (canonical — onboarding surfaces quote this block)

The minimal do-this-now onboarding. This is the single canonical shape landing
pages and naapp sites quote verbatim. `aw team create` creates your team and
materializes its starter agents from the `aweb.team` blueprint in one command —
a public catalog read, no Library plugin (aw 1.32+) — then `aw team up` launches
them.

```bash
# Install the aw CLI
npm install -g @awebai/aw

# Create your team and its starter agents in one command
aw team create eng --username <you> \
  --agent alice@aweb.team/developer=claude-code \
  --agent bob@aweb.team/reviewer=pi

# Launch the team
aw team up
```

`aweb.team` comes from [library.aweb.ai](https://library.aweb.ai), the open
blueprint library — we maintain it with high-quality profiles anyone can start
from. Browse what each profile is: the
[`aweb.team` blueprint](https://library.aweb.ai/blueprints/aweb.team) and its
profiles, for example
[developer](https://library.aweb.ai/blueprints/aweb.team/profiles/developer) and
[reviewer](https://library.aweb.ai/blueprints/aweb.team/profiles/reviewer).

`aw team up` uses **tmux** — install it for the automatic launch, and `aw team
up` starts and wires every agent for you (channel plugin, trust/dev-channel
prompts, `pi --approve`); without tmux it prints the exact per-agent commands to
start each home manually. It launches each materialized home's runtime — Claude
Code (with the aweb channel plugin) and Pi today — auto-answering the trust and
development-channel prompts; Codex and `local-shell` homes are materialized but
started manually. No `aw plugin install` is needed to onboard — materialization
is a plain catalog read; the Library **shelf** is a separate opt-in app. See
[Running materialized agents](running-agents.md) for the launch details, the
one-command `aw team add … --start`, and home/worktree isolation.

**Grow an existing team.** To add members later, use `aw team extend` — it adds
agents from the same blueprint, discovering the authority from your team context:

```bash
aw team extend charlie@aweb.team/developer=pi
```

From any directory with no active team context, a team API key is the whole
credential — no dashboard session:

```bash
AWEB_URL=<url> AWEB_API_KEY=<key> aw team extend alice@aweb.team/developer=claude-code
```

When the current workspace already has an active team, an ambient
`AWEB_API_KEY` selects API-key authority and uses the active team as an assertion
against the team returned by the server. A mismatch rolls back the first added
member and stops before adding another. To deliberately extend a different team,
pass an explicit `--api-key`, which bypasses the workspace assertion; add
`--team-id` when the API key's team should be checked against a specific team.

**Self-hosted (BYOT).** To create and populate a team you control end to end,
add `--byot` and your namespace:

```bash
aw team create eng --byot --namespace <your-domain> --username <you> \
  --agent alice@aweb.team/developer=claude-code --agent bob@aweb.team/reviewer=pi
aw team up
```

The default seed blueprint is `aweb.team`; override it with `--blueprint` (or
`AWEB_BLUEPRINT`) and the catalog provider with `--library-url` (or
`AWEB_LIBRARY_URL`). The catalog URL precedence is `--library-url`, then
`AWEB_LIBRARY_URL`, then `https://library.aweb.ai`.

### Fuller dev-team flow (named team + roster)

The one-command `aw team create … --agent …` in Getting started wraps these
composable primitives. Use them directly when you want to inspect first, create
the team and add members in separate steps, or grow a team later:

```bash
aw blueprint inspect aweb.team          # see the proposed team and its profiles
aw team create eng                       # create the team
aw team add developer@aweb.team/developer=claude-code   # add a member from the team workspace
```

(To add members from outside the team workspace — a fresh dir or another home —
use `aw team extend <agent-spec>...` with a team API key or discovered authority.)

Run agents with `aw team up` as in the Getting started block above, or start a
materialized home manually when using a runtime that `aw team up` does not launch
yet.

`aw team add` materializes the profile from the public blueprint catalog with a
direct read — no Library plugin required (aw 1.30+). The blueprint defaults to
`aweb.team`, our maintained starter blueprint; override the blueprint with
`--blueprint` (or `AWEB_BLUEPRINT`) and the catalog provider with `--library-url`
(or `AWEB_LIBRARY_URL`). The Library **shelf** — the propose/approve profile
evolution loop — is a separate opt-in app a team installs when it wants it:
`aw plugin install https://library.aweb.ai/.well-known/aweb-app.json`. See
[`blueprint-materialization-contract.md`](blueprint-materialization-contract.md)
for the payload/pin contract and [`running-agents.md`](running-agents.md) for the
runtime launcher behavior.

A roster can also be seeded during create:

```bash
aw team create eng \
  --agent coordinator@aweb.team/coordinator=claude-code \
  --agent developer@aweb.team/developer=claude-code \
  --agent reviewer@aweb.team/reviewer=pi
```

These commands must show or rely on an inspectable plan and compose explicit
primitives. The recoverable lower-level verbs must exist.

Those primitives must reuse existing authority rails:

- team and identity creation from core/control-plane APIs;
- app install/grant from the app-grant model;
- role/instruction/profile installation as pinned artifacts;
- effective permissions from team grant intersect profile request intersect
  per-agent override intersect approval policy.

Do not implement blueprint application as a second team-setup system.

### Installed ownership

Once applied, the materialized home owns a local pinned copy:

- files are visible in the agent home;
- `.aw/profile/ref.json` records the blueprint/profile/version/digest and runtime;
- local modifications are expected;
- agents can propose patches;
- humans/coordinators review changes;
- updates from upstream are diffs or explicit re-materialization, not live mutations.

There is no live dependency on the source blueprint at runtime.

Teams may materialize from:

- the public catalog source directly;
- a `library.aweb.ai` shelf profile after installing the Library plugin;
- a repo-local or local-directory blueprint.

The important invariant is that execution uses a pinned local materialized
snapshot. Learning and updates flow through proposals and promotion, not implicit
live mutation.

### Non-dev teams

For non-dev teams that do not have a repo, aweb provides a hosted
`library.aweb.ai` app and hosted team-installed snapshots. It must preserve the
same semantics:

- immutable versions;
- diffs;
- approvals;
- rollback;
- provenance;
- fork from catalog;
- propose update.

Do not build a mutable hosted "role text" editor as the primary model. That
recreates the roles feature nobody used.

## 7. `library.aweb.ai` and learning model

Without a library app, teams can learn locally but the company does not learn
reliably. A developer profile improved in one repo may never reach another repo;
a marketing lesson learned by a hosted MCP team may disappear into that team's
local profile snapshot. `library.aweb.ai` solves this as an app, not by
expanding core.

The first product wedge is still excellent team creation:

```text
good blueprint -> aw inspect -> aw team create/add -> direct runtime launch
```

The library app is the learning and reuse loop that follows. It should not
delay making blueprints and native `aw` support work well.

### Library entry types

Long term, the library app can store:

- **Profiles** — operating packages for agent types.
- **Skills** — reusable procedures.
- **Playbooks** — workflows, checklists, and recurring operating patterns.
- **Memory** — durable company facts.
- **Policies** — approval rules, forbidden actions, escalation rules.
- **App recipes** — how this company uses GitHub, Slack, HubSpot, Linear, etc.
- **Evals** — how the company judges quality.
- **Glossary/context** — product names, customer names, KPI definitions, tone.

V1 should prove the full learning loop with one entry type before broadening the
surface. The recommended first entry type is **Memory**:

```text
team produces a useful durable fact
  -> agent proposes it as a patch/blob
  -> human reviews
  -> library.aweb.ai publishes a new version
  -> other teams can pin that version
```

Profiles, skills, playbooks, policies, recipes, and evals should be represented
in the SOT because they are where the product likely goes, but they should not
all be v1 implementation scope.

Keep these categories distinct:

- Knowledge: "ACME calls customers members, not users."
- Policy: "Legal approval is required before sending external claims."
- Skill: "How to draft a launch email."
- Profile: "Marketing Writer uses these skills, policies, apps, and style
  constraints."

### Learning flow

Learning flows upward; execution flows downward.

```text
Team install learns something
  -> agent proposes a change
  -> team accepts locally or rejects
  -> company promotes the useful change to library.aweb.ai
  -> other teams can update from the library
```

Concrete flow:

1. An agent completes work.
2. The agent writes a short retrospective when useful.
3. The agent proposes a profile/skill/memory/policy/workflow change.
4. A human or coordinator reviews it.
5. The change lands locally for that team, or is promoted to `library.aweb.ai`.
6. `library.aweb.ai` creates a new version.
7. Other teams are shown an update with a diff and impact.

Example:

```text
Learned from: Marketing Team / campaign-2026-06 / researcher
Proposed change: add competitor matrix format to market-research skill
Impact: 4 teams use this skill
Options: approve to this team only / promote to library / reject
```

### Versioning and pins

Everything reusable should be versioned:

```text
company/code-reviewer@1.4
company/legal-approval-policy@2.1
company/launch-email-skill@0.8
team/website-redesign/reviewer@local+3
```

Teams pin library entries:

```yaml
profiles:
  reviewer: company/code-reviewer@1.4
policies:
  approval: company/engineering-approval@2.1
```

The dashboard may say:

```text
Update available: company/code-reviewer 1.5
Changes: adds migration-review checklist and stricter security escalation.
Used by: 6 teams.
```

No update is applied without review/approval unless the company deliberately
configures an auto-update policy for a low-risk category.

### Git-backed and hosted-backed libraries

Both modes must share semantics:

- hosted `library.aweb.ai` for non-technical companies;
- git-backed library for technical companies;
- repo-local installs for dev teams.

The storage backend changes, not the product contract: versioned, diffable,
reviewable, promotable, pinned, and rollbackable.

## 8. CLI surface

The CLI should make blueprint use boring and inspectable.

The current assumption that "the blueprint ships skills, so an agent can create
the team" is not good enough for the product. It is too slow, too fragile, and
too dependent on an agent correctly following a long filesystem/identity/runtime
procedure. Skills remain useful as documentation and extension points, but the
happy path must be first-class `aw` behavior.

Required CLI principle:

> Creating a team from a blueprint and adding/running agents must be one or two
> obvious commands with a dry-run plan, clear recovery, and no hidden identity
> magic.

The commands are orchestration over existing primitives. They are product UX,
not a second source of truth for teams, identities, apps, grants, or installed
runtime facts.

### Blueprint/profile-pack commands

```bash
aw blueprint inspect <source>
aw blueprint materialize <source> --profile <profile> --target <dir>
aw team create <team> [--agent [NAME@]BLUEPRINT/PROFILE[:scope][=<runtime>]]...
aw team add <name>@<blueprint>/<profile>=<runtime> [--home <dir>]
aw agent profile show <name>
```

`inspect` prints:

- profiles and default agents;
- runtime hints;
- apps requested;
- capability requests;
- event subscriptions;
- approval policy;
- code artifacts;
- files that would be written;
- commands that would be run;
- required human decisions.

`team create` / `team add` with profile selectors must:

- validate the blueprint/profile source fetched through the public catalog or a local source;
- materialize a pinned profile payload into the agent home without requiring the private shelf;
- keep the shelf import/bind/update loop as an explicit Library plugin path;
- write no `.aw` keys/certs/tokens into committed profile resources;
- create or update a reviewable local layout;
- record blueprint source/version/digest and selected runtime;
- show app/capability/subscription requests as setup hints, not grants;
- stop before any app action that needs human approval;
- be idempotent enough that a failed run can be resumed or inspected.

The shipped vocabulary is `aw team create` plus `aw team add NAME@BLUEPRINT/PROFILE`;
there is no separate `aw blueprint apply` or `aw agent add` alias in the launch path.

### Profile commands

```bash
aw profile list
aw profile show <profile>
aw profile diff <profile> --from <source>
aw profile propose-change <profile> --body-file <proposal.md>
```

`profile show` must be useful to agents as well as humans: it should answer
"what am I for?", "what work do I accept?", "what apps/scopes do I need?", "what
events wake me?", and "what requires approval?"

### Library commands

The company learning loop needs explicit CLI/MCP affordances. These commands
target `library.aweb.ai`, not core.

```bash
aw library list
aw library search <query>
aw library show <entry>
aw library diff <entry>@<old> <entry>@<new>
aw library propose memory --title <title> --body-file <file>
aw library promote <team-change-id> --to company
aw library update-team <team> --entry <entry>@<version>
```

Agents may read and propose through these commands. Direct mutation of company
library entries requires explicit human/coordinator authority.

Profile and skill change proposals are later commands. V1 should not require
automatic patch application to blueprints:

```bash
aw library propose skill-change <skill> --patch-file <patch>
aw library propose profile-change <profile> --patch-file <patch>
```

### Agent commands

```bash
aw team add <name>@<blueprint>/<profile> --runtime <runtime> [--home <dir>]
aw agent profile show <name>
```

Adding an agent must be trivial. The setup UX:

```bash
aw team add reviewer@aweb.team/reviewer=claude-code
cd agents/instances/reviewer
claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace

aw team add agent-resources@aweb.team/agent-resources=pi
cd agents/instances/agent-resources
pi --approve
```

For local runtimes, the shipped `aw team add NAME@BLUEPRINT/PROFILE` path:

- creates/admit the agent identity into the team;
- creates the instance home under `agents/instances/<name>` unless `--home` is used;
- materializes profile resources and `.aw/profile/` provenance directly from the public catalog or local source;
- installs or verifies the team certificate;
- connects the instance/workspace with aweb when needed;
- writes harness adapter docs/config;
- leaves runtime launch to `aw team up` or a manual start from the selected home.

For hosted MCP runtimes, the dashboard/Team Builder flow should create or select
the hosted custodial identity, bind it to the profile and effective app grants,
and print the connection instructions for the external client.

Existing `spawn-instance` and `retire-instance` skills remain useful as
documentation and compatibility while CLI support lands, but they should not be
the product happy path.

### Runtime handoff

Runtime launch is an operator action for interactive local harnesses. The CLI
materializes the home, records profile provenance, and writes harness-specific
entry files; the operator starts Claude Code, Codex, Pi, or another harness from
that home using the command printed by setup docs or profile guidance.

The product requirement is that the human does not need to remember the right
directory, symlinks, env vars, or startup command after materialization.

`aw team up` is the shipped local convenience for this handoff. It reads the
materialized `agents/instances/*` roster, builds a tmux plan, and starts one
window per supported interactive harness. It is not the team definition or a
hosted runtime service; it only launches already-materialized local homes.

Current behavior:

- with no explicit session, a caller already inside tmux launches into that
  exact caller session and socket context; outside tmux, the launcher retains
  the active-team-derived session default (falling back to `aw-team`);
- supported launch runtimes: `claude-code` and `pi`;
- unsupported-by-launch but valid materialization runtimes: `codex` and
  `local-shell`;
- idempotent reconcile skips an agent home when a running process already has
  that home as its current working directory;
- `--force` bypasses that active-home skip;
- `--recreate` kills and recreates the tmux session;
- preflight installs/verifies the Claude `aweb-channel` plugin or Pi extension
  before starting windows;
- Claude starts with `claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace`;
- `aw team up` auto-answers the known Claude trust-folder and development-channel prompts;
- Pi starts as `pi --approve`, which trusts the project-local files so Pi does
  not show its trust-folder prompt.

This is deliberately operational. If a company cannot quickly add one more
agent and start it in the right home, the blueprint model will feel theoretical.

Implementation anchors for the shipped claims above:

- public materialization defaults: `cli/go/cmd/aw/library_profile.go:21`, `cli/go/cmd/aw/library_profile.go:23`, `cli/go/cmd/aw/library_profile.go:24`, `cli/go/cmd/aw/library_profile.go:25`, `cli/go/cmd/aw/library_profile.go:424`, `cli/go/cmd/aw/library_profile.go:434`;
- public catalog GET and local materialization path: `cli/go/cmd/aw/library_profile.go:466`, `cli/go/cmd/aw/library_profile.go:471`, `cli/go/cmd/aw/team_human.go:1204`;
- shelf/plugin path is separate: `cli/go/cmd/aw/library_profile.go:265`, `cli/go/cmd/aw/library_profile.go:612`; regression coverage asserts public team materialization does not import to shelf or call `/v1/materialize` at `cli/go/cmd/aw/local_surface_e2e_test.go:422` and `cli/go/cmd/aw/local_surface_e2e_test.go:426`;
- `aw team add` agent spec, local/global scope, runtime/catalog flags, and `agents/instances` root: `cli/go/cmd/aw/team_human.go:74`, `cli/go/cmd/aw/team_human.go:161`, `cli/go/cmd/aw/team_human.go:162`, `cli/go/cmd/aw/team_human.go:165`, `cli/go/cmd/aw/team_human.go:166`, `cli/go/cmd/aw/team_human.go:167`, `cli/go/cmd/aw/team_human.go:1089`;
- materialization runtimes: `cli/go/cmd/aw/library_profile.go:597`;
- `aw team up` launch scope, commands, active-home skip, preflight, and Claude prompt handling: `cli/go/cmd/aw/team_up.go:30`, `cli/go/cmd/aw/team_up.go:175`, `cli/go/cmd/aw/team_up.go:209`, `cli/go/cmd/aw/team_up.go:222`, `cli/go/cmd/aw/team_up.go:420`, `cli/go/cmd/aw/team_up.go:463`;
- channel installers: `cli/go/cmd/aw/channel_setup.go:14`, `cli/go/cmd/aw/channel_setup.go:17`, `cli/go/cmd/aw/channel_setup.go:41`, `cli/go/cmd/aw/channel_setup.go:63`.

### App/capability commands

```bash
aw app list
aw app install <app>
aw app grant <app> --scope <scope>
aw app grants
aw subscription list
aw subscription approve <request>
```

These commands must reinforce the authority model: teams grant apps; profiles
request; agents receive the intersection.

## 9. Dashboard surface

The dashboard is the human workroom and control surface. For blueprints and
profiles it should show:

- which blueprint created the team;
- installed profile versions and local modifications;
- agents and their runtime bindings;
- requested vs granted app capabilities;
- event subscriptions;
- approval policies;
- active work;
- agent activity;
- cost/usage;
- signed audit trail;
- available upstream blueprint/profile updates.

For `library.aweb.ai`, it should show:

- memory proposals in v1;
- later: profiles, skills, playbooks, policies, app recipes, evals, glossary;
- proposed changes;
- source team/task/agent for each proposal;
- diff and impact analysis;
- which teams use each entry/version;
- approve to team only / promote to library / reject;
- updates available for teams;
- rollback history.

The dashboard should not start as the primary profile authoring tool. It can
show diffs, approve changes, and later edit hosted profile stores. The first
product path for dev teams should be repo/git/CLI because that matches how the
target customers already review operational code. For non-technical users,
hosted library editing is allowed, but it must still be versioned and reviewed.

## 10. Agent-first UX

Agents need a simple operating contract:

```bash
aw whoami
aw agent profile show
aw library search "pricing tone"
aw library show company/style-guide
aw app list
aw work ready
aw work claim <ref>
aw mail send ...
aw chat send-and-wait ...
aw memory read
aw profile propose-change
aw library propose memory --title "Preferred KPI definitions" --body-file kpis.md
```

The exact commands may differ, but the questions must be answerable:

- Who am I?
- Which team am I in?
- What profile am I running?
- What work can I accept?
- What apps and scopes do I have?
- What events wake me?
- What needs human approval?
- Who do I ask when blocked?
- What should I record when I learn something durable?
- What company knowledge or policy should I reuse?
- How do I propose that the company remember what I learned?

The same team state should power human and agent surfaces:

- humans see workroom, approvals, activity, costs, and audit;
- agents see tools, tasks, instructions, memory, subscriptions, and events.

## 11. Learning and improvement

Do not sell "self-improving agents" as magic. The concrete loop is:

1. An agent completes work.
2. The agent writes a short retrospective when useful.
3. The agent proposes a profile/skill/memory/workflow improvement.
4. A human or coordinator reviews the change.
5. The change lands in the team install, `library.aweb.ai`, or both.
6. Future agents use updated pinned versions after approval.
7. The dashboard can later show whether metrics improved.

Profiles may evolve, but not silently. The rule:

> Agents can propose changes to their operating package. Humans or authorized
> coordinators approve them.

For code agents, these are ordinary git diffs. For hosted profile stores, they
are reviewed versioned changes with rollback.

`library.aweb.ai` is what makes this company-level learning instead of
team-local drift. It should consume core authority and app-install primitives;
it should not become a second core control plane.

## 12. Runtime model

### Local dev runtime

The first wedge uses materialized local homes plus runtime handoff:

- Claude Code sessions launched in instance directories, with the aweb-channel plugin;
- Pi sessions launched in instance directories, with the Pi aweb extension;
- Codex and local-shell homes materialized for manual launch and polling;
- channel/event subscription for wakeups where the selected harness supports it;
- `aw team up` as the operator-managed tmux launcher for supported interactive harnesses.

Do not expose "tmux team" as the product. The product is an AI team; tmux is
only an optional local terminal/session tool.

### Hosted MCP runtime

For ChatGPT, Claude.ai, Copilot, and similar clients, aweb creates or selects a
hosted custodial identity and exposes the allowed app tools through MCP.

The same profile/capability model applies:

- team grants apps;
- profile requests capabilities;
- connector grant binds external runtime to a custodial identity;
- gateway exposes the effective tool surface.

### Future hosted runners

Aweb-hosted agents are valuable but should not block v1. They add compute,
sandboxing, runtime billing, secrets isolation, and fleet operations. The
blueprint/profile model should support them later without making them required
for early customer value.

## 13. Distribution and community

People should be able to publish blueprints and profiles in git repos.

Distribution levels:

1. **Aweb built-ins**: high-quality first-party blueprints/profiles.
2. **Library app**: private canonical profiles, skills, playbooks, memory,
   policies, app recipes, and evals, exposed by `library.aweb.ai`.
3. **Team installs**: pinned working copies used by a specific team/repo.
4. **Community**: public repos discoverable through aweb.
5. **Vendor**: app-specific profiles maintained by app providers.

Install must be security-aware:

- show source and version;
- show digest;
- show code artifacts;
- show required apps and scopes;
- show event subscription requests;
- show approval policy;
- pin installed version;
- support diff/update/rollback.

Contributed profiles are not automatically trusted. Treat them like code and
dependencies.

## 14. Suggested first wedge

Build the first polished path around engineering teams:

> Run an AI dev team without losing control.

V1 blueprint:

- coordinator profile;
- developer profile;
- reviewer profile;
- messages app;
- tasks app;
- GitHub/dev app integration where available;
- signed audit log;
- secret-mediated execution through `aw do` or app-native secret use;
- local Claude Code/Pi runtime launch, with Codex/local-shell materialization available for manual operation;
- optional hosted MCP coordinator or assistant;
- human workroom with activity, approvals, and status.

The customer flow:

1. Point aweb at a repo or blueprint source.
2. Inspect proposed team and required app capabilities.
3. Apply blueprint.
4. Connect GitHub/tasks/messages.
5. Start coordinator/developer/reviewer.
6. Assign a real code task.
7. Watch work, approve sensitive actions, review output, inspect audit trail.

This should work before marketplace/profile hosting is built.

Wedge v1 has zero dependency on the private Library shelf. It can read public
profile payloads from a provider-agnostic Library catalog URL or from local
blueprint sources, materializes a pinned local snapshot, grants apps through
existing app-grant rails, and hands operators clear `aw team up` or manual
runtime launch guidance. The Library shelf app adds company-level learning later;
it is not required for initial team creation.

The quality bar for first-party blueprints is product-level, not sample-code
level. A blueprint must be something a company can actually start from: clear
profiles, useful defaults, realistic app requests, runtime hints, reviewable
code artifacts, and enough workflow shape that the first task can start quickly.

## 15. Migration from today's blueprints

Near-term migration:

1. Rename external concept from soul to profile while keeping directory
   compatibility.
2. Add `blueprint.yaml` to `../aweb-team-dev-simple/`.
3. Add `profile.yaml` to each existing soul/profile directory.
4. Add `required_apps`, `subscriptions`, and `artifacts` fields where useful.
5. Add `aw blueprint inspect` for local dirs first.
6. Add `aw team create` / `aw team add NAME@BLUEPRINT/PROFILE` that materialize a pinned local snapshot and show a plan.
7. Keep existing `spawn-instance`/`retire-instance` skills as compatibility
   documentation while CLI commands mature.
8. Add dashboard read-only visualization of installed blueprint/profile state.
9. Add remote git source support.
10. Specify `library.aweb.ai` as an app that reuses app installs/grants and
   pinned digests. Do not add a new core library layer.
11. Build the smallest library-app v1 only when product priority justifies it:
   memory entries, proposal blobs, diff/show/promote, team pin/update. This can
   follow the first app-extraction milestone unless a concrete hosted
   non-technical customer need pulls it forward.
12. Add profile/skill/playbook/policy promotion only after the memory loop
   proves value.
13. Add hosted catalog/search only after the local/git path and library-app
   learning loop prove value.

Do not build a hosted mutable profile editor first. That path recreates roles.

## 16. Open decisions

- Exact on-disk names: `profiles/` now, or keep `souls/` internally until a
  compatibility migration?
- First blueprint source syntax: GitHub shorthand, full URL, local dir, or all
  three?
- How much local-dir materialization is needed beyond `aw blueprint inspect` and
  the public-catalog `aw team create` / `aw team add` launch path?
- Which app is first for external capabilities: GitHub, Tasks, Messages, or Dev?
- What is the minimal signed audit trail in v1?
- How hosted MCP profile binding appears in the dashboard.
- Whether `library.aweb.ai` should build before or after the first extracted
  anapp proves the extraction template.
- Whether the first library backend is hosted-only, git-backed, or both.
- Whether the v1 library entry type is memory only, or memory plus profiles.
- How team-local changes are represented so they can be promoted cleanly to the
  library app.
- Whether community catalog lives in a repo first or in hosted aweb.ai.

The default answers are: keep compatibility with current soul layout, support
local dir where useful, make `aw blueprint inspect` the read-only primitive and
use `aw team create` / `aw team add NAME@BLUEPRINT/PROFILE` for the launch setup
path, prove with the `aweb.team` seed blueprint, prioritize native `aw` team
creation and `aw team up`/direct harness launch guidance, specify the private
`library.aweb.ai` shelf as an app rather than a core layer, and prove the
learning loop with memory before broadening it.
