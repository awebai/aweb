---
title: "Team blueprints"
kicker: "Product SOT"
description: "What a team blueprint is, why it replaces bootstrap-era templates and operating-pattern vocabulary, and what every blueprint must contain."
weight: 26
---

# Team blueprints

This document is the source of truth for **team blueprints**: the product
motion that replaces bootstrap-era template repos and the interim
"team operating pattern" vocabulary.

It defines the user flow, the vocabulary, the target repo layout a blueprint
produces, and the contract for what a blueprint must contain. The
[setup-surface taxonomy](cli-setup-surface-sot.md) and the
[resource-pack contract](resource-pack-template-contract.md) remain the SOTs
for command classification and the manifest layer; this document sits above
them and defines the product story they serve.

## What the user does

> A human owns a repo and wants a team working in it. They point their agent
> at a **blueprint** — a repo containing souls, roles, skills, playbooks, and
> instructions. The agent clones the blueprint somewhere disposable, follows
> its `create-team` skill, copies the identity-free resources into the
> human's repo, commits them, connects the first instance with explicit aweb
> primitives, and publishes the shared team context. From then on the team
> grows itself: existing instances spawn new ones with the `spawn-instance`
> skill, and every agent grows its own soul with `self-maintenance`.

The human then runs the team: `cd agents/instances/<name>` and launch the
harness. The agent that created the team has no role in the finished team.

There is no monolithic bootstrap command. If a convenience command ever
exists, it may only clone a blueprint to a local directory — something the
agent can already do with `git clone`.

## Why

Two forces drove this design.

**The bootstrap monolith failed a real customer.** `aw agents bootstrap`
combined template reading, team creation, identity minting, role/instruction
publication, filesystem mutation, gitignore edits, and worktree creation in
one command. A non-TTY run created `agents/` before hosted setup completed;
retry refused the existing `agents/`; provision could not create the missing
hosted team. The customer was stranded (see their write-up in
`a2am/docs/aweb-setup-feedback.md`). Rollback fixes landed, but the deeper
fix is the abstraction: identity/team/service mutation must stay separate
from filesystem/template/git mutation, and each step must be explicit.

**The same customer then built the model we want.** Their repo (`a2am`)
defines the team as committed, identity-free **souls** and runs it as
gitignored **instances**, each minted explicitly with aweb primitives. Souls
are living state — they accumulate `docs/`, `decisions/`, `memory/`, and
skills as the team works — so they belong in the team's own repo, versioned
and reviewed. That is why a blueprint is a **seed, not a dependency**: its
resources are copied in, committed, and owned by the team from day one.
There is no upstream to sync; the copies fork and grow.

## Vocabulary

- **Blueprint** — a repo packaging souls, roles, skills, playbooks,
  instructions, and adapters that an agent uses to create a team. Replaces
  "template repo", "pattern repo", and "team operating pattern" in all
  happy-path copy.
- **Create a team (from a blueprint)** — the activity. The blueprint's skill
  is named `create-team`. Do not call this "bootstrapping" in product copy:
  `aw agents bootstrap` is the obsolete/legacy command, and one word cannot
  name both the deprecated path and its replacement.
- **Soul** — the committed, identity-free canonical body of an agent:
  `AGENTS.md`, `soul.yaml`, its own skills, and accumulated
  `docs/`/`decisions/`/`memory/`. One soul can back many instances.
- **Instance** — a runnable copy of a soul with its own aweb identity. Its
  directory is its **home** (`.aw`, body symlinked to the soul) plus a
  `work` location (the main checkout or its own git worktree). Instances are
  gitignored and machine-local.
- **Spawn an instance** — minting one instance from a soul
  (`spawn-instance` skill).
- **Resource pack** — the low-level manifest layer (`resource-pack.yaml`)
  that declares what a blueprint contains. A blueprint *is* a resource pack
  plus the knowledge needed to apply and understand it.
- **Community blueprints** — externally contributed blueprints.
- **Template** — legacy/compatibility vocabulary only, for the bootstrap-era
  repos and `aw agents` surfaces.

`aw team create` (network-team creation) and creating a team from a
blueprint are different layers: the first creates the hosted/BYOT team
object; the second creates the working team in the repo and uses the first
(or the dashboard) for authority.

## Target layout

A blueprint's `create-team` skill produces this shape in the human's repo:

```text
agents/
  souls/<role>/          committed canonical bodies
    soul.yaml            role, work (main | worktree | home), runtime hint
    AGENTS.md            the operating doc; never edited by the agent itself
    docs/ decisions/ memory/   accumulated knowledge (living)
    .agents/skills/      soul-specific skills, if any
  roles/<role>.md        published with `aw roles add`
  instructions.md        published with `aw instructions set`
  docs/                  team architecture doc and other shared team docs
  instances/<name>/      gitignored homes: .aw identity, body -> soul, work
.agents/
  skills/                repo-level shared skills (spawn-instance, self-maintenance)
  bin/                   shared helpers (e.g. launch-session.sh)
.claude/skills -> ../.agents/skills    (harness adapter; per-harness)
.gitignore               contains /agents/instances/
```

Notes:

- `agents/instances/<name>/` is keyed by instance alias, not role, because
  one soul backs many concurrent instances (`developer-authflow`,
  `reviewer-<sha>`). Alias convention: bare role for standing singletons,
  `<role>-<purpose>` for work-specific instances.
- An instance's `work` is declared by its soul: `main` (symlink to the main
  checkout) for coordination agents, `worktree` (own git worktree and
  branch) for code agents. Never move or rename an instance home after
  `aw init`; the service registers the workspace at its path.

## Lifecycle

**Create.** The creating agent (the human's assistant, transient, never a
team member) clones the blueprint, copies resources into the target repo,
commits, creates `agents/instances/<first>` (usually the coordinator), and
has the human connect it with the dashboard-generated
`AWEB_API_KEY=... AWEB_URL=... aw init ...` (or explicit team primitives
where the installed CLI supports them). From that connected instance it
publishes `aw instructions set` and `aw roles add` per role, then hands the
human the launch command for the first instance and stops.

**Grow.** Existing instances mint new ones: `aw id team invite` from the
spawner's home, `aw id team accept-invite` + `aw init` in the new home,
symlink the body to the soul, add a worktree if the soul says so. Spawning
is constrained: only on explicit human request or a documented workflow
step.

**Maintain.** Agents grow their souls (docs/decisions/memory/skills) via
`self-maintenance`, but never edit their own `AGENTS.md` or role; soul
changes are commits reviewed like any other change.

**Retire.** The instance closes its session; the spawner runs
`aw workspace delete` and removes the home/worktree/branch.

## What a blueprint must contain

A blueprint must carry everything an agent needs to **create** the team and
everything the resulting team needs to **understand itself**:

- root `AGENTS.md` addressed to the applying agent: this repo is a
  blueprint, read the manifest, follow `skills/create-team`;
- `resource-pack.yaml` manifest (see the
  [resource-pack contract](resource-pack-template-contract.md));
- `skills/create-team/SKILL.md` — the application procedure;
- `skills/spawn-instance/SKILL.md` and `skills/self-maintenance/SKILL.md` —
  copied into the target as repo-level skills;
- `resources/souls/<role>/` — soul.yaml + AGENTS.md (+ seed docs/decisions/
  memory directories);
- `resources/roles/<role>.md` and `resources/instructions.md`;
- a team architecture doc (copied into the target's `agents/docs/`) that
  explains the souls/instances model, who spawns whom, the naming
  convention, and how work flows — so the finished team and its humans can
  understand the system they are running;
- adapter notes per harness (Claude Code, Codex, Pi, ...);
- a README for the human browsing GitHub.

A blueprint must **not** contain `.aw` state, DIDs, certificates, aliases,
invite tokens, private keys, generated worktrees, or canonical
harness-specific files (a committed final `CLAUDE.md`). Harness wiring is
done by adapters/symlinks at create/spawn time.

## Boundaries that must hold

- Pattern application (copying resources) never creates identities, accepts
  invites, mutates `.aw`, or creates worktrees. Those are separate explicit
  steps.
- Identity/team/service mutation uses aweb primitives the human can see;
  filesystem/git mutation uses git and the shell.
- Public copy must not teach unreleased CLI verbs; the released-safe
  connection step is the dashboard-generated `aw init`.
- The hosted happy path never requires namespace/controller/certificate
  vocabulary; BYOT remains explicit protocol/admin.

## Current blueprints

- `awebai/aweb-team-coord-worktrees` — coordinator + developer + reviewer.
- `awebai/aweb-team-company-surfaces` — company-surface roles.

Both are being converted from the interim "operating pattern" shape to the
blueprint shape defined here. The richer maintainer/vision team structure
proven in `a2am` is a candidate for a future blueprint.

## Rollout

1. This SOT.
2. Convert both blueprint repos: `create-team` skill (renamed from
   `bootstrapping-a-team`), a2am target layout, spawn/retire model,
   architecture doc.
3. Update aweb docs/skills vocabulary (blueprint; pattern/template only as
   legacy references).
4. AC public copy guides humans and agents to blueprints (`/orchestration`
   first, then the rest of the site with Olivia's lane).
5. Community blueprints come later, on the same contract.
