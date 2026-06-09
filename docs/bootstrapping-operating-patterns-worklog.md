---
title: "Bootstrapping and team operating patterns worklog"
kicker: "Handoff"
description: "Durable handoff for the setup-surface, primitive-first bootstrapping, and team operating pattern work."
weight: 99
---

# Bootstrapping and team operating patterns worklog

_Last updated: 2026-06-09 by rose._

This is a restart handoff for the recent redesign of aweb team setup. It records
what changed, what vocabulary is now canonical, which repos were touched, and
what is still in flight.

## North star

The product motion is no longer “apply a template” or “run one bootstrap
command.”

The intended user flow is:

> A human owns a repo or directory and wants a team patterned after one of our
> samples. They point their agent at a **pattern repo**. The agent reads that
> repo’s `AGENTS.md`, `resource-pack.yaml`, `skills/bootstrapping-a-team`, souls,
> roles, playbooks, and adapters. The agent then uses explicit aweb primitives
> and explicit filesystem/git steps to set up concrete teammates in the human’s
> target repo.

Key boundary:

- Pattern repos teach agents how to bootstrap teams.
- Pattern repos do not contain `.aw`, DIDs, certs, aliases, private keys,
  generated identities, generated worktrees, or final harness files.
- Concrete instances are created later and explicitly.
- Identity/team/service mutation must stay separate from filesystem/template/git
  worktree mutation.

## Vocabulary

Locked with Olivia on 2026-06-09:

- Product/category: **team operating patterns**
- GitHub/sample repos: **pattern repos**
- Future external submissions: **community operating patterns**
- Low-level manifest/package concept: **resource pack**
- Avoid: **template** as public happy-path terminology
- Use “template” only for obsolete/legacy compatibility or historical context.

Avoid “advanced” as a bucket. Preferred buckets remain:

1. everyday human intents;
2. agent primitives;
3. protocol/admin primitives;
4. obsolete/legacy compatibility.

## aweb CLI/setup-surface work already landed on `rose`

Current repo/worktree:

```text
/Users/juanre/prj/awebai/aweb-rose
branch: rose
latest pushed HEAD as of this handoff: 034a0c11
```

Important commits on `rose`:

- `af17c368` — setup-surface source of truth
- `d94d542d` — SOT review adjustment
- `e88bf837` — CLI legacy/protocol grouping
- `c08b7d19` — initial `aw team` / `aw workspace connect`
- `a8661c9c` — skills update
- `6691f0e5` — resource-pack contract
- `dc31fb12` — bootstrap trigger alignment
- `21f98217` — `aw check` + bootstrap rollback
- `9cda3d61` — setup surface release gate
- `a220f11a` — docs stop teaching bootstrap happy path
- `2d9e22ee` — complete human team lifecycle verbs
- `3ec2d191` — successor resource packs inside aweb repo
- `45d0bc24` — merge `origin/main` into `rose`
- `c3986736` — full bootstrap git-side-effect rollback
- `d7c3e534` — `aw roles add`
- `75f8cd51` — novice resource-pack skill/gate polish
- `b6a5a367` — exploratory operating-pattern docs in aweb repo
- `034a0c11` — revert of `b6a5a367`

Important: the exploratory aweb commit `b6a5a367` was reverted because Juan
clarified that team operating patterns belong in the standalone pattern repos,
not primarily in the aweb repo or AC dashboard copy. Do not reintroduce that
exact approach without explicit direction.

### CLI/interface changes on `rose`

Already implemented in source, but not yet necessarily released to npm:

- `aw team create`
- `aw team invite`
- `aw team join <invite-token>`
- `aw team list`
- `aw team switch <team_id>`
- `aw team leave <team_id>`
- `aw team remove-agent <member-address>`
- `aw workspace connect`
- `aw check` aliasing/supporting `aw doctor`
- `aw roles add <role-name> --title <title> --playbook-file <path>`
- `aw roles show <role-name>` positional support

`aw agents bootstrap`, `aw agents provision`, and `aw workspace add-worktree`
remain callable but are now obsolete/legacy compatibility surfaces rather than
the product center.

### Released CLI constraint

Public copy must not teach unreleased commands yet.

Observed npm `@awebai/aw` 1.26.8/1.26.9 does **not** include:

- `aw team ...`
- `aw workspace connect`
- `aw check`
- `aw roles add`

Released-safe public flow for now:

```bash
npm install -g @awebai/aw
# dashboard-generated:
AWEB_API_KEY=... AWEB_URL=... aw init ...
```

After a CLI release includes the source-only verbs, public docs can promote the
new explicit primitives.

## Bootstrap/provision catch-22 fix

The customer bug that motivated much of this:

- non-TTY/interrupted `aw agents bootstrap` created `agents/`/worktrees before
  hosted setup completed;
- retry refused existing `agents/`;
- provision could not create the missing hosted team;
- user was stranded in partial state.

Fixes landed on `rose`:

- `wrapInRepoBootstrapFailureWithRollback`
- `rollbackInRepoBootstrapLayoutIfIdentityFree`
- `rollbackInRepoBootstrapWorktrees`
- `restoreInRepoBootstrapGitignore`

Rollback now restores `.gitignore`, removes generated `agents/`, generated
worktrees, and branches created by a failed run, while preserving layouts that
contain `.aw` key state.

Athena reviewed through `c3986736` and had no remaining blocker.

## a2am customer example and resulting insight

The customer repo `../a2am` showed the durable “souls vs instances” model:

```text
souls/<role>/
  soul.yaml
  AGENTS.md
  docs/
  decisions/
  memory/
```

Example `soul.yaml`:

```yaml
role: developer
work: worktree
runtime: claude
```

The key product insight from Juan:

> Choose a team operating pattern. It gives you souls, roles, skills, and
> playbooks. Then explicitly create instances when you need them.

This is now the conceptual center for replacing old template repos.

## Pattern repos updated

### `aweb-team-coord-worktrees`

Repo:

```text
/Users/juanre/prj/awebai/aweb-team-coord-worktrees
branch: main
latest pushed: e308d0e
```

Relevant commits:

- `3e8671c` — Replace bootstrap template with operating pattern pack
- `a48cd61` — Make operating pattern first run noob-safe
- `c91da77` — Make pattern repo agent-applicable
- `e308d0e` — Rename apply skill to bootstrapping a team

Current shape:

```text
AGENTS.md
resource-pack.yaml
resources/
  instructions.md
  roles/{coordinator,developer,reviewer}.md
  souls/{coordinator,developer,reviewer}/
    soul.yaml
    AGENTS.md
    docs/
    decisions/
    memory/
skills/
  bootstrapping-a-team/SKILL.md
  spawn-instance/SKILL.md
  self-maintenance/SKILL.md
examples/
  deploy.md
  create-instance.md
adapters/{claude,codex,pi}/README.md
scripts/
  install-local.sh
  build-roles-bundle.py
```

The root `AGENTS.md` tells an applying agent that this is a source pattern, not
the target team. It instructs the agent to read the manifest and load
`skills/bootstrapping-a-team/SKILL.md`.

The `bootstrapping-a-team` skill teaches the applying agent to:

1. confirm target repo/directory, team source, harnesses, and instance policy;
2. inspect `resource-pack.yaml`, souls, roles, instructions, and adapters;
3. copy only identity-free resources into the target repo;
4. keep concrete instances local, usually via `.git/info/exclude` `/instances/`;
5. create `instances/coordinator` explicitly first;
6. connect with dashboard-generated `AWEB_API_KEY=... AWEB_URL=... aw init ...`
   or explicit primitives when available;
7. publish instructions and roles;
8. create developer/reviewer worktree instances only when needed.

### `aweb-team-company-surfaces`

Repo:

```text
/Users/juanre/prj/awebai/aweb-team-company-surfaces
branch: main
latest pushed: cccc823
```

Relevant commits:

- `df499e2` — Replace bootstrap template with operating pattern pack
- `cccc823` — Make company pattern agent-applicable

Current shape mirrors `coord-worktrees`, with company-surface souls:

```text
AGENTS.md
resource-pack.yaml
resources/
  instructions.md
  roles/{direction,engineering,operations,support,outreach,analytics,developer}.md
  souls/{direction,engineering,operations,support,outreach,analytics,developer}/
    soul.yaml
    AGENTS.md
    docs/
    decisions/
    memory/
skills/
  bootstrapping-a-team/SKILL.md
  spawn-instance/SKILL.md
  self-maintenance/SKILL.md
examples/
  deploy.md
  create-instance.md
adapters/{claude,codex,pi}/README.md
scripts/
  install-local.sh
  build-roles-bundle.py
```

This was brought to parity because AC `/orchestration` references both sample
pattern repos.

## AC/site work

Repo:

```text
/Users/juanre/prj/awebai/ac
branch: main
latest pushed from rose: 33ff3e42
```

Commit:

- `33ff3e42` — `site: recenter orchestration on operating patterns`

Touched only:

```text
site/content/orchestration.md
site/layouts/_default/orchestration.html
```

What changed on `/orchestration`:

- removed user-facing `aw agents bootstrap` from that page;
- removed `template`, `template repo`, `team.yaml`, `agents/home`,
  one-command bootstrap happy path from that page;
- added “Tell your agent” prompt-as-command pattern;
- centered **team operating patterns**, **pattern repos**, `AGENTS.md`,
  `resource-pack.yaml`, `skills/bootstrapping-a-team`, souls, roles, playbooks;
- kept released-safe by avoiding unreleased shell commands;
- described dashboard-generated `aw init` as the connection step.

Gate run:

```bash
cd ../ac/site && hugo --minify
```

Grep gate run against touched files for stale terms:

```bash
rg -n "aw agents bootstrap|team template|template repo|team.yaml|agents/home|Bootstrap docs|claim-human|one command" \
  site/layouts/_default/orchestration.html site/content/orchestration.md
```

No matches after patch.

## Coordination with Olivia

Olivia is working in:

```text
/Users/juanre/prj/awebai/ac-olivia
```

Conversation summary:

- Rose asked Olivia about AC `/orchestration` and vocabulary.
- Olivia said she was not actively patching yet and recommended Rose patch
  `/orchestration` directly because Rose had the canonical pattern-repo framing.
- Rose acquired lock `ac:site/layouts/_default/orchestration.html`, patched,
  pushed `33ff3e42`, then released the lock.
- Olivia ACKed `33ff3e42` and locked vocabulary:
  **team operating patterns / pattern repo / community operating patterns**.

Olivia’s lane:

- home hero;
- `/mcp` orchestration teaser;
- `/docs/team-bootstrap` legacy framing;
- `index.llms.txt` and `mcp.llms.txt` mirrors.

Olivia is waiting on Juan for three structure questions before starting her lane
and will ping for sequencing before any Hestia handoff.

Important: there is still old bootstrap/template copy elsewhere in AC outside
`/orchestration`, especially:

- `site/layouts/index.html`
- `site/layouts/index.llms.txt`
- `site/layouts/_default/mcp.html`
- `site/layouts/_default/mcp.llms.txt`
- `site/content/docs/team-bootstrap.md`
- `site/static/docs/team-bootstrap.md`
- some docs with bootstrap as API-key init wording

Do not assume AC is fully aligned until Olivia’s lane lands.

## Hestia/deploy context

Earlier Hestia deploy was put on hold because AC hero commit `27f43d4c` centered
`aw agents bootstrap`.

Current deploy posture:

- `/orchestration` patch is pushed to AC `main`.
- Olivia still needs to patch other public surfaces.
- Coordinate with Olivia before any Hestia deploy handoff.
- Do not ask Hestia to deploy public copy that still teaches unreleased commands
  or old bootstrap happy paths.

## Naming decision for future contributors

When describing external contributions, say:

> community operating patterns

The repo object can be called:

> pattern repo

A pattern repo should teach agents via:

- root `AGENTS.md`;
- `resource-pack.yaml` manifest;
- `skills/bootstrapping-a-team/SKILL.md`;
- reusable `skills/*` for target agents;
- `resources/souls/*` with `soul.yaml` + `AGENTS.md`;
- `resources/roles/*.md`;
- `resources/instructions.md`;
- examples/adapters.

## Things to avoid next session

- Do not re-center public copy on `aw agents bootstrap`.
- Do not call new pattern repos “templates” in happy-path copy.
- Do not teach unreleased commands on public AC/site pages until the CLI release
  ships.
- Do not hide git worktree creation behind pattern application.
- Do not allow pattern repos to contain `.aw`, identities, DIDs, certs, aliases,
  invite tokens, private keys, generated work symlinks, or canonical
  harness-specific files like committed final `CLAUDE.md`.
- Do not mutate AC while Olivia is patching the same surfaces without locking and
  coordinating.

## Useful commands

Check current aweb coordination:

```bash
aw workspace status
aw work ready
aw mail inbox
aw chat pending
```

Check AC stale setup copy broadly:

```bash
rg -n "aw agents bootstrap|template repo|team.yaml|agents/home|agents/worktrees|workspace add-worktree" ../ac/site
```

Validate AC site after copy changes:

```bash
cd ../ac/site && hugo --minify
```

Validate pattern repo install helper shape:

```bash
tmp=$(mktemp -d)
mkdir -p "$tmp/project"
./scripts/install-local.sh "$tmp/project"
find "$tmp/project" -path '*/.aw*' -print
```

Validate aweb setup-surface gates:

```bash
git diff --check
scripts/check-resource-packs.sh
scripts/regenerate-cli-reference.sh --check
scripts/check-setup-surface.sh
cd cli/go && go test ./cmd/aw
```

## Current repo statuses at handoff

As of the handoff immediately before writing this doc:

```text
aweb-rose:                 branch rose, HEAD 034a0c11, clean before this doc
aweb-team-coord-worktrees: branch main, HEAD e308d0e, pushed/clean
aweb-team-company-surfaces:branch main, HEAD cccc823, pushed/clean
ac:                        branch main, HEAD 33ff3e42, pushed/clean
```

This doc itself is added after that status and should be committed/pushed on
`aweb-rose` if we want it durable across restarts.
