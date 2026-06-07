# Superseded In-Repo Bootstrap Layout Contract

This document is retained as historical design context for the earlier
in-repo bootstrap work. The current `aw agents` lifecycle contract is
[`agents-layout-lifecycle-contract.md`](agents-layout-lifecycle-contract.md),
and that document is authoritative for current implementation and user-facing
guidance.

This document is the normative contract for the in-repository `agents/`
bootstrap convention. It is subordinate to the team and identity authority
model in `aweb-sot.md`, `awid-sot.md`, and `product-authority-sot.md`.

The goal is to make the customer work repo the center of gravity:

```bash
cd my-project
aw agents bootstrap gh:awebai/aweb-team-coord-worktrees --username juan --identity-prefix juan
cd agents/home/coordinator
codex
```

The current template-checkout bootstrap behavior remains supported as legacy
compatibility. The in-repo layout is additive; it must not be implemented by
mutating the legacy path into a partially new shape.

## Terms

- **Customer repo**: the git worktree containing the project the agents will
  work on.
- **Agents directory**: the generated project-local directory selected by
  `--agents-dir`, defaulting to `agents`.
- **Agent home**: a directory containing an agent's local runtime state, most
  importantly `.aw/`, `AGENTS.md`, and `CLAUDE.md`.
- **Template repo**: a reusable source blueprint containing `team.yaml`,
  shared docs, roles, and source home templates.
- **Legacy mode**: the existing template-checkout / external-work bootstrap
  behavior selected by `--work-directory` or `--work-repo-url`.
- **In-repo mode**: the new project-local layout that runs from the customer
  repo and creates `<agents-dir>/`.

## Mode Selection

`aw agents bootstrap` has two explicit layout modes.

| Explicit `--agents-dir` | `--work-directory` | `--work-repo-url` | Behavior |
| --- | --- | --- | --- |
| absent or present | unset | unset | in-repo mode |
| absent | set | unset | legacy work-directory mode |
| absent | unset | set | legacy work-repo-url mode |
| present | set | any | reject: `--agents-dir cannot be combined with --work-directory` |
| present | any | set | reject: `--agents-dir cannot be combined with --work-repo-url` |
| absent | set | set | reject: `--work-directory and --work-repo-url are mutually exclusive` |

The default `--agents-dir=agents` applies to in-repo mode. Supplying
`--agents-dir agents` explicitly is valid when neither legacy work flag is
present.

`--home-root` is legacy-only in this contract. In-repo mode owns the generated
home root as `<agents-dir>/home/`; combining `--home-root` with in-repo mode
must be rejected unless a later reviewed contract revision defines exact
semantics.

Dry-run output must state the selected mode and show the generated paths for
that mode. It must not describe the template checkout as the customer working
directory in in-repo mode.

## In-Repo Generated Layout

In-repo mode creates one visible directory in the customer repo:

```text
my-project/
├─ src/
├─ README.md
└─ agents/
   ├─ team.yaml
   ├─ docs/
   ├─ roles/
   ├─ home/
   │  ├─ coordinator/
   │  │  ├─ .aw/
   │  │  ├─ AGENTS.md
   │  │  ├─ CLAUDE.md
   │  │  └─ work -> ../../..
   │  ├─ dev/
   │  │  ├─ .aw/
   │  │  ├─ AGENTS.md
   │  │  ├─ CLAUDE.md
   │  │  └─ work -> ../../worktrees/dev
   │  └─ review/
   │     ├─ .aw/
   │     ├─ AGENTS.md
   │     ├─ CLAUDE.md
   │     └─ work -> ../../worktrees/review
   └─ worktrees/
      ├─ dev/
      └─ review/
```

All live agent homes created by in-repo bootstrap must be under
`<agents-dir>/home/<agent>`. The bootstrap command must not create `.aw/` at
the customer repo root.

Worktree checkouts are implementation detail under
`<agents-dir>/worktrees/<agent-or-alias>`. A worktree-bound agent's home is
still under `<agents-dir>/home/<agent>`; its `work` symlink points to the
matching generated checkout.

Repo-root agents, such as coordinators or planners, use a `work` symlink that
points to the customer repo root.

## Agents Directory Path Rules

`--agents-dir` names a project-local convention directory. The default is
`agents`.

The value must:

- be non-empty,
- be relative,
- be clean after path normalization,
- not be `.`,
- not contain `..` path traversal,
- remain inside the customer repo root,
- not already exist.

The `agents` default is the recommended convention. `--agents-dir` exists for
repos where `agents` would conflict with an existing top-level directory.

If the chosen path exists, bootstrap must fail before side effects with an
actionable error:

```text
Error: agents directory already exists at /path/to/my-project/agents.

To create a new bootstrap here:
  1. Pick a different name with --agents-dir <name>, or
  2. Remove or rename the existing directory if you no longer need it.

aw agents bootstrap does not adopt, merge, or overwrite existing agents
directories in v1. This prevents accidental data loss to existing agent
identity state.
```

Multiple independent bootstraps in one customer repo are allowed by choosing
different non-existing agents directories, for example `agents-dev` and
`agents-review`. Each generated directory is an independent team convention.
The command must not add a global "only one bootstrap per repo" guard.

## Customer Repo Requirement

In-repo mode requires the current directory to be inside a git worktree. The
implementation must resolve the customer repo root with the equivalent of:

```bash
git rev-parse --show-toplevel
```

If that fails, in-repo mode must reject before side effects and tell the user
to run from a git repo or use legacy mode with `--work-directory` /
`--work-repo-url`.

## Template Source Shape

Template repos are source blueprints, not generated project layouts. New
templates must not use top-level `agents/` as the source home directory. The
word `agents/` is reserved for generated customer repos.

Preferred template shape:

```text
template/
├─ team.yaml
├─ docs/
├─ roles/
└─ home/
   ├─ coordinator/
   │  └─ AGENTS.md
   ├─ dev/
   │  └─ AGENTS.md
   └─ review/
      └─ AGENTS.md
```

`team.yaml` uses `home_template` to name the source home directory for each
agent. The path is relative to the template root.

```yaml
name: coord-worktrees
instructions:
  file: docs/team.md
roles:
  coordinator:
    title: Coordinator
    file: roles/coordinator.md
  developer:
    title: Developer
    file: roles/developer.md
  reviewer:
    title: Reviewer
    file: roles/reviewer.md
agents:
  coordinator:
    role_name: coordinator
    work: repo_root
    home_template: home/coordinator
  dev:
    role_name: developer
    work: git_worktree
    home_template: home/dev
  review:
    role_name: reviewer
    work: git_worktree
    home_template: home/review
```

`work` accepts these values:

- `repo_root`: generated `work` symlink points to the customer repo root.
- `git_worktree`: bootstrap creates a git worktree under
  `<agents-dir>/worktrees/<alias-or-agent>` and points `work` there.

If `work` is omitted in an in-repo template, it defaults to `repo_root`.

If `home_template` is omitted, in-repo mode looks for `home/<agent>`. For
legacy compatibility only, if `home/<agent>` is missing and
`agents/<responsibility>/AGENTS.md` exists in the template, bootstrap may use
that legacy source path. New templates should not use this fallback.

No role-level `home_template` override exists in v1. Agent-level
`home_template` is the canonical source-home field.

## Source Copy Rules

In-repo bootstrap copies template source into `<agents-dir>`:

- `team.yaml` -> `<agents-dir>/team.yaml`
- `docs/` -> `<agents-dir>/docs/`
- `roles/` -> `<agents-dir>/roles/`
- each `home_template` directory -> `<agents-dir>/home/<agent>/`

Each generated home must contain `AGENTS.md`. Bootstrap must create or update
`CLAUDE.md` as a symlink or copy pointing at the same content as `AGENTS.md`,
matching existing platform behavior.

Template files are copied before identity-specific files are written, but only
after all required pre-flight checks pass.

## Pre-Flight Before Side Effects

In-repo mode must complete pre-flight checks before any mutation. In
particular, the `<agents-dir>` path validation and existence check must happen
before all of:

- file writes at any path,
- temp directories that resolve under `<agents-dir>`,
- git operations: init, fetch, clone, worktree add, branch creation,
- template fetching or cloning into any location,
- identity or team creation, local or hosted,
- API key creation for hosted identities,
- registry, AWID, hosted onboarding API, or template registry network calls,
- DNS verification calls for global identities,
- role install or role registry fetches,
- worktree creation,
- `.gitignore` updates,
- lock file writes,
- `.aw/` state mutation anywhere on disk.

The implementation should structure this as a separate in-repo pre-flight
phase that runs before template resolution performs network or filesystem
side effects. If a future implementation needs a remote template to determine
layout, it must still perform the agents-dir path and existence checks before
fetching that template.

## Gitignore Contract

Bootstrap is responsible for protecting runtime state from accidental commits.
After pre-flight passes, it must append or create scoped ignore entries in the
customer repo `.gitignore`.

Canonical block:

```gitignore
# Auto-written by aw agents (do not remove)
/agents/home/*/.aw/
/agents/home/*/work
/agents/worktrees/
```

When `--agents-dir` is not `agents`, the paths must use that directory:

```gitignore
# Auto-written by aw agents (do not remove)
/ai-team/home/*/.aw/
/ai-team/home/*/work
/ai-team/worktrees/
```

Rules:

- Do not ignore the whole `<agents-dir>/`.
- Create `.gitignore` if it does not exist.
- Do not duplicate the block if the exact canonical block is already present.
- If equivalent manual entries already exist, avoid duplicate patterns where
  practical.
- If a later run finds the canonical block missing, it may re-add it after
  pre-flight passes.
- Treat each agent home's `work` symlink as generated local state. It points at
  a machine-local repo root or generated worktree checkout and must be
  regenerated by provision/add rather than committed as shared layout.

The generated blueprint files under `<agents-dir>` are intended to be visible
project files. The ignored paths are runtime identity state and generated git
worktree checkouts.

## Identity Resolution

In-repo mode does not create an aw identity at the customer repo root. After
bootstrap, commands run from the repo root should behave like any directory
without `.aw/`: they fail with the normal "current directory is not
initialized" / "no identity found" guidance.

Humans and agents must start from an agent home:

```bash
cd agents/home/coordinator
codex
```

This keeps local identity state unambiguous. The repo root remains ordinary
project source, not an agent.

## Symlink and Worktree Behavior

V1 in-repo bootstrap targets platforms that support directory symlinks in the
same way the existing `aw` workspace helpers do, primarily macOS and Linux.
If symlink creation fails, bootstrap must return a clear error naming the
path it could not link. Windows-specific fallback behavior is out of scope
unless added by a later reviewed contract revision.

If a user deletes or moves a generated worktree, the corresponding agent
home's `work` symlink becomes dangling. The agent home and `.aw/` identity
remain valid, but commands that need the work checkout will fail when they
enter `work`. Repair is a user action: restore the worktree, rerun a future
repair command, or create a new agents directory. V1 bootstrap does not
auto-adopt or repair dangling work symlinks.

## Team Source Semantics

In-repo mode preserves the existing team source authority choices:

- hosted new team via `--username` or interactive prompt,
- hosted API key via `AWEB_API_KEY`,
- invite token via `--invite-token`,
- current workspace forwarding,
- BYOT via `--namespace` and `--team`.

Source conflicts must fail before side effects, as in legacy mode. Missing
non-interactive team source must fail before side effects.

The first generated agent remains the team anchor: bootstrap connects that
home first, installs roles/instructions through that team context, and then
connects additional homes and worktree-bound agents through the established
team context.

## Legacy Compatibility

Legacy template-checkout / external-work bootstrap remains supported:

- `--work-directory` selects legacy work-directory mode when `--agents-dir` is
  not explicitly supplied.
- `--work-repo-url` selects legacy work-repo-url mode when `--agents-dir` is
  not explicitly supplied.
- legacy templates using `agents/<responsibility>/AGENTS.md` remain valid in
  legacy mode.

Legacy behavior may be relabeled in docs as advanced or compatibility, but it
must not break as part of the in-repo implementation unless a later contract
revision and release note deliberately deprecate it.

## Required Tests

Minimum release-blocking tests for this contract:

1. `--agents-dir` validation rejects absolute paths, `.`, empty paths, and
   `..` escapes.
2. Existing target `<agents-dir>` fails before any observable side effect.
3. Mixed flag matrix is enforced exactly.
4. In-repo happy path creates `<agents-dir>/team.yaml`, docs, roles, and
   homes under `<agents-dir>/home`.
5. Repo-root agent home has `work` symlink to the customer repo root.
6. Git-worktree agent home has `work` symlink to
   `<agents-dir>/worktrees/<agent>`.
7. `.gitignore` block is written and does not ignore all of `<agents-dir>`.
8. Running from customer repo root after bootstrap does not resolve as an aw
   identity.
9. `aw whoami`, mail, and chat work from each generated home.
10. Docker-backed e2e covers a full in-repo bootstrap from a customer git repo.
11. Docker-backed e2e reruns bootstrap against the same `<agents-dir>` and
    proves fail-closed behavior with no new filesystem, git, identity,
    network, role, worktree, or ignore-file mutation.
12. Legacy regression covers `--work-directory` and `--work-repo-url`, or
    documents why one is not applicable.

## Release Requirements

Implementation may proceed only after this contract receives Mia review
sign-off. If the template source grammar, path layout, mode selection,
pre-flight side-effect list, or ignore policy changes, route the contract back
for review before code follows it.

Public docs, skills, and template README changes must not describe the new
recommended convention as available until the required CLI/template surfaces
are released.
