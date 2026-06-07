# aw agents Layout and Lifecycle Contract

This document is the normative contract for `aw agents`: the repo-root
command family that owns the project-local `agents/` convention, multi-human
provisioning, naming, and agent lifecycle operations.

It supersedes the `aw team bootstrap` command model for this surface. Team
authority remains in `aw id team`; `aw agents` manages the repo-local
convention and per-human materialization of identities into that convention.

Implementation of `aweb-aapz.2+` must cite this document. If command taxonomy,
naming grammar, preflight semantics, destructive behavior, or the shared vs
per-human data split changes, route this document back through review before
code follows the change.

## Goals

The customer work repo should be the center of gravity:

```bash
cd my-project
aw agents bootstrap gh:awebai/aweb-team-coord-worktrees \
  --username juan \
  --identity-prefix juan
cd agents/home/coordinator
codex
```

The same repo should work for multiple humans:

```bash
git clone git@github.com:customer/my-project.git
cd my-project
aw agents provision --identity-prefix maria --invite-token "$TOKEN"
cd agents/home/developer
claude
```

The first command creates or updates a shared repo convention. The second
command creates only Maria's local, ignored identity state and joins the same
team without reusing Juan's aliases, addresses, DIDs, keys, or certificates.

## Terms

- **Customer repo**: the git worktree containing the project agents will work
  on.
- **Agents directory**: the project-local convention directory selected by
  `--agents-dir`, defaulting to `agents`.
- **Agent responsibility**: a stable blueprint key such as `coordinator`,
  `developer`, or `reviewer`. Responsibilities are safe to commit.
- **Agent home**: `agents/home/<responsibility>/`, containing `AGENTS.md`,
  `CLAUDE.md`, the `work` symlink, and this human's ignored `.aw/` runtime
  state after provisioning.
- **Worktree checkout**: `agents/worktrees/<name>/`, a generated git worktree
  for a worktree-bound agent.
- **Template repo**: reusable source blueprint containing `team.yaml`, shared
  docs, roles, and source home templates. It is not generated output.
- **Team alias**: the alias stored in the team certificate. Active aliases are
  unique inside an AWID team.
- **Global name**: the name part of a public AWID namespace address such as
  `example.com/juan-review`. Active global names are unique inside the
  namespace.
- **Identity prefix**: the human or operator prefix used to derive per-human
  aliases/global names, for example `juan` or `maria`.
- **Naming sequence**: a deterministic stream of candidate words such as
  `classic-name` (`alice`, `bob`, `charlie`, ...) or `star-name`.
- **Naming pattern**: a template such as `{user}-{responsibility}` or
  `{user}-{classic-name}` expanded by the naming planner.

## Command Taxonomy

`aw agents` is the current command family for this product surface:

```text
aw agents bootstrap <template>
aw agents plan
aw agents provision
aw agents add <responsibility>
aw agents add-worktree <responsibility>
aw agents remove <responsibility>
```

Command meanings:

- `aw agents bootstrap <template>` creates the shared `agents/` convention
  from a template in the current customer repo and provisions this human's
  local state unless `--layout-only` or `--dry-run` is used.
- `aw agents plan` reads an existing `agents/` layout and renders the complete
  naming/provisioning plan without mutation.
- `aw agents provision` reads an existing committed `agents/` layout and
  creates or verifies this human's local ignored identity state.
- `aw agents add <responsibility>` adds a local or global agent responsibility
  to the layout and optionally provisions it for this human.
- `aw agents add-worktree <responsibility>` adds a worktree-bound agent from
  repo root. Its home remains under `agents/home/<responsibility>/`; its
  checkout lives under `agents/worktrees/<name>/`.
- `aw agents remove <responsibility>` safely removes or deprovisions an agent
  responsibility or this human's local materialization, depending on flags.

`aw team bootstrap` is not preserved as a compatibility alias in this
contract. Remove it from the current command surface unless a later reviewed
decision explicitly reverses that.

`aw id team` remains the place for AWID team authority commands:

```text
aw id team create
aw id team invite
aw id team accept-invite
aw id team add-member
aw id team remove-member
aw id team register
```

`aw workspace` remains the place for operations on the current initialized
workspace. `aw agents` may reuse workspace helpers internally, but its user
contract is repo-root layout management.

## Authority Model

`aw agents` must not invent team authority from repo files.

Allowed team sources:

- `--invite-token`: the invite token already binds to a team. Bootstrap and
  provision must not require separate `--namespace` or `--team` for this path.
- `AWEB_API_KEY`: service authority. The service resolves or provisions the
  hosted team/workspace context. The CLI must not treat the API key as a
  sender-declared team id.
- current initialized workspace: the current workspace's active team creates
  invites for the new agent homes.
- `--username`: hosted onboarding path for creating/using hosted service
  context.
- `--namespace <domain> --team <name>`: BYOT team-controller path. The local
  namespace/team controller keys under `~/.awid/` authorize namespace/team
  creation and invite/certificate minting.

Source conflicts must fail before side effects. Missing non-interactive source
must fail before side effects with an actionable message naming the accepted
sources.

Global address deletion requires namespace-controller authority. Team
certificate revocation requires team-controller authority or the service path
that legitimately holds that authority. A repo file cannot grant either.

Authority resolution must respect custody mode:

| Operation | Self-custodial namespace/team | Hosted custodial namespace/team |
| --- | --- | --- |
| Delete global namespace address | Local namespace controller key under `~/.awid/` | Hosted service session/API authority that legitimately controls the managed namespace |
| Revoke team certificate | Local team controller key under `~/.awid/` or signed BYOT authority flow | Hosted service session/API authority that legitimately controls the hosted team |
| Create team invite/cert | Local team key or namespace/team controller path | Hosted service invite/cert authority |

The CLI must detect which authority model applies from the selected team
source and existing state. Missing authority errors must name the correct
recovery path. A hosted custodial user must not be told only to find a local
namespace controller key; a self-custodial user must not be told that the
server can delete their namespace address without their controller authority.

## Repo Root Invariant

In-repo `aw agents` commands run from the customer repo root or a directory
inside that git worktree. The implementation must resolve the repo root using
the equivalent of:

```bash
git rev-parse --show-toplevel
```

The customer repo root is not an aw identity. `aw agents` must not create
`.aw/` at the repo root. Identity-dependent commands such as `aw whoami`,
`aw mail`, and `aw chat` run from the repo root should fail with normal
"not initialized" guidance plus, where practical, a hint to `cd
agents/home/<responsibility>`.

All live agent homes created or provisioned by `aw agents` are under:

```text
<agents-dir>/home/<responsibility>/
```

All generated worktree checkouts are under:

```text
<agents-dir>/worktrees/<name>/
```

## Shared vs Per-Human State

Committed/shared:

- `<agents-dir>/team.yaml`
- `<agents-dir>/docs/`
- `<agents-dir>/roles/`
- source home files such as `AGENTS.md` and `CLAUDE.md`
- responsibility names and role/work binding metadata
- naming policy defaults and hints

Ignored/per-human:

- `<agents-dir>/home/*/.aw/`
- private signing keys
- private encryption keys
- team certificates
- workspace ids
- DID/key material
- generated local aliases and global addresses selected for this human
- generated git worktree checkouts

Never commit:

- `.aw/`
- `~/.awid/` key material
- namespace controller keys
- team controller keys
- generated private identity keys
- generated worktree checkouts

The generated `agents/` layout may be committed. It must not reserve final
global addresses or active team aliases for every future user.

## Generated Layout

Default generated customer layout:

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
   │  │  ├─ .aw/              # ignored, created per human
   │  │  ├─ AGENTS.md
   │  │  ├─ CLAUDE.md
   │  │  └─ work -> ../../..
   │  ├─ developer/
   │  │  ├─ .aw/              # ignored, created per human
   │  │  ├─ AGENTS.md
   │  │  ├─ CLAUDE.md
   │  │  └─ work -> ../../worktrees/<developer-worktree>
   │  └─ reviewer/
   │     ├─ .aw/              # ignored, created per human
   │     ├─ AGENTS.md
   │     ├─ CLAUDE.md
   │     └─ work -> ../../worktrees/<reviewer-worktree>
   └─ worktrees/
      ├─ <developer-worktree>/
      └─ <reviewer-worktree>/
```

`work: repo_root` means the agent home's `work` symlink points to the customer
repo root. `work: git_worktree` means the agent home's `work` symlink points
to a generated checkout under `agents/worktrees/`.

## Template Source Shape

Templates are source blueprints. New templates must not use top-level
`agents/` as their source layout.

Preferred template shape:

```text
template/
├─ team.yaml
├─ docs/
├─ roles/
└─ home/
   ├─ coordinator/
   ├─ developer/
   └─ reviewer/
```

Template `team.yaml` should express responsibilities and hints, not final
identity state:

```yaml
name: coordinator-with-dev-review-worktrees
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
naming:
  local_alias:
    sequence: classic-name
    pattern: "{classic-name}"
  global_alias:
    sequence: classic-name
    pattern: "{user}-{classic-name}"
  global_name:
    pattern: "{user}-{responsibility}"
agents:
  coordinator:
    role_name: coordinator
    identity_scope: global
    home_template: home/coordinator
    work: repo_root
  developer:
    role_name: developer
    identity_scope: local
    home_template: home/developer
    work: git_worktree
  reviewer:
    role_name: reviewer
    identity_scope: local
    home_template: home/reviewer
    work: git_worktree
```

`identity_scope` values:

- `local`: create a local team member identity/certificate only.
- `global`: create or use a global AWID identity and namespace address.

If `identity_scope` is omitted, default to `local`.

`default_alias` and `default_name` from the previous bootstrap contract are
removed from the current schema. Templates that still contain them should
parse with a deprecation warning for one transition release and the values must
be ignored by the planner. CI guardrails should fail canonical templates that
continue to use those fields after the transition. Do not treat
`default_alias` or `default_name` as public addresses or mandatory team
aliases for all users.

After every `aw agents` command, committed `agents/team.yaml` remains
identity-free. It must not be rewritten with final aliases, global addresses,
DIDs, cert paths, workspace ids, or any per-human state. Runtime state belongs
under ignored `agents/home/<responsibility>/.aw/` or approved user key
locations only.

## Naming Grammar

Named sequences are deterministic candidate streams. At minimum:

- `classic-name`: the existing understandable sequence (`alice`, `bob`,
  `charlie`, ...).
- `star-name`: a human-readable astronomy/star sequence. The exact list must
  be committed and tested before use.

Future sequence names are allowed only through a reviewed contract update or a
backward-compatible extension with tests and docs.

Supported pattern fields:

- `{user}`: resolved identity prefix for the current human/operator.
- `{responsibility}`: template responsibility key.
- `{classic-name}`: next candidate from the classic sequence.
- `{star-name}`: next candidate from the star sequence.

Pattern rules:

- Each expanded source field must pass slug rules before substitution.
- Unknown fields fail before side effects.
- Empty expansions fail before side effects.
- Final generated names must pass the relevant slug rules.
- Patterns must not contain path separators or path traversal.
- The same generated final alias/address/worktree name must not appear twice
  inside one plan.

Both checks are required: validate each source field independently and validate
the final expanded result. This applies to:

- explicit `--identity-prefix`;
- hosted username used as `{user}`;
- `AWEB_IDENTITY_PREFIX`, `AWEB_HUMAN`, and `$USER`;
- template responsibility keys;
- classic-name and star-name sequence entries;
- namespace and team slugs where they are reused in derived names;
- explicit pattern strings and the expanded pattern result.

Values such as `../escape`, `alice/ops`, `.`, and empty strings must fail
before any filesystem, git, registry, service, or local state mutation.

Default naming policy:

| Identity scope | Field | Default sequence | Default pattern | Rationale |
| --- | --- | --- | --- | --- |
| local | team alias | `classic-name` | `{classic-name}` | Preserves the clear existing `alice`, `bob`, `charlie` model. |
| global | team alias | `classic-name` | `{user}-{classic-name}` | Keeps team aliases unique across humans by default. |
| global | namespace address name | none required | `{user}-{responsibility}` | Global public addresses should show owner/context and avoid generic reservations. |
| worktree | checkout/branch suffix | responsibility | `{responsibility}` with collision suffix if needed | Worktree names should remain role-readable. |

Supported global alternatives must include:

```text
{user}-{classic-name}
{user}-{star-name}
{user}-{responsibility}
```

The CLI may expose these as:

```bash
--identity-prefix juan
--local-alias-sequence classic-name
--global-name-sequence star-name
--local-alias-pattern "{classic-name}"
--global-alias-pattern "{user}-{classic-name}"
--global-name-pattern "{user}-{responsibility}"
```

If a user wants public global addresses from the star sequence, they can select
that explicitly:

```bash
--global-name-sequence star-name
--global-name-pattern "{user}-{star-name}"
```

The exact flag names are part of the implementation slice, but the semantics
above are load-bearing.

Identity prefix resolution order:

1. explicit `--identity-prefix`;
2. hosted username when unambiguous;
3. `AWEB_IDENTITY_PREFIX`;
4. `AWEB_HUMAN`;
5. `$USER`;
6. fail if no valid prefix can be derived for a pattern that needs `{user}`.

The resolved prefix must be displayed in dry-run output.

## Availability Preflight

The naming planner produces candidates. Availability checks decide whether the
plan is valid.

Preflight must check:

- internal duplicate aliases, global names, home paths, worktree paths, and
  branches in the generated plan;
- active aliases in the target AWID team;
- active namespace addresses for global agents;
- local filesystem paths under `<agents-dir>/home` and
  `<agents-dir>/worktrees`;
- git branch names and worktree metadata;
- `.gitignore` state and ability to write the canonical block;
- template source paths and required files;
- team source conflicts and availability;
- namespace controller/team controller key presence when required;
- service/API key reachability when required;
- role/instructions install prerequisites;
- existing local `.aw` state in any target home.

The existing hosted service alias-suggestion endpoint may remain useful for
single-workspace flows. It is not sufficient as the only planner for
multi-agent `aw agents`, because the planner needs N coordinated names and
must support AWID-only/BYOT/global-address cases.

If a candidate is unavailable, the planner may try the next candidate in the
selected sequence. It must stop with an actionable error when no valid
candidate is found within the bounded search space.

Successful preflight is necessary but not sufficient for mutation success.
Another human or process can allocate the same team alias, namespace address,
branch, or path after preflight and before mutation. Hosted-side or AWID-side
conflict responses such as 409 must be treated as a re-plan/fail-actionable
condition, not as a panic or silent fallback. The failing command must not
leave local `.aw` state from a half-committed identity creation; it should
report the conflict and tell the user to rerun plan/provision with a different
prefix, pattern, or sequence.

## Fail Before Side Effects

Mutating `aw agents` commands must complete preflight before any observable
mutation.

No mutation before preflight:

- file writes anywhere in the customer repo;
- temp dirs under `<agents-dir>`;
- `.gitignore` writes;
- template clone/fetch into any persistent location;
- git branch creation;
- git worktree creation/removal;
- identity/key creation;
- encryption key creation;
- DID/AWID identity registration;
- namespace address registration/delete/reassign;
- DNS verification record writes;
- namespace verification API calls to third-party DNS resolvers;
- hosted namespace registry registration calls;
- team cert registration/revocation;
- invite creation/acceptance;
- API-key hosted onboarding calls;
- role/instructions upload;
- service registration/init calls;
- local move-aside or deletion;
- lock file writes;
- `.aw/` mutation at any path.

If a future implementation needs remote template metadata to determine the
layout, it must still perform path and existence checks for `<agents-dir>`
before fetching.

## Gitignore Contract

`aw agents bootstrap` is responsible for writing scoped ignore entries after
preflight passes:

```gitignore
# Auto-written by aw agents (do not remove)
/agents/home/*/.aw/
/agents/home/*/work
/agents/worktrees/
```

For non-default agents dirs:

```gitignore
# Auto-written by aw agents (do not remove)
/ai-team/home/*/.aw/
/ai-team/home/*/work
/ai-team/worktrees/
```

Rules:

- Do not ignore the whole `<agents-dir>/`.
- Create `.gitignore` if missing.
- Do not duplicate the canonical block.
- If equivalent manual entries exist, avoid duplicate patterns where practical.
- If the block is missing on a later run, `aw agents` may re-add it after
  preflight passes.
- Treat each agent home's `work` symlink as generated local state. It points at
  a machine-local repo root or generated worktree checkout and must be
  regenerated by provision/add rather than committed as shared layout.

## Command Details

### aw agents bootstrap

Creates the shared layout from a template and optionally provisions this
human's identities.

Examples:

```bash
aw agents bootstrap gh:awebai/aweb-team-coord-worktrees \
  --username juan \
  --identity-prefix juan
aw agents bootstrap ./my-template \
  --namespace juanreyero.com \
  --team circle \
  --identity-prefix juan
aw agents bootstrap gh:awebai/aweb-team-coord-worktrees \
  --layout-only \
  --identity-prefix juan
aw agents bootstrap gh:awebai/aweb-team-coord-worktrees \
  --dry-run \
  --identity-prefix juan
```

Behavior:

- Requires current directory inside a git worktree.
- Fails if `<agents-dir>` already exists.
- Copies template source to `<agents-dir>`.
- Writes `.gitignore` block.
- Creates homes and work symlinks.
- Creates worktrees only after preflight.
- Provisions identities unless `--layout-only`.
- Does not create `.aw` at repo root.

V1 does not auto-adopt or resume partial `<agents-dir>` bootstrap output. If
`<agents-dir>` exists, even partially, bootstrap fails before side effects with
manual cleanup guidance. The error must tell the user to inspect/back up any
`.aw` identity state before removing the directory, then remove or rename
`<agents-dir>` or use the approved remove command once available. Automatic
merge/resume requires a later contract with explicit idempotency markers.

### aw agents plan

Reads an existing layout or a template and prints what would happen.

Examples:

```bash
aw agents plan
aw agents plan --identity-prefix maria --invite-token "$TOKEN"
aw agents plan --global-name-pattern "{user}-{star-name}"
```

Output must include:

- resolved agents dir;
- resolved identity prefix;
- team source;
- each responsibility;
- identity scope;
- planned team alias;
- planned global address if any;
- home path;
- work path;
- branch/worktree path if any;
- availability status and source of each check.

### aw agents provision

Creates this human's ignored identity state from an existing `agents/` layout.

Examples:

```bash
aw agents provision --identity-prefix maria --invite-token "$TOKEN"
aw agents provision --identity-prefix juan --namespace juanreyero.com --team circle
aw agents provision --identity-prefix alice
```

Behavior:

- Fails if `<agents-dir>/team.yaml` is missing.
- Does not overwrite conflicting `.aw` state.
- Accepts matching existing state and reports it as already provisioned.
- Creates E2EE encryption keys for every new identity path.
- Connects to service where the selected source requires service connection.
- Installs roles/instructions only after the anchor identity is established.

V1 provision does not auto-recover partial `.aw` state. If a previous run left
a signing key without a certificate, a certificate without matching workspace
state, or otherwise incomplete local state, fail before further mutation with
actionable move-aside/repair instructions. Do not silently continue from
ambiguous partial identity state.

### aw agents add

Adds a responsibility to the layout and optionally provisions it.

Examples:

```bash
aw agents add analyst --local --role analyst
aw agents add support --global --role support --namespace juanreyero.com --team circle --global-name-pattern "{user}-{star-name}" --identity-prefix juan
aw agents add planner --layout-only
```

Behavior:

- Updates `agents/team.yaml` and source home only after preflight.
- Creates a source home with required `AGENTS.md`/`CLAUDE.md` behavior.
- Allocates aliases/global names through the planner.
- Supports `--layout-only` for blueprint-only changes.

### aw agents add-worktree

Adds a worktree-bound agent from repo root.

Examples:

```bash
aw agents add-worktree developer
aw agents add-worktree reviewer --identity-prefix maria
```

Behavior:

- Home path remains `agents/home/<responsibility>`.
- Worktree path is `agents/worktrees/<safe-name>`.
- Branch/worktree name is sanitized and collision checked.
- Reuses established team authority paths internally:
  local team key, API key, hosted cert-only parent invite, or BYOT team key.

### aw agents remove

Safely removes/deprovisions an agent.

Examples:

```bash
aw agents remove reviewer --dry-run
aw agents remove reviewer --deprovision-local
aw agents remove reviewer --remove-layout
aw agents remove support --delete-global-address
```

Removal modes:

- `--deprovision-local`: revoke this human's membership where possible and
  move aside local `.aw`/home runtime state.
- `--remove-layout`: remove the shared responsibility from `agents/team.yaml`
  and move aside source home files. This is a repo change and must be explicit.
- `--delete-global-address`: delete the namespace address after membership
  revocation. Requires namespace-controller authority. Without this flag,
  preserve the global address by default.

`--delete-global-address` authority follows the custody matrix in the
Authority Model section. For self-custodial namespaces, use the local
namespace controller key. For hosted custodial namespaces, use the hosted
session/API authority. If the needed authority is unavailable, fail with a
message specific to that custody mode.

Destructive filesystem behavior should move aside to a timestamped backup
under the agents dir or another contract-approved safe location. Do not unlink
private key material silently.

Remote revocation failure must not silently delete local state. Report partial
state and next commands.

## Multi-Human Scenario

Human A:

```bash
cd my-project
aw agents bootstrap gh:awebai/aweb-team-coord-worktrees \
  --namespace example.com --team circle \
  --identity-prefix juan
git add agents .gitignore
git commit -m "Add aw agents layout"
```

Human B:

```bash
git clone git@github.com:customer/my-project.git
cd my-project
aw agents provision --invite-token "$TOKEN" --identity-prefix maria
cd agents/home/developer
aw whoami
```

Expected result:

- Human B does not reuse Human A's DIDs, aliases, private keys, certs, or
  global addresses.
- Shared responsibilities and instructions are reused.
- `agents/home/*/.aw/` remains ignored.
- Team aliases/global addresses are unique and checked before provisioning.

## Add and Remove Semantics

Adding an agent may be a layout change, a local provisioning change, or both.
The command must make this explicit in dry-run and output.

Removing an agent may mean:

- remove only this human's local materialization;
- revoke team certificate;
- remove generated git worktree;
- remove shared layout responsibility;
- delete global namespace address.

Those are separate effects. Do not bundle global address deletion into ordinary
remove. Do not remove shared layout by default when the user only wants to
deprovision their local agent.

`--remove-layout` is a shared-blueprint change only. It removes the
responsibility from committed layout going forward; it does not revoke other
humans' existing certificates, delete their global addresses, delete their
private keys, or invalidate their local `.aw` state. If Maria provisioned
`reviewer` and Juan later commits a layout removal for `reviewer`, Maria's
existing local identity remains under her ignored `.aw` state until she
explicitly deprovisions it or the certificate expires/revokes through normal
authority. Commands run from a home whose responsibility no longer exists in
the pulled layout should show a stale-layout notice and must not auto-remove
anything.

## Existing State Handling

Existing matching state:

- If the home has `.aw` state matching the planned identity/team/alias, report
  already provisioned and continue.

Existing conflicting state:

- If the home has `.aw` state for a different identity/team/alias, fail before
  side effects and show move-aside or explicit override guidance.

Existing committed layout:

- `aw agents provision` and `aw agents add` operate on existing `agents/`.
- `aw agents bootstrap` does not adopt/merge an existing agents directory.

## Security and Key Handling

- Private identity keys stay in agent-home `.aw/` or approved key storage.
- Namespace/team controller keys stay under `~/.awid/`.
- Global identities and namespace controller keys must print backup warnings
  consistent with identity docs.
- Every new identity creation path must create an encryption key suitable for
  E2EE messaging.
- Do not write secrets into template source, generated docs, role files,
  `.gitignore`, git config, or command output.
- Dry-run must not generate real private keys.

## Required Tests

Minimum release-blocking tests:

1. Contract parsing: valid `team.yaml` with naming policies.
2. Unknown naming sequence and unknown pattern field fail before side effects.
3. Local defaults allocate classic aliases and skip unavailable aliases.
4. Global defaults allocate `{user}-{responsibility}` addresses and reject
   unavailable namespace names.
5. `{user}-{classic-name}` and `{user}-{star-name}` work for global names.
6. Two humans with separate HOME directories provision from the same committed
   layout into the same team without collisions.
7. A collision in the second human's alias/address aborts before local or
   remote mutation.
8. `aw agents bootstrap` refuses existing `<agents-dir>` before template fetch,
   file writes, git operations, identity creation, or network mutation.
9. Repo root remains non-aw identity after bootstrap/provision.
10. `aw agents add` local and global paths work and are dry-run visible.
11. `aw agents add-worktree` creates home under `agents/home` and checkout
    under `agents/worktrees`.
12. `aw agents remove` dry-run, move-aside, revoke, preserve-address default,
    and explicit address deletion are covered.
13. Existing standalone `aw workspace add-worktree` behavior remains green.
14. Skills/docs examples execute or are covered by smoke tests.
15. CI guardrail scans docs, skills, generated CLI reference, and source for
    stale `aw team bootstrap` recommendations. Historical/changelog mentions
    may be allowlisted explicitly; current guidance must use `aw agents`.
16. Path-traversal injection fails before side effects for inputs including
    `--identity-prefix '../escape'`, malicious responsibility keys,
    `--namespace`/`--team` values reused in derived names, and
    `--global-name-pattern '{user}/escape'`. Tests assert no files are created
    under `<agents-dir>` or sibling escape paths.
17. Concurrent allocation/TOCTOU: two runs against the same team with the same
    identity prefix are serialized to force a mutation-time conflict. One
    succeeds; the other fails actionably on conflict without leaving local
    `.aw` state in the failing branch.
18. Custodial vs self-custodial removal: `aw agents remove
    --delete-global-address` succeeds with the correct authority for both
    local controller-key namespaces and hosted custodial namespaces, and fails
    with the correct custody-specific recovery message when authority is
    absent.
19. Partial-bootstrap recovery: simulate a crash after the canonical
    `.gitignore` block is written but before homes are created. A retry must
    produce the v1 manual-cleanup error and must not silently merge/resume.
20. Multi-human identity-free layout: after Human A bootstraps/commits and
    Human B provisions, Human B's git diff contains no changes to committed
    `agents/team.yaml`, source homes, docs, or roles. Only ignored state may
    differ.

Docker-backed e2e must include the multi-human same-repo journey and a
fail-before-side-effects collision journey. Tests 16 and 17 belong in the
Docker-backed matrix because they need realistic filesystem and service/AWID
boundaries. Test 15 is a PR-time guardrail. Tests 18 and 19 may be unit or
integration if they exercise the custody/error and partial-state semantics
directly.

## Release Requirements

Release decisions must follow actual touched surfaces:

- CLI changes require `@awebai/aw` publish.
- Python server/shared package changes require PyPI `aweb` publish before
  downstream consumers pin them.
- AC changes require AC release and correct PyPI floor if AC imports new aweb.
- Template changes require updating `aweb-team-coord-worktrees`.
- Skill changes require verifying live tarball contents before deciding
  whether to publish `@awebai/claude-skills`, Pi, and marketplace updates.

Before tag/publish:

- contract sign-off by Mia;
- implementation slice reviews by Mia;
- canonical release gate at exact target SHA;
- e2e tests green;
- no stale `aw team bootstrap` recommendations in current docs/skills/help.

## Review Gates

Mia must sign off this contract before `aweb-aapz.2+` implementation starts.

Back-route to this contract for review if any of these change:

- `aw agents` command taxonomy;
- naming sequence or pattern grammar;
- default naming policy;
- preflight availability list;
- destructive remove semantics;
- template `team.yaml` grammar;
- shared vs per-human state boundary;
- decision not to preserve `aw team bootstrap`.
