---
name: aweb-bootstrap
description: This skill should be used when dealing with legacy `aw agents` bootstrap/provision/add/remove layouts, recovering old bootstrap-era agents/ directories, or migrating from bootstrap templates toward primitive-first setup and resource packs. For new team/identity/workspace setup, prefer aweb-team-membership and aweb-identity primitives plus resource-pack guidance.
allowed-tools: "Bash(aw *)"
---

# aweb Bootstrap

Use this skill when a human is working with the legacy
`aw agents` bootstrap/provision/add/remove lifecycle, recovering an existing
bootstrap-era `agents/` directory, or migrating from old template repos toward
primitive-first setup and resource packs.

For a new setup, do **not** start here by default. Prefer:

- `aweb-team-membership` for invite/join/remove/team-membership decisions;
- `aweb-identity` for who the agent is and where keys live;
- ordinary git/filesystem primitives for worktrees and copied resources;
- resource-pack templates for roles, instructions, playbooks, and harness
  adapters.

This skill is about **legacy compatibility mental model + decision policy +
safe recovery**, not memorizing flags.

Related skills:

- For day-to-day coordination once the team exists: `aweb-coordination`
- For mail/chat response policy: `aweb-messaging`
- For joining an existing team, multi-team membership, custody,
  addressability, and contacts: `aweb-team-membership`

Long-form references in the aweb repo:

- `docs/cli-setup-surface-sot.md`: current setup-surface taxonomy;
- `docs/team-bootstrap.md`: legacy bootstrap-era reference;
- `docs/bootstrap-layout-contract.md`: legacy compatibility contract.

## Current product direction

The product center is now **primitives + skills + resource packs**, not a
monolithic bootstrap command. Keep these boundaries separate:

1. Team/identity membership: invite, join, connect, switch, leave.
2. Workspace connection: `aw workspace connect` or `aw service init` with an
   existing identity/certificate.
3. Team context: `aw roles` and `aw instructions`.
4. Filesystem and git worktrees: normal git/filesystem primitives unless a
   compatibility command is explicitly needed.
5. Templates: resource packs containing harness-neutral Markdown roles,
   instructions, playbooks, skills, and adapter examples. They must not be
   canonical `CLAUDE.md`/Pi/Cursor-specific source of truth, and must not carry
   final aliases, DIDs, addresses, certificates, `.aw` state, or generated
   work symlinks.

Use `aw agents ...` only for existing bootstrap-era layouts or when a human
explicitly chooses the compatibility path.

## Mental model: what legacy bootstrap is assembling

`aw agents bootstrap` is obsolete/legacy compatibility because it combines five
things that are easy to confuse:

1) Template repo — the blueprint.

- Contains `team.yaml`, role playbooks, shared instructions, and
  `home/<responsibility>/AGENTS.md` files.
- The template says what responsibilities should exist and which
  `role_name` each should use.
- The template is identity-free. Do not put final aliases, DIDs,
  global addresses, certs, or per-human state in committed
  `team.yaml`.

2) Generated project-local agents directory — where humans start agents.

- By default, run bootstrap from the root of the work repo.
- Bootstrap creates `agents/` in that repo. Every responsibility has a
  blueprint home under `agents/home/<responsibility>/`.
- Repo-root agents use that home as the live workspace.
- Worktree-bound agents use `agents/worktrees/<worktree-name>/` as the
  live workspace; their `.aw/` state lives in that worktree.
- The blueprint home's `work` symlink points at the repo root or at the
  generated worktree for convenience.
- Use `--agents-dir <name>` only when the repo already uses `agents/`
  for something else. If the target directory exists, bootstrap must
  fail before side effects.

3) Team source — the authority/context the generated agents join.

- Hosted new team, existing hosted team via `AWEB_API_KEY`, explicit
  `--invite-token`, current workspace forwarding, or BYOT.
- Exactly one explicit source is allowed. If no explicit source is set
  and cwd is already an aw workspace, bootstrap forwards that current
  team. If no current workspace exists and the run is interactive,
  bootstrap creates a hosted team. Non-interactive runs need an
  explicit source.

4) Per-human naming — how shared layouts avoid collisions.

- Use `--identity-prefix <slug>` for shared repos. Examples: `juan`,
  `maria`, `acme-dev`.
- Canonical multi-human templates use patterns such as
  `{user}-{classic-name}` for local aliases and
  `{user}-{responsibility}` for global address names.
- Never commit the final planned alias/address to `team.yaml`; it
  belongs in ignored `.aw/` state under each agent's runtime workspace.

5) Generated workspaces — the identities that will act.

- Each planned agent gets an aw workspace with its own identity and
  team certificate: repo-root agents under `agents/home/<responsibility>/`,
  worktree-bound agents under `agents/worktrees/<worktree-name>/`.
- The **first generated plan** is the anchor: bootstrap connects it
  first, installs roles/instructions from that workspace's team
  context, then invites/connects the rest.
- Do not assume a responsibility named `implementation` is special.
  The anchor is the first plan the CLI generated.

Aweb team source terms:

- Hosted new team: aweb.ai creates/hosts the team.
- API key: joins the hosted team represented by `AWEB_API_KEY`;
  `--aweb-url`/`AWEB_URL` is optional and defaults to hosted aweb.ai.
- Invite token: first generated workspace accepts an existing invite.
- Current workspace forwarding: caller cwd already has `.aw`;
  bootstrap creates a one-use invite from that active team.
- BYOT: bring your own team. This includes bringing your own
  domain/namespace and controller key. Do not describe a separate
  domain-only bootstrap mode.

## Bootstrap vs provision vs add

Use `aw agents bootstrap` when:

- You are creating the committed `agents/` layout for a repo.
- You are creating a brand-new team from a template.
- You are extending an existing team with a template-defined set of
  agent homes, roles, and instructions.

Use `aw agents provision` when:

- The repo already has a committed `agents/` layout.
- Another human needs their own local `.aw/` state for the same
  responsibilities.
- They have an invite, API key, BYOT authority, or current workspace
  context for the same team.

Use `aw agents add` or `aw agents add-worktree` when:

- The layout already exists and you need one more repo-root
  responsibility (`add`).
- You want one more local git worktree agent without changing the
  committed layout (`add-worktree`).

Do NOT bootstrap when:

- The team already exists and you just need to add yourself: use
  `aweb-team-membership` and the `aw id team ...` commands.
- You only need another workspace for yourself outside the repo-local
  convention: use explicit `git worktree`/filesystem steps plus `aw team join`,
  `aw init`, or `aw workspace connect` as appropriate. `aw workspace
  add-worktree` is a legacy convenience, not the new default.

## Pick a template

Bootstrap-era templates:

- awebai/aweb-team-coord-worktrees
- awebai/aweb-team-company-surfaces

These are being replaced by resource-pack templates. Treat them as legacy
compatibility inputs, not the new customer happy path. A new-design template is
not an identity/workspace mutation plan; it is a collection of harness-neutral
resources that an agent or human can adapt explicitly.

Fork/edit vs use-as-is:

- Use as-is to learn the flow or to run a standard team.
- Clone or fork when you want to customize roles, responsibilities, or
  instructions before provisioning.
- It is safe to edit the template checkout before applying it;
  `aw agents bootstrap` reads `team.yaml`, `roles/`, `docs/`, and
  `home/` from the local template directory at run time.

## Customizing a template before applying it

When the human wants different agents, role playbooks, names, or
instructions, do not patch generated workspaces after bootstrap.
Clone/edit the template first, then bootstrap the edited local
directory.

Typical safe flow:

```bash
git clone https://github.com/awebai/aweb-team-coord-worktrees.git my-team-template
cd my-team-template
# edit team.yaml, roles/*.md, docs/team.md, home/<responsibility>/AGENTS.md
cd /path/to/project-repo
aw agents bootstrap /path/to/my-team-template --dry-run --identity-prefix juan
aw agents bootstrap /path/to/my-team-template --username alice --identity-prefix juan
```

What to edit:

- `team.yaml` roles: add/remove role names and point each to a role
  file.
- `team.yaml` agents: add/remove responsibility workspaces and set
  each `role_name`, optional `identity_scope`, optional
  `home_template`, and optional `work`.
- `team.yaml` naming: for shared repos, prefer
  `naming.local_alias.pattern: "{user}-{classic-name}"`.
- Use `work: repo_root` for an agent whose runtime workspace is its
  blueprint home and whose `work` symlink points to the project repo root.
- Use `work: git_worktree` for an agent whose runtime workspace is a
  generated git worktree under `agents/worktrees/`.
- `roles/*.md`: change operational playbooks installed with
  `aw roles`.
- `docs/team.md`: change shared team instructions installed after the
  anchor connects.
- `home/<responsibility>/AGENTS.md`: change per-workspace startup
  context.

Do not use `default_name` or `default_alias` in current templates.
Those are legacy hints only and must not become committed identity
state.

## Before running bootstrap

1) For the default layout, run bootstrap from the root of the project
git repo.

- Bootstrap creates `agents/` there.
- If `agents/` exists, stop. Do not ask bootstrap to adopt, merge, or
  overwrite it.
- If the project already has a different `agents/` directory, ask the
  human for a different `--agents-dir <name>`.

2) Decide the team source. This affects whether bootstrap creates a
new hosted team, joins an API-key/invite team, forwards the current
team, or uses BYOT.

3) Decide the identity prefix. Shared repos should always pass
`--identity-prefix <human-slug>` explicitly.

## Legacy default layout: project-local agents/

If you must use the obsolete/legacy bootstrap compatibility path, prefer the
default layout:

```bash
cd /path/to/project-repo
aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username alice \
  --identity-prefix juan
```

Expected generated shape:

```text
agents/
  team.yaml
  docs/
  roles/
  home/
    coordinator/
      .aw/
      AGENTS.md
      work -> ../../..
    developer/
      .aw/
      AGENTS.md
      work -> ../../worktrees/developer
    reviewer/
      .aw/
      AGENTS.md
      work -> ../../worktrees/reviewer
  worktrees/
    developer/
    reviewer/
```

The repo root itself is not an aw workspace. Start Codex, Claude Code,
or Pi from an agent runtime workspace:

```bash
cd agents/home/coordinator
codex

cd agents/worktrees/developer
claude
```

Bootstrap writes scoped `.gitignore` entries for
`agents/home/*/.aw/`, `agents/home/*/work`, and `agents/worktrees/`.
It must not ignore the whole `agents/` directory.

If an older generated repo tracked `agents/home/*/work`, remove those
symlinks from git after upgrading:

```bash
git rm --cached agents/home/*/work
git add .gitignore agents
git commit -m "agents: ignore generated work symlinks"
```

## Legacy multi-human shared repo flow

This flow exists for old bootstrap-era layouts. New resource-pack flows should
not require a shared identity-bearing `agents/` layout.

First human:

```bash
cd /path/to/project-repo
aw agents bootstrap https://github.com/awebai/aweb-team-coord-worktrees.git \
  --username alice \
  --identity-prefix juan
git add agents .gitignore
git commit -m "agents: add team layout"
```

Second human:

```bash
git pull
aw agents provision --invite-token <token> --identity-prefix maria
cd agents/home/coordinator
codex
```

The second human does not run bootstrap over the existing `agents/`
directory. Provision reads the committed layout and writes only ignored
local state.

## Team source policy

Non-dry-run bootstrap needs one coherent team source.

Resolution order:

- If any explicit source is set (`AWEB_API_KEY`, `--invite-token`,
  `--username`, or `--namespace/--team`), do not set another explicit
  source.
- If no explicit source is set and cwd is an initialized aw workspace,
  bootstrap forwards the current active team.
- If no explicit source is set, cwd is not an aw workspace, and the
  run is interactive, bootstrap creates/uses a hosted team through
  onboarding prompts.
- If no source can be resolved, stop and ask the human which team
  source to use.

Supported sources:

1) Hosted new team

- Best for first-time teams.
- Use `--username <name>` or run interactively in a TTY.
- Bootstrap uses the same hosted onboarding path as `aw init` for the
  first generated workspace.

2) Existing hosted team via API key

- If `AWEB_API_KEY` is set, bootstrap joins the API key's hosted team.
- `--aweb-url`/`AWEB_URL` is optional; when omitted, the hosted
  aweb.ai default is used.
- Do not also pass `--username`, `--invite-token`, or BYOT flags.

3) Existing team via invite token

- Pass `--invite-token <token>`.
- Bootstrap accepts it into the first generated workspace, then
  creates further invites from that established team context.

4) Current workspace forwarding

- If caller cwd is already initialized for aw and no explicit source
  is set, bootstrap creates a one-use invite from the current active
  team and accepts it into the first generated workspace.

5) BYOT

- Use `--namespace <domain> --team <slug>` when the team's namespace/
  domain and controller key live in your environment.
- Bootstrap creates/ensures the team in that namespace, invites the
  first generated workspace, then uses it as the anchor.

Decision recipe:

- Human says "make me a new team" and has no existing aw context: use
  hosted (`--username` or interactive prompt) plus
  `--identity-prefix`.
- Human has a dashboard/API key: use
  `AWEB_API_KEY=... aw agents bootstrap ... --identity-prefix <slug>`.
- Human pasted an invite: use `--invite-token`.
- Human is already inside the team workspace that should own the new
  agents: use current workspace forwarding.
- Human controls a namespace/domain and wants the team under that
  namespace: use BYOT (`--namespace` + `--team`).

## Adding agents later

Add a repo-root local responsibility:

```bash
aw agents add support --role support
```

Create a local worktree-bound agent without changing the shared layout:

```bash
aw agents add-worktree developer
```

Add a global BYOT responsibility:

```bash
aw agents add support \
  --global \
  --namespace example.com \
  --team circle \
  --identity-prefix juan
```

Remove explicitly separates layout and identity effects:

```bash
aw agents remove support --remove-layout
aw agents remove support --deprovision-local
aw agents remove support --delete-global-address
```

`--remove-layout` does not revoke other humans' certs and does not
delete their ignored `.aw/` state.

`--deprovision-local` uses the local team controller key for self-custodial
teams. For hosted-managed cert-only agents, it can use the agent's own signing
key and active team certificate to ask the hosted service to deprovision that
same agent. It must not be described as dashboard authority over BYOT members.

`--delete-global-address` is opt-in. Self-custodial namespaces require the
local namespace controller key. Hosted-managed global agents can delete only
hosted-managed addresses through hosted self-deprovision; BYOT/unmanaged
addresses remain customer-controller-owned.

Map hosted self-deprovision structured errors to concrete recovery:

- `hosted_team_controller_required`: use/restore the self-custodial team
  controller key; this is not a hosted-managed team.
- `global_address_not_hosted_managed`: delete the address with the customer
  namespace controller; the hosted service must not delete BYOT/unmanaged
  addresses.
- `delete_global_address_required`: rerun with `--delete-global-address` for a
  hosted-managed global agent.
- `local_identity_has_no_global_address`: rerun without
  `--delete-global-address`; local identities do not have global addresses.

## Legacy mode

Legacy out-of-repo mode is still supported for existing scripts that
pass `--work-directory` or `--work-repo-url`. Do not choose it for a
new customer unless they explicitly need the old shape.

## After bootstrap: validate that the team is usable

For each agent directory under `agents/home/<responsibility>/`:

- Run `aw workspace status` to confirm the workspace is initialized,
  the active team is correct, and the identity is present.
- Run `aw whoami` to confirm identity fields are present.
- If you use a wake-up path (Pi extension / Claude Code channel
  plugin), start it inside the agent directory after initialization.

## Troubleshooting policy

If bootstrap fails:

- Stop and capture the first error.
- Do not retry over an existing `agents/` directory.
- Prefer explicit recovery with `aw agents provision`, `aw agents add`,
  or `aw agents remove` over deleting `.aw/` state.
- If you must remove generated state, inspect/back up `.aw/` first.

If a multi-human provision hits an alias/address conflict, rerun with a
different `--identity-prefix` or naming pattern. Invite-only flows may
discover collisions only when accepting/registering; this is expected
fail-closed behavior.

## References

Read these only when deeper context is needed:

- references/bootstrap-scenarios.md: scenarios, checklists, and
  troubleshooting.
- docs/team-bootstrap.md (aweb repo checkout): full reference guide.
