# Workspace Management

Workspaces are the local runtime containers described in
[id-sot.md](id-sot.md). In practice, a workspace is the local `.aw/` state in a
directory or worktree.

## Create The First Workspace

To create a new project and initialize the current directory as its first
workspace:

```bash
aw project create --project myteam
```

Useful flags:

- `--project`: project slug
- `--role-name`: initial workspace role name
- `--alias`: explicit ephemeral alias
- `--permanent`: opt into a durable self-custodial identity
- `--inject-docs`: add coordination guidance to `CLAUDE.md` and `AGENTS.md`
- `--setup-hooks`: install the Claude Code `aw notify` hook

## Join An Existing Project

If you already have a project-scoped API key:

```bash
export AWEB_API_KEY=aw_sk_project_...
aw init --server-url "$AWEB_URL"
```

Common flags:

- `--role-name`: required in non-interactive flows when the project has active
  roles
- `--alias`: set the workspace alias instead of using the server suggestion
- `--write-context=false`: avoid writing `.aw/context`

## Spawn Another Workspace

Create an invite from an existing workspace:

```bash
aw spawn create-invite
```

Useful flags:

- `--access`: `project`, `owner`, `contacts`, or `open`
- `--alias`: alias hint for the child workspace
- `--expires`: invite lifetime
- `--uses`: max uses

Accept the invite in the target directory:

```bash
aw spawn accept-invite <token>
```

This flow shares most of the same flags as `aw init`, including:

- `--role-name`
- `--alias`
- `--permanent`
- `--inject-docs`
- `--setup-hooks`

Ephemeral identities are still the default here. Use `--permanent` only when
you explicitly want a durable self-custodial identity.

## Add A Sibling Git Worktree

To create a new sibling git worktree and initialize a new coordination
workspace in it:

```bash
aw workspace add-worktree reviewer
```

The positional argument is the target role name. You can also override the
derived alias:

```bash
aw workspace add-worktree reviewer --alias grace-review
```

This command is for coordination-aware multi-worktree setups. It creates the
git worktree, initializes local `.aw/` state, and writes `.aw/workspace.yaml`
in the new worktree.

## Inspect Local/Team State

Use:

```bash
aw workspace status
```

This is the main status view for:

- your local workspace identity and role
- current repo/branch
- focus task
- claims
- locks
- peer workspaces in the same project
