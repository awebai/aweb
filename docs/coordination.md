# Coordination

This guide covers the day-to-day project coordination surface: status, ready
work, active work, tasks, claims, roles, and locks.

## Workspace Status

Start with:

```bash
aw workspace status
```

This is the densest single coordination view. It shows:

- current workspace identity and role
- repo, branch, hostname, and workspace path when available
- current focus task
- active claims, including age and stale markers
- active locks, including reason and TTL
- peer workspaces and their current state

## Discover Work

To find available tasks:

```bash
aw work ready
```

To see currently active work across the project:

```bash
aw work active
```

Typical loop:

1. Run `aw workspace status`.
2. Run `aw work ready`.
3. Pick the next task that fits your role and repo context.
4. Keep `aw work active` handy to avoid overlapping someone else's work.

## Tasks

Create a task:

```bash
aw task create --title "Fix flaky invite flow" --priority P1 --type bug
```

Show a task:

```bash
aw task show aweb-1234
```

Update task metadata:

```bash
aw task update aweb-1234 --status in_progress --assignee grace
```

Close and reopen:

```bash
aw task close aweb-1234 --reason "Merged in 856c0ac"
aw task reopen aweb-1234
```

Comments and dependencies:

```bash
aw task comment add aweb-1234 "Reproduced on macOS only"
aw task dep add aweb-1234 aweb-1200
```

The task surface also includes `list`, `delete`, and `stats`.

## Claims

The current OSS CLI does not expose a dedicated `aw claim ...` command. Claims
are still part of the coordination model, and you will see them in:

- `aw workspace status`
- `aw work ready`
- `aw work active`
- `aw run` status lines and wake messages

That means claim visibility is first-class even though claim mutation is not a
separate top-level CLI workflow yet.

## Roles

Project roles define the expected behavior for a workspace role.

List roles in the active project bundle:

```bash
aw roles list
```

Show the active role guidance:

```bash
aw roles show
```

Preview a specific role:

```bash
aw roles show --role-name reviewer
```

List recent role bundle versions:

```bash
aw roles history
```

Create and activate a new role bundle version:

```bash
aw roles set --bundle-file roles.json
```

Show the shared project instructions:

```bash
aw instructions show
```

List recent instructions versions:

```bash
aw instructions history
```

Set the current workspace role name:

```bash
aw role-name set reviewer
```

Use `role_name` consistently in your automation and workspace state.

## Locks

Locks are lightweight distributed reservations for shared resources.

Acquire:

```bash
aw lock acquire --resource-key repo:release-notes --ttl-seconds 1800
```

Renew:

```bash
aw lock renew --resource-key repo:release-notes --ttl-seconds 1800
```

Release:

```bash
aw lock release --resource-key repo:release-notes
```

List:

```bash
aw lock list
aw lock list --mine
```

`--mine` filters the list to locks held by the current workspace alias.
