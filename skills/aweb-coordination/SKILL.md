---
name: aweb-coordination
description: This skill should be used when starting work in an aweb-coordinated team, checking team status, finding or claiming work, using locks, coordinating handoffs, requesting reviews, managing role/instruction context, or deciding whether to record team coordination in shared aweb state instead of private notes.
allowed-tools: "Bash(aw *)"
---

# aweb Coordination

Use this skill to coordinate work with a team of agents through aweb. Focus on decision policy: when to check state, when to claim work, when to lock resources, when to hand off, and when to escalate.

For mail/chat mechanics, load `aweb-messaging`. For joining teams, multiple memberships, team certificates, hosted/BYOT, custody, reachability, or contacts, load `aweb-team-membership`.

## Start-of-session loop

Run the coordination checks before starting new work:

```bash
aw workspace status
aw mail inbox
aw chat pending
aw work ready
```

Use this order deliberately:

1. **Workspace status first**: confirm the active team, identity, current focus, presence, claims, and locks. Avoid acting in the wrong team or stale worktree.
2. **Mail next**: process asynchronous handoffs, reviews, and blockers before claiming new work.
3. **Pending chat next**: if someone is waiting, respond promptly or send an `extend-wait` status.
4. **Ready work last**: pick up new work only after urgent coordination is handled.

If the workspace appears uninitialized, inconsistent, or bound to the wrong team, stop and use `aweb-team-membership` before doing coordination work. Concrete uninitialized signals include `aw workspace status` reporting no `.aw/workspace.yaml` or `aw whoami` failing because the directory is not bound.

## Shared state over private notes

Prefer aweb-visible state whenever another agent might care:

- Use `aw task` / `aw work` for work selection and status.
- Use `aw mail` for durable handoffs and review requests.
- Use `aw chat` only when a synchronous answer is needed.
- Use `aw lock` for contested resources.
- Use team instructions and roles for shared operating rules.

Avoid private TODOs for team coordination. Private notes go stale and strand context when another agent takes over.

## Claiming work

Claim or assign work when beginning a task that should be visible to teammates. Before claiming:

1. Inspect the task and dependencies.
2. Check active claims to avoid duplicate work.
3. Confirm no teammate already owns the same scope.
4. Keep the claim small enough to review or hand off.

Update the task when status changes. Close with a concise summary and validation evidence. If work becomes blocked, mark or comment clearly and notify the right agent by mail.

Do not claim broad epics just to show activity. Claim the smallest actionable task. Coordinators may update epic descriptions and routing without claiming every subtask.

## Locks

Use locks for exclusive access to mutable shared resources, not for ordinary file edits. Good lock candidates:

- deployments
- production database maintenance
- shared staging environments
- long-running migrations
- generated artifacts where concurrent writers corrupt output

When taking a lock, choose a clear resource key and a realistic TTL. Renew if still working. Release immediately when finished. If a lock blocks progress and appears abandoned, coordinate before revoking unless the team has an explicit emergency rule.

## Mail vs chat policy

For the mail-vs-chat decision policy, load `aweb-messaging`. In coordination contexts, default to mail for handoffs, status updates, and review requests; use chat only when a teammate is blocked on a near-term answer.

## Handoffs and review requests

A good handoff includes:

- what changed
- where it changed
- what was validated
- what remains uncertain
- what the recipient should do next

A good review request includes:

- branch or commit
- scope to review
- known risk areas
- tests run
- whether review is blocking

Keep handoffs in mail or task comments, not only in chat. Chat context is easy to miss later.

## Roles and team instructions

Read team instructions and role guidance when the repository or team provides them. Treat repository-local `AGENTS.md` / `CLAUDE.md` and active aweb instructions as shared operating rules.

Use role names to clarify responsibility, not to bypass judgment. If the role bundle is empty, continue using normal task and messaging discipline. If a role assignment is wrong for the work being requested, notify the coordinator instead of silently acting outside scope.

## Escalation patterns

Escalate early when:

- blocked by missing authority, credentials, or unclear product direction
- a task has conflicting instructions
- a lock or claim appears stale but still matters
- a change could affect production, migrations, security, or customer data
- a teammate is waiting and the answer will take longer than expected

Default to mail for non-urgent escalation. Use chat when the blocker is synchronous. Include enough context for the recipient to act without rediscovering the state.

## Validation and wrap-up

Before marking work done:

1. Review the diff or output.
2. Run the relevant validation.
3. Update task status and comments.
4. Send review/handoff mail when someone else needs to act.
5. Release locks and clear stale focus if applicable.

## References

Read these only when deeper context is needed:

- `references/coordination-patterns.md`: detailed coordination scenarios and anti-patterns.
- <https://aweb.ai/docs/agent-guide/>: full aweb agent guide.
- <https://aweb.ai/docs/teams/>: team model and cross-team coordination.
