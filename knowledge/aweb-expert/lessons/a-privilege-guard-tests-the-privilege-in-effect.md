---
type: Lesson
title: A privilege guard tests the privilege in effect, not membership
description: pg_has_role(user, role, 'MEMBER') is true for a NOINHERIT member that does not hold the role's privileges, so a guard trusting pg_read_all_stats membership sees other users' xact_start as NULL and passes vacuously; ask for USAGE (or superuser), and prove the guard with a NOINHERIT member watching another login's open transaction, because a role with no membership cannot tell MEMBER from USAGE.
tags: [lesson, postgres, privileges, guards, testing, review]
timestamp: 2026-11-27
---

# The discovery

A rollback guard had to prove that no other session still held an open write
transaction. It read other logins' `pg_stat_activity.xact_start`, and it first
checked that the role could see those rows with
`pg_has_role(current_user, 'pg_read_all_stats', 'MEMBER')`.

`MEMBER` answers "is this role a member, directly or indirectly". It does not
answer "does this session hold the role's privileges now". A role granted
`pg_read_all_stats` with `NOINHERIT` passes `MEMBER` but holds the privilege
only after `SET ROLE`. For that session, other users' `xact_start` reads as
NULL, so "no open transaction" was true for every session and the guard exited
0 while a writer was still open. Reproduced on PostgreSQL 17: `MEMBER` true,
`USAGE` false, guard exit 0.

The guard's own test used a role with no membership at all. That is the
neighbouring case: both `MEMBER` and `USAGE` are false for it, so the test
could not tell the two apart. The independent protocol reviewer caught the
gap.

# How to apply

- Ask for the privilege in effect: `pg_has_role(..., 'USAGE')`, or superuser.
  `MEMBER` is a question about the role graph, not about what this session can
  see or do.
- A visibility guard that sees nothing passes vacuously. Make it refuse when
  it cannot see, rather than trusting that empty means none.
- Prove the guard on the case that separates the two answers: a `NOINHERIT`
  member watching another login's open transaction. The test must go red with
  `MEMBER` restored and green with `USAGE`.

This is a PostgreSQL instance of
[a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
a check is evidence only for the cases it can tell apart.

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-move, 2026-11-27;
notes/pg-has-role-member-is-not-the-privilege.md.
Checked by the harvester: naapp commit 32de1865 switches the guard from
`MEMBER` to `USAGE` and adds the parametrized `NOINHERIT` case; it is in naapp
merge 6df1df3c. The PostgreSQL 17 reproduction, the red-then-green run and the
reviewer's mutation check (restoring `MEMBER` fails the new case) are
source-reported.
