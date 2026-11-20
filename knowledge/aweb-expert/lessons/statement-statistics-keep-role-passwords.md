---
type: Lesson
title: Statement statistics keep role passwords
description: pg_stat_statements normalises the constants in ordinary queries but keeps a CREATE ROLE or ALTER ROLE ... PASSWORD literal as typed, so a read-only tool that exports statement text can copy a role password into its output; keep text only for SELECT, INSERT, UPDATE, DELETE and WITH, or key statements by queryid.
tags: [lesson, security, secrets, postgresql, observability]
timestamp: 2026-11-13
---

Load, observability and diagnostic tooling around a team deployment must not
put a credential in its output. A tool that only reads PostgreSQL statistics
looks safe and passes a read-only review, yet it can still leak a password.

- **What PostgreSQL keeps.** pg_stat_statements replaces constants with `$n`
  placeholders in SELECT, INSERT, UPDATE, DELETE and WITH statements. Utility
  statements are tracked too, because `pg_stat_statements.track_utility` is on
  by default. Some utility constants are normalised as well: `CREATE TABLE AS
  SELECT '...'` is stored with `$1`. A role password is not normalised.
  `CREATE ROLE ... PASSWORD '...'` and `ALTER ROLE ... PASSWORD '...'` are
  stored exactly as typed.
- **Why it matters here.** A team deployment's bundled PostgreSQL runs
  role-creation statements with passwords at first start for each component
  role, so those passwords are in the statistics of any database that has the
  extension.
- **pg_stat_activity and statement logs.** `pg_stat_activity.query` and logs
  written with `log_statement` normalise nothing, so their text shows a
  password exactly as it was typed.

# How to apply

- A tool that exports pg_stat_statements text keeps text only for statements
  matching `^\s*(select|insert|update|delete|with)\M` (case-insensitive). For
  every other statement it drops the text and keys the statement by `queryid`.
  The load-ramp collector applies this rule. With the filter, a canary
  `ALTER ROLE ... PASSWORD` run after the extension was created appeared in
  none of its recorded samples.
- When reviewing any tool that exports pg_stat_statements,
  `pg_stat_activity.query` or `log_statement` output, check what it does with
  utility statements. Do not accept "it only reads statistics" as a reason the
  output has no secrets.
- Prove the filter with a canary password in the same run, not by reading
  the regex. This applies
  [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md).

This is one more persistence boundary of the kind named in
[secret history sweeps define their coverage](/aweb-expert/lessons/secret-history-sweeps-define-their-coverage.md):
a credential can sit somewhere that a read-only tool exports.

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-wake-fixes, 2026-11-13;
notes/pg-stat-statements-keeps-utility-statements-verbatim.md. The source ran
the filtered canary on PostgreSQL 16. When harvesting, the harvester ran the
unfiltered case on a throwaway PostgreSQL 17.11 cluster with the default
`track_utility = on`. Canary CREATE ROLE and ALTER ROLE passwords were stored
as typed, and a CREATE TABLE AS literal and a SELECT literal were stored as
placeholders. No real credential is recorded here.
