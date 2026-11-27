---
type: Lesson
title: Schema checks must not depend on collation
description: information_schema names sort in the C collation whatever the database default, so an ordered comparison of a table's column names against a literal list passes on a C-collated database and fails on a glibc or ICU en-US one; compare the sets, or put COLLATE "C" on both sides, and reproduce with an ICU 'en-US-u-ka-shifted' database.
tags: [lesson, postgresql, sql, testing, ci, migrations]
timestamp: 2026-11-27
---

A schema guard that compared a table's column names, in order, against an
expected list passed locally and failed in CI with the same thirteen columns
found as expected. Only the order differed.

# Why

- `information_schema.columns.column_name` is `sql_identifier`, a domain over
  `name`, and `name` sorts in the C collation. Its `::text` keeps that
  collation. Text from anywhere else, such as a literal or a jsonb value,
  takes the database default.
- Under glibc `en_US.utf8`, or ICU with punctuation ignorable
  (`en-US-u-ka-shifted`), the `_` is skipped at the first level, so
  `answered_at` and `answer_key` sort differently than they do in C.
- macOS libc `en_US` and plain ICU `en-US` both sort these names like C. A
  local PostgreSQL that is C-collated, or uses either of those locales, proves
  nothing about ordering.

# How to apply

- Compare names as sets: containment both ways, or `EXCEPT` both ways, so
  that order cannot matter. Where order truly matters, put `COLLATE "C"` on
  both sides.
- To reproduce, restore the real schema into a database created with
  `LOCALE_PROVIDER icu ICU_LOCALE 'en-US-u-ka-shifted'`. Confirm the old check
  goes red there before trusting the fix, and keep that restore as a
  regression test.
- This refines [a harness must be shown to fail](/aweb-expert/lessons/a-harness-must-be-shown-to-fail.md):
  a green under the wrong collation is not evidence.

Limits: seen in one data move on one engine (PostgreSQL 17).

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-move, 2026-11-27;
notes/information-schema-names-sort-in-c-collation.md. naapp PR 65 (board
move): the first CI run failed at 3c5e8cfd on postgres:17 with `en_US.utf8`.
It was reproduced on an ICU `en-US-u-ka-shifted` database and fixed by set
comparison at 3e80b9d4.
