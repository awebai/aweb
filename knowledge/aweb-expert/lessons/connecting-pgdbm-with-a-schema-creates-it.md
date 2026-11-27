---
type: Lesson
title: Connecting pgdbm with a schema creates the schema
description: An AsyncDatabaseManager configured with a schema runs CREATE SCHEMA IF NOT EXISTS on connect, so connecting to a schema to check whether it exists creates it, and a role without CREATE on the database cannot connect at all even when the schema exists; check existence through another schema's connection, and grant CREATE or connect without a schema.
tags: [lesson, pgdbm, postgres, schemas, privileges, tooling]
timestamp: 2026-11-27
---

# The discovery

pgdbm's `AsyncDatabaseManager`, configured with a `schema`, runs
`CREATE SCHEMA IF NOT EXISTS` when it connects. Two consequences cost a
debugging round each in naapp operator tooling:

- **Connecting to check is creating.** A command that connected "to" an
  optional staging schema and then asked whether it existed always got yes.
  On a missing schema it raised a missing-relation error instead of refusing,
  and a probe left an empty schema behind in a local database. It was found
  only because a subprocess test asserted the refusal text; the in-process
  tests never connected to a missing schema.
- **Connecting needs CREATE on the database.** The statement is checked
  against the database's CREATE privilege even when the schema already
  exists, so a least-privilege role fails with "permission denied for
  database" before it can run anything.

# How to apply

- Check whether an optional schema exists through a connection pinned to
  another schema (for example the live one), and name the optional schema's
  tables explicitly. Never connect to a schema in order to ask whether it
  exists.
- For a least-privilege role, either grant CREATE on the database or use a
  manager without a schema and qualify every table.
- The elimination route is a pgdbm option not to create the schema on
  connect. pgdbm is the operator's own library, so whether to add one is the
  operator's call.

Pool sizing for one-off tooling is a separate pgdbm default, recorded with
the shared-host connection limit rather than here.

# Evidence

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-move, 2026-11-27;
notes/pgdbm-connect-creates-the-schema.md.
Checked by the harvester: naapp commits 0211253a and ee1e936f, in naapp merge
6df1df3c, where the board-move tooling checks the staging schema through the
live schema's connection. The pgdbm connect behaviour, the phantom schema and
the permission error are source-reported. Observed with pgdbm as pinned in
naapp at e2449562.
