---
type: Decision
title: vm-gate guests keep their per-run Postgres containers
description: The operator's 2026-11-28 rule that tests use the host's own PostgreSQL instead of per-run containers covers local runs on hosts, not runs inside a vm-gate guest; the guest is itself the throwaway, so its per-run postgres containers stay and no vm-gate change follows from the rule.
tags: [decision, testing, postgres, vm-gate, environment, scope]
timestamp: 2026-11-28
---

# Decision

On 2026-11-28 the operator ruled that tests use the host's own PostgreSQL,
with databases created by pgdbm's test fixtures, and not per-run Postgres
containers. That rule is about local test runs on the team's hosts.

It does not cover runs inside a vm-gate guest. There the guest is the
throwaway, so per-run Postgres containers stay as they are. This includes:

- aweb's test-egress `postgres:17` container;
- the pilot's gate container;
- the databases of the servers rehearsals.

aweb's candidate gate and test-egress are outside the rule's scope. No
vm-gate change follows from it.

# Why

Seats relaying the rule read it as covering the gate VM, and asked vm-gate to
provide "the VM's own Postgres". The guest base disk has no postgresql or
redis package, and no host service may reach the VM. That reading would have
meant building a new base disk and changing the launcher for nothing, since
the guest is discarded after every run anyway.

# How to apply

When a seat cites the host-Postgres rule to move a gate run off its per-run
containers, check where the run happens first. In a vm-gate guest, keep the
existing path and do not rebuild the guest. The rule's host route (the
repository's host test-database settings, such as `TEST_DB_HOST` and
`TEST_DB_PORT`) is for runs on a host.

After this ruling, the A2 untimed proof ran green inside the guest on per-run
`postgres:17`, twice.

# Acceptance

The scope comes from coordinator rulings of 2026-11-28, relayed by aweb mail,
including a relay through another seat: **source-reported**. The operator's
own text of the original rule was not seen by the source, so the scope is the
coordinator's reading of it. If the operator states a different scope, that
statement supersedes this decision.

Evidence: OKF proposal from aweb-expert/aweb-expert-gate-dispatch, 2026-11-28; notes/vm-guest-postgres-scope.md.
