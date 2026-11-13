---
type: Decision
title: OATS supplies the operation id for admit and endorse, and admits spawns unattended
description: OATS's spawn hook admits every spawned agent with team.agent.admit/default from the deployment's root, unattended, and passes its own operation UUID to aw's admit and endorse; owner_approved was rejected for spawns and a server-assigned id was rejected because a killed hook would orphan the operation.
tags: [decision, aw, oats, integration, admission, protected-operations, idempotency]
timestamp: 2026-11-13
---

What OATS needs from aw's admit, endorse and admission-policy commands, as
agreed with OATS for its human-ids work. The contract's rule that the client
chooses and persists an operation UUID before prepare
(`docs/human-assurance-contract.md`) is the general form; this concept records
the integration choices and the alternatives rejected.

# Decision

- **Spawns are admitted root-unattended.** The OATS spawn hook admits with
  `team.agent.admit/default`, run by the deployment's endorsed root with no
  human present. Only the root requests admission; spawners hold no controller
  key.
- **The caller supplies the operation UUID** (`--operation-id`) on both admit
  and endorse. OATS persists it in the new home before prepare.
  - The same UUID with the same inputs resumes and returns the current receipt;
    for admit, the original certificate, with no second quota spent.
  - Changed inputs under the same UUID return `operation_conflict` as a
    `--json` error code.
- **aw stays out of OATS's home layout.** aw writes the certificate to a path
  the caller names; the hook chooses that path and installs the certificate
  itself.
- **The policy read returns version and digest.** The admission binds the
  policy version and digest OATS recorded from `aw id team admission-policy
  --json`, so that read must return both.

# Rejected

- **`owner_approved` for spawns.** It would put a live human prompt on every
  spawn. It may come later for human seats.
- **A server-assigned operation id.** A hook killed between prepare and
  persisting the id would orphan the operation, and its retry would prepare a
  second one.

# How to apply

When changing aw's admit or endorse surface, or answering OATS about it, keep
these properties; a change to any of them is a change to an agreed integration,
not a local refactor.

**Status (checked by the harvester 2026-11-13):** `--operation-id` on admit and
endorse and `aw id team admission-policy` are on the branch
`agents/aweb-expert-owner-acts-admission-policy`, not on main at dfce11678. The
source reports that the commands have not yet passed their real-path tests.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-owner-acts, 2026-11-13;
notes/oats-human-id-commands-requirements.md. The OATS specification version
and its relays are the source's report.
