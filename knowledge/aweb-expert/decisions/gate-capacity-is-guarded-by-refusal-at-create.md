---
type: Decision
title: Gate capacity is guarded by refusal at create
description: The gate dispatcher guards provider capacity by treating a refused create as the answer, not by a quota pre-check, because the Hetzner Cloud API exposes no quota and a project token cannot see other projects; inventory by label, create once, report resource_limit_exceeded with no retry or type fallback, and reconcile uncertain creates by label.
tags: [decision, gates, infrastructure, hetzner]
timestamp: 2026-11-11
---

Recorded with the per-run VM decision of 2026-11-11:
[every full gate runs on its own VM](/aweb-expert/decisions/full-gates-run-on-per-run-vms.md).

# Decision

- **No quota pre-check.** The guard is the provider's own refusal at create
  time.
- **Inventory by label** before and after a run. An API error is not an empty
  list.
- **Create once.** Treat `resource_limit_exceeded` as a capacity refusal and
  report it clearly. Do not retry, and do not fall back to another server
  type.
- **Reconcile an uncertain create by its label** (for example a timed-out
  create) before anything else is tried.
- **Prove a limit raise with a create the old limit would refuse**, deleted
  at once. A larger server type created and deleted was the proof used.

# Why

- Hetzner's Cloud API has no limits or quota endpoint (the hcloud SDK 2.27
  has none), and a project token cannot see servers in the account's other
  projects. The dedicated-vCPU limit is account-wide, so a "global pre-create
  check" cannot be written.
- `resource_limit_exceeded` does not name the dimension that was exceeded, so
  a type fallback would guess, and could hide that capacity is gone.

# Rejected

- **A quota pre-check before create.** It cannot work with this API: it would
  read a number that does not exist, or count only one project.

Every cloud provider limits new accounts in a similar way, so changing
provider does not remove the need for this guard.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-testing-servers,
2026-11-11; notes/gates-move-to-vms-2026-11-11.md,
notes/ephemeral-vm-gate-findings.md and
notes/gate-capacity-provider-options-2026-11-10.md. The API limits and the
create probe are the source's report; the harvester did not check them.
