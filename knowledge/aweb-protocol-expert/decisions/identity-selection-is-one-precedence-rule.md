---
type: Decision
title: Identity selection is one precedence rule
description: Every aw command selects its principal the same way (--identity-home, else AWEB_IDENTITY_HOME, else the current directory's .aw) and a selected folder never falls back to the current directory; a per-command allowlist was removed as "not security", and the peer trust store stays user-level.
tags: [decision, aw-cli, identity, oats, security]
timestamp: 2026-10-19
---

Ruled by the operator on 2026-10-19, after `aw team invite` refused to run for
OATS-attached agents. An earlier change had default-denied every command run
with an external identity home unless it was on an "identity-home-aware"
allowlist; shipped features silently disappeared for attached agents whenever
the list lagged the product. The operator: "always give priority to the env
variable defining the identity folder. If that is set up, that defines the
identity, period. If not set up, the current folder is. That's it. No lists of
commands; that is not security."

# Decision

- One precedence rule for every command, in one resolver: the flag, then the
  environment variable, then the current directory's `.aw`.
- A selected folder that is missing, unreadable, wrongly owned or incomplete
  fails with an error naming it; it never falls back to the current directory.
- Identity-creating commands run with a selected identity never create into or
  extend that inherited folder: with no explicit target they refuse when it
  already holds an identity, and with one they create only there. OATS sets the
  variable for everything an agent runs, so anything else would overwrite the
  agent's identity.
- Identity state (signing key, did, certificates, memberships, grants, own
  continuity) lives only in the selected folder; workspace state (the checkout's
  binding, repo, presence) stays with the checkout, so two worktrees of one
  identity do not collide.
- The peer continuity pins (`known_agents.yaml`) are the machine user's trust
  store, not the acting principal's identity: no move, copy or migration.
  Per-principal pins come only if a concrete attack is shown, as a design
  decision for the operator.

# Rejected

- **A per-command allowlist with default deny.** It granted no protection the
  resolver did not, and removed shipped features from attached agents.
- **Migrating peer pins into the identity folder.** No backward-compatibility
  code without the operator's explicit approval.

`docs/cli-identity-selection.md` describes the current rule and file
classification; this records why it is one rule.

# Provenance

Harvested 2026-10-25 from seat `aweb-protocol-expert-agent-activity` (log of
2026-10-19; coordinator relays bef1f53c, 0b627a17 and d34cd563; security
reviewer 8b22dd8a and 2e94961d).
