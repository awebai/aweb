---
type: Decision
title: Agent human names are explicit metadata
description: An agent identity gets a human_name only from explicit input, never from the machine account or environment; identities whose effective type is human keep their existing name defaults, and existing identities are not migrated.
tags: [decision, aw-cli, identity, human-name, agent-type]
timestamp: 2026-11-08
---

Accepted by the operator on 2026-11-08 (task aweb-abuc). The acceptance is
**source-reported**: the OSS coordinator relayed it and recorded it in the
task; no independently readable acceptance record exists. The coordinator's
scope clarifications came by mail (9a2329a7 and c9a7c631).

**Status (2026-11-08):** accepted product boundary. The implementation was
awaiting independent review and landing when this was recorded; nothing here
claims released behaviour.

# Decision

- An identity whose effective `agent_type` is an agent receives a
  `human_name` only from explicit input. No machine-derived value fills it:
  not `AWEB_HUMAN`, `AWEB_HUMAN_NAME`, `USER`, nor a hard-coded developer
  fallback. With no explicit input the name is empty.
- An identity whose effective `agent_type` is `human` keeps its existing
  environment fallbacks, and the human-only `id human init` path is
  unchanged. Classification follows the effective type, even when the
  identity is created through a CLI path shared with agents; a file or
  command name containing "human" does not make the result human.
- Existing identities are not migrated, cleaned up or backfilled.
- Reconnect keeps its existing overwrite semantics. For an agent it now
  writes the empty value instead of the machine-derived one; that is
  intended.

# Why

A machine login is not a chosen human name. A reader of `human_name` cannot
tell a machine label from a name someone chose, so a convenient default
quietly presents an account name as a person's identity.

# Rejected

- **Deriving an agent's human name from the machine account or environment**
  (the prior behaviour). Do not reintroduce it as a convenience default.
- **Preserving a previously stored name across reconnect.** Declined by the
  coordinator as a scope expansion beyond this decision.

# Related

[Humans use mail; recipient kind is authoritative](/aweb-protocol-expert/decisions/humans-use-mail.md)
classifies human recipients by authoritative type, not labels. This decision
applies the same principle to naming and does not change that messaging rule.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-agent-human-name,
2026-11-08; notes/agent-name-defaults.md.
