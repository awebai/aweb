---
type: Decision
title: The outbound federation switch sits at the delivery choke point and fails closed
description: AWEB_FEDERATION_OUTBOUND is enforced first in deliver_federated_message, before the transport, with a 403 naming the setting; an unreadable value fails closed; registry reads are not governed; enforcing in the transport, threading it through MessagingRuntime and gating registry reads were rejected.
tags: [decision, federation, security, egress, architecture]
timestamp: 2026-11-13
---

**Status (2026-11-13):** implemented on a branch (task aweb-aczg, head
`0de24f3ef`) under security review; not yet on main. If the review moves the
check, this concept must be superseded to follow the landed code.

# Decision

`AWEB_FEDERATION_OUTBOUND` controls whether the server sends federated mail
and chat to other servers: unset or empty leaves delivery unchanged, `off`
sends nowhere, and a comma-separated list of origins sends only to those,
compared as `canonical_server_origin`.

- **Where.** The check is the first thing in
  `federation/mail.deliver_federated_message`, before the transport is
  touched. A refusal is a 403 naming the setting, raised before any lookup
  of or connection to the delivery origin.
- **Why there.** It is the single place outbound bytes leave the server.
  Two existing structural tests pin it as the choke point
  (`test_one_module_makes_destination_named_requests` and
  `test_every_server_caller_passes_the_delivery_transport`), so every caller
  (REST, MCP, continuations) is covered, and a new caller has to break a
  pinned test to get around it.
- **Fail closed.** It is a data boundary. An unreadable value refuses
  start-up, and an embedding host that never loaded settings still refuses
  every send.
- **Scope.** Registry reads are not governed. "Before any network call" means
  before resolving or connecting to the delivery origin; the registry lookup
  that learns the origin necessarily comes earlier.

# Rejected

- **Enforcing in the transport** (the address-checked transport). A
  host-set transport, as embedding hosts and tests use, bypasses it, and a
  refusal there reaches the sender as a 502 transport refusal rather than as
  the operator's 403.
- **Threading the policy through MessagingRuntime.** More surface for the
  same effect, and against config's convention of reading the environment at
  call time.
- **Gating registry reads.** The registry is needed for every recipient
  resolution, local ones included, and a registry read is not data leaving to
  another server's delivery origin, which is the boundary.

# Why it is recorded

A later change to outbound federation (a new send type, a new transport, a
deployment egress policy) needs to know where the boundary is enforced and
why not in the transport, or a "simplification" moves the check somewhere a
host-set transport bypasses.

# Evidence

The change answered the 2026-11-12 deployment review's finding that the
server relays data outside the egress boundary. RED: with the switch off, a
real delivery through the mail route reached a loopback listener (200, one
connection). GREEN: `off` and unlisted origins answered 403 with zero lookups
and zero connections; listed and unset origins delivered. The harvester
checked the check's position, the 403 refusal and the fail-closed read
against the branch head.

Evidence: OKF proposal from aweb-expert/aweb-expert-wake-fixes, 2026-11-13;
notes/outbound-federation-switch-sits-at-the-delivery-choke-point.md.
