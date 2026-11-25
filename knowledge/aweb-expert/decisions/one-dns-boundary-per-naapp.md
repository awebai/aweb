---
type: Decision
title: One DNS boundary per naapp, shared by the egress guard and AWID lookups
description: Without explicit nameservers the naapp egress guard resolves through dnspython's process default resolver, the same boundary as the app's AWID TXT lookups, so a test can point the whole app at one DNS server; no nameserver setting and no create_app(egress=...) parameter. AWID refuses IP-literal team-server origins in every environment, so test worlds publish the team server under a name.
tags: [decision, naapp, egress, dns, awid, testing]
timestamp: 2026-11-25
---

Option approved by the naapps lane lead (ruling 89da2ac6) and landed in naapp
PR #45 (merge 2aa09370, "Egress guard resolves through the process default
resolver").

# Decision

- The egress guard's `DnsResolver` **without nameservers** asks dnspython's
  process default resolver at each query. That is the same resolver the app's
  AWID `_awid` TXT lookups use, so an app has one DNS boundary.
- **With explicit nameservers** the guard keeps its own resolver, as before. A
  port belongs to explicit nameservers only; a port without nameservers is
  refused. The guard never sets anything on the shared default resolver.
- Production behaviour is unchanged: the default resolver is built from the
  same system configuration the guard's private resolver used.

# Why

In-process test worlds must publish the team server under a name, and the
guard's private resolver could not be pointed at a test DNS server. Setting
dnspython's default resolver reached AWID lookups but not team-server egress.

The tempting shortcut is closed: **AWID refuses IP-literal team-server
origins in every environment.** Publishing a team-server record runs its
origin through `validate_delivery_origin`, which refuses any literal IP with
`server_url_invalid` under production and test settings alike. Do not try an
IP-literal origin to avoid DNS in a test world.

# Rejected

- **An operator nameserver setting.** It adds a product settings surface
  mainly to serve tests.
- **A `create_app(egress=...)` parameter.** It makes a contrived production
  composition for the sake of tests.

# Consequence

The process default resolver is now part of the egress guard's trust
boundary: whatever replaces or reconfigures it in a process also steers the
guard's address checks. Code that swaps the default resolver outside a test
is changing egress policy, and is reviewed as such.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-25; notes/egress-resolver-is-not-dnspython-default.md. The harvester
read naapp PR #45 (merged at 2aa09370), whose description states the option,
the two rejected alternatives, the AWID refusal and the red-first tests. The
AWID refusal was verified by the source under both production and test
settings; the lane-lead ruling is source-reported.
