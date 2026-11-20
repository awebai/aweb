---
type: Lesson
title: A naapp trusts exactly one AWID registry
description: aweb_naapp verifies every team against one configured registry and refuses a team whose _awid TXT selects another, unlike the server's cross-registry path, so a shared naapp makes the vendor registry mandatory for BYOT teams with their own; the fix follows the TXT per team with no fallback.
tags: [lesson, naapp, awid, registry, byot, dns, decentralization]
timestamp: 2026-11-08
---

The naapp runtime verifies teams against one registry, set by
`awid_registry_url` (default `https://api.awid.ai`). It looks up a team's
`_awid` DNS TXT record only to refuse a team whose record names another
registry, with `registry_mismatch`. The server's cross-registry path does the
opposite: it selects the registry from the `_awid.<domain>` record
(`docs/awid-sot.md`, "Cross-registry consumption").

Verified on main e7ae65cd7: `naapp-lib/src/aweb_naapp/runtime/settings.py`
(the setting), `runtime/team_auth.py` (one registry origin in the team cache)
and `runtime/team_server.py` (`_require_verifier_registry`).

# Why it matters

BYOT lets a customer select its own registry through DNS, and `awid/` is open
source and self-hostable. A naapp shared by several teams therefore makes the
vendor registry a hard dependency for those customers. It is the first real
vendor-central dependency in naapp authorization, and it fails test A of
[nothing requires a vendor-central server](/aweb-protocol-expert/decisions/no-vendor-central-server.md).
The registry check itself carries the revocation guarantee and stays.

Do not answer "does aweb need our registry?" from the server's behaviour; for
naapps the answer today is yes.

# The fix, and the tempting wrong one

- Follow the TXT selection per team through the strict external resolver
  (`awid/src/awid/external_registry.py`), as the server does. Absence of a
  record selects the canonical public registry. Malformed, multiple,
  timed-out or failed discovery refuses and never falls back
  (`docs/awid-sot.md`).
- Resolve only for teams installed in the naapp, so unauthenticated input
  cannot drive DNS and registry lookups
  ([unauthenticated input must not drive remote work](/aweb-protocol-expert/lessons/unauthenticated-input-must-not-drive-remote-work.md)).
  Validate the registry origin.
- **Do not copy the awid client's write-routing helper** in
  `awid/src/awid/registry.py`. On a failed DNS lookup it logs and returns the
  configured registry. That is fine for routing writes, but in a verifier a
  DNS failure would silently select the vendor registry.

# Provenance

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-secrets-docs, 2026-11-08; notes/naapp-trusts-one-registry.md.
The harvester checked the cited code and documentation on main e7ae65cd7.
