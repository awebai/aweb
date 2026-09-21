---
type: Decision
title: The signed request target is the external path
description: The team-auth envelope signs the actual external request target, mount prefix included; the verifier reconstructs it from the ASGI raw path and re-prepends a root path only when the path lacks it, so one verifier is conformant to the unmounted vector and correct behind a mount without any prefix stripping.
tags: [decision, team-auth-envelope, events, app-emit, conformance]
timestamp: 2026-06-18
---

Locked by the OSS coordinator role on 2026-06-18 after the first end-to-end
app-emit landed, and after two coordinators had argued from theory that the
verifier reconstructs the mount-internal path and that emitters must be changed
to sign it. The live emit, the source and the guard test settled it the other
way. Verified against source on 2026-09-21 by the OATS steward:
`raw_request_target` in `server/src/aweb/team_auth_envelope.py` reads the ASGI
`raw_path` (the full external wire path, which a mount leaves intact while it
strips `path`), decodes it, and prepends `root_path` only when the path does
not already start with it; `server/tests/test_team_auth_envelope.py` covers
the mechanism.

# Decision

- The signed path is the external request target as the client sent it. Behind
  a mount that is the mounted path; unmounted it is the bare route.
- The conformance vector for app-emit signs the unmounted route and is a
  byte-parity fixture for the unmounted case, not a mandate for every
  deployment. Confirm the fixture's current location under `test-vectors/`
  before citing it; the file was renamed after this decision was recorded.
- Neither the verifier nor the emitters are changed to strip or add a prefix.

# Rejected

Changing emitters to sign the internal route, or changing the verifier to strip
the mount prefix: both would re-break a proven path and require re-freezing the
vector for no interoperable gain.

# Consequences

Where a specific deployment mounts the API, its concrete external path is that
deployment's fact and lives with its owner; this decision states only the
interoperable rule.
