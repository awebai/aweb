---
type: Lesson
title: Recover partial lifecycle actions from receipts
description: A failed lifecycle command can already have completed irreversible side effects; inspect each effect before retrying.
timestamp: 2026-10-01
---

Retirement may revoke credentials before another hook fails. A retry can then
lack the authority used successfully on its first pass. Preserve original hook
outputs and exact identity/workspace identifiers, and determine which effects
completed before issuing another lifecycle command.

The October 1, 2026 handovers included a retry returning 401 after revocation.
Later exact-ID receipts showed the remote records had already been soft-deleted.
Neither the retry error nor local directory removal alone proved remote state.
Another incomplete retirement left work bytes present but a broken Git admin
link; subsequent attempts failed during inspection before reaching capture.
Repeated attempts could not complete the missed hook.

Track identity deletion, alias release, credential retention, code preservation,
knowledge capture and local cleanup separately. Require the documented structured
release result before disposing of credentials; an authentication error or loosely
matched “not a member” text is not that result. Preserve explicit false and unknown
states. When recovery needs force or a changed preservation plan, return to the
incident's existing authority with concrete evidence rather than assuming the
original clean-retirement authorization still applies.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `partial-retirement-hooks-and-revoked-credentials.md`, `require-alias-release-before-credential-cleanup.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
