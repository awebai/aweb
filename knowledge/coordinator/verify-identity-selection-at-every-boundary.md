---
type: Lesson
title: Verify identity selection at every process boundary
description: An explicit identity selected in one layer does not automatically scope subprocesses, streams or later lifecycle operations.
timestamp: 2026-10-01
---

Test the full path using a caller home and selected external home with
intentionally different credentials and teams. Verify actual requests and
unchanged unrelated state, rather than checking only the installed files or a
command allowlist. Admission, resolver selection and service authorization are
separate boundaries.

The September 2026 investigations found a reconstructed identity-home object
that lost selection provenance, a correctly scoped JavaScript client whose CLI
decrypt fallback used the terminal default, and a consumer's team selection that
did not reach its upstream event stream. A local root path alone was therefore
insufficient evidence of the acting principal.

Carry selection explicitly across each boundary; avoid process-global mutations
shared by concurrent consumers. Test allowed and denied calls with empty and
shadow caller homes, distinct teams, and no fallback to a more powerful
credential. Cover acceptance, ordinary operation and supported cleanup together.
Fallback fetch instructions must retain locally trusted receiving-binding context;
a message ID or sender-supplied path cannot choose the recipient's credential home.

## Provenance

Harvested from the coordinator’s September–October 2026 handover notes: `binding-client-does-not-scope-cli-fallback.md`, `identity-home-root-without-provenance-selects-caller.md`, `consumer-team-does-not-scope-event-stream.md`, `identity-home-command-allowlist-is-not-scope-support.md`, `wake-fetch-hints-need-receiving-identity-context.md`, `grants-need-complete-acting-principal.md`, `hosted-grant-custody-attachment.md`. The preserved notes and archived sessions retain the detailed incident receipts; this concept records the reusable conclusion, not a current implementation inventory.
