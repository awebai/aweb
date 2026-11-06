---
type: Lesson
title: Review requests carry their content
description: aw mail is per-recipient, so a reviewer cannot open mail that was sent to the coordinator; a review request pastes the referenced content instead of citing a message id, and message ids are only ever cited as captured from tool output.
timestamp: 2026-10-23
---

Three times in one week a review stalled because the request cited a message
the reviewer could not open: mail sent to the coordinator, or between author
and security reviewer, is not visible to anyone else, and `mail show` reports
it as not found. Separately, a coordinator cited a message id it had typed from
memory, and another rebuilt a full id from its eight-character prefix; both were
wrong.

## How to apply

- When a review depends on someone else's mail, paste its body into the
  request, or have its author send it to both parties. Never just name the id.
- Cite only message ids captured from tool output. Never reconstruct an id from
  its prefix, and do not suppress aw's stderr on sends; confirm "Sent mail".

Related: [resolve full review anchors before integration](resolve-review-anchors-before-integration.md),
which applies the same discipline to commit ids.

## Provenance

Harvested 2026-10-25 from the `integrations` coordinator seat (note
`review-requests-carry-content.md`; log of 2026-10-18 and 2026-10-21), the
`naapps` coordinator seat (Claude memory `aw-message-ids.md`) and the
`secrets` coordinator seat (note `team-quality-rules.md`).
