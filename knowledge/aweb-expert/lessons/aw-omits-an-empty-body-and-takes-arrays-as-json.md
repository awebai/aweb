---
type: Lesson
title: aw omits an empty request body and takes array parameters as JSON
description: aw's app dispatcher (1.36.59) sends no request body when no body parameter is given, so a naapp route whose body fields are all optional must accept a missing body or real aw users get 422; an array-typed parameter is given as JSON (--labels '["x"]'). In-process route tests always send a body, so only a journey through the released aw shows either.
tags: [lesson, naapp, aw, cli, testing, e2e]
timestamp: 2026-11-27
---

The naapp Tasks app was the first naapp app driven through aw's real app
dispatcher. Its in-process route tests passed. Its end-to-end journey against
the pinned aw 1.36.59 failed twice:

- `aw tasks close --number 1` got 422 "body Field required". The tool's body
  parameters were all optional and none was given, so aw sent no body at all,
  and FastAPI refused the missing body.
- `aw tasks create --labels release` was refused by aw with "expected array
  (JSON)". aw takes an array-typed parameter as a JSON array, not as a bare
  word or a repeated flag.

# How to apply

- **A naapp route whose body fields are all optional must accept a missing
  body.** The fix that worked: `payload: Model | None = Body(default=None)`,
  with a route test that sends no body and was red before the fix.
- **Give array parameters to aw as JSON:** `--labels '["release"]'`. Write
  app docs, examples and journey tests that way.
- **Run the journey through the released aw** for any app whose tools aw
  dispatches. In-process route tests build and sign their own requests and
  always send a body, so they cannot show what aw sends. This is the app-side
  case of [identity and routing review needs the real client](/aweb-expert/lessons/identity-and-routing-review-needs-the-real-client.md).

Elimination route: a shared naapp-lib route convention or test that sends
each optional-only tool with no body would catch this for every app. Whether
aw should send an empty object instead is aw's design question. Until one of
those lands, this is a review and test habit.

**Limit:** observed with one app and one aw release (1.36.59). Recheck when
the pinned aw changes.

Evidence: OKF proposal from aweb-expert/aweb-expert-tasks-app, 2026-11-27;
notes/aw-omits-empty-bodies-and-takes-arrays-as-json.md (naapp PR 61: the
tasks-e2e runs at 511ed010 and 698d3d22 failed as above; green at b2695df5).
