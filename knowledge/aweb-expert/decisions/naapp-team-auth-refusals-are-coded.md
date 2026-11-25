---
type: Decision
title: naapp team-auth refusals are coded
description: naapp-lib's team-auth refusals answer detail {"code", "message"} with unchanged statuses, reusing names that already exist in the server and awid; awid verifier text is never mapped to finer codes, the coded detail reaches the handoff and owner-act routes with no transition path for released aw, and released bare-string writers stay bare.
tags: [decision, naapps, team-auth, refusals, contracts]
timestamp: 2026-11-24
---

Ruled by the naapps coordinator (ruling 05d8c81d, with conditions 2fe75060 and
approval e7d479f2) for task aweb-advy, 2026-11-25 by the source's clock. The
naapps lane lead chose the released-client handling in c5093f07. These are
lane-lead rulings, source-reported; no human acceptance is claimed.

# The decision

- Every refusal from naapp-lib's team auth (`runtime/team_auth.py`) answers
  `detail = {"code": ..., "message": ...}`. Statuses do not change. Callers
  branch on the code, never on the message.
- **A code reuses an existing name wherever one exists**: the server's
  `certificate_revoked` and `unknown_team`, awid's `team_key_unverified`,
  awid's typed `TeamCertificateReason` as `certificate_<reason>`, and
  `authority_unavailable` (503) for awid's typed `invalid_team_key`. Only
  refusals with no existing name get a new one.
- **Every error from awid's request verifier answers `signed_payload_invalid`**,
  with awid's text as the message. naapp does not read that text to pick a
  finer code. Finer codes wait until awid raises coded errors (aweb-adwy).
- **The coded detail also reaches the routes that pass team-auth refusals
  through**: the session handoff start and owner-act verification. There is no
  transition layer keeping prose or bare strings on those routes.
- **Released bare-string writers stay bare**: the console, owner act, handoff
  and human-member refusals that are already released are not converted.

# Rejected

- **Mapping awid's verifier prose to codes.** It would make naapp depend on
  another component's wording, which is the coupling that coding the refusals
  removes. The codes belong in awid.
- **Inventing names where the server or awid already has one.** Two names for
  one refusal across the stack make every client learn both.
- **A translation layer that keeps the old detail on the handoff and owner-act
  routes (option B).** The lane lead chose no transition path because naapps
  have no users yet. Released aw branches only on `applied_earlier` and
  `console_session_required`, and team auth produces neither, so no released
  client changes behaviour.

# What released aw shows

aw's handoff client (`cli/go/internal/handoff/client.go`, `RefusalCode`) takes
the code only from a string `detail`, and only when it is a single token of at
most 64 characters. Otherwise it prints `handoff_http_<status>`. Prose
refusals already fell through to that generic code. A refusal that used to be
a single token, such as a removed member's `"revoked"` on handoff start, now
does too, until aw reads `detail.code` (aweb-adwb). Only the printed reason
changes, so this is display, not behaviour. It is accepted narrowly under
[released clients are a permanent constraint](/aweb-protocol-expert/decisions/released-clients-are-a-permanent-constraint.md):
no released client branches on the changed values. A future change that
alters a value aw branches on does not get this exemption.

# How to apply

- A new team-auth refusal gets a code. Look for an existing name in the server
  and awid before making one up.
- Do not parse awid verifier messages. If a finer code is needed, raise it in
  awid.
- Do not convert the released bare-string writers as a side effect of
  team-auth work. They change only as their own decision.

Evidence: OKF proposal from aweb-expert/aweb-expert-naapp-folio-links,
2026-11-24; notes/advy-plan.md. The harvester checked the code table and the
"wire change beyond team_auth's own routes" section in the description of
naapp PR #43 (open at harvest, head c649cd61 green in run 45551472492), and
`RefusalCode` on aweb main.
