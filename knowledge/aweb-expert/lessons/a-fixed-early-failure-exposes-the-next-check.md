---
type: Lesson
title: A fixed early failure exposes the next unexercised check
description: When a live journey step fails early inside a command, every later check in that command has never run; before asking for the next live run, read the rest of the command's preflight and the target's declared requirements against what the journey passes, and cover the journey's argv with a unit test.
tags: [lesson, testing, journeys, debugging, live-runs]
timestamp: 2026-11-13
---

Observed on 2026-11-13 in the team-deployment journey. `aw` designate reads the
holder export before it checks the request against the role's declared
requirements. One live run failed in the export read (`invalid_shape`). That
was fixed, and the next live run got past the export read. It then failed at
the request check, because the `secrets.owner` role declares
`notice_contact: true` and the journey's designate passed no notice contact.
Both refusals were already in the source when the first run failed. The second
one cost another full live run.

# How to apply

- When a fix moves a live run past a failure, treat every later check in that
  command as unexercised.
- Before asking for the next live run, read the rest of that command's
  preflight. Also read the target's declared requirements (here the app
  manifest's owner acts), and compare both with the arguments the journey
  passes.
- Cover the arguments the journey builds with a unit test. That catches a
  missing argument without a VM. The fix on main (ba2edfad3) names the notice
  contact on designate and adds such a test.

This extends
[reproduce and read the first error before attributing a regression](/aweb-expert/lessons/reproduce-before-attributing-a-regression.md):
read the literal first failure, and remember that the first failure hides the
next one.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/a-fixed-failure-exposes-the-next-unexercised-check.md. The harvester
checked the fix commit on aweb main (ba2edfad3). The live run outcomes and the
order of checks inside designate are source-reported.
