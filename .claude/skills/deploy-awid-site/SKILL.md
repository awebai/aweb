---
name: deploy-awid-site
description: Deploy the awid.ai landing page through the release driver. Use after changing its mirrored docs or site files.
---

# Deploy the awid.ai landing page

The deployed artifact is `awid/site/`, including the repository-owned mirrors
of `docs/identity-guide.md` and `docs/trust-model.md`. The release graph owns
both synchronization and the `deploy-awid-landing` delivery lane.

Use the two-command release train in the `release` skill. Do not invoke the
underlying branch target as a separate hand-maintained procedure; the driver
plans the site node, runs its lane in graph order, and records the result.

Deployment is an outward production action and still requires the applicable
human authorization. After delivery, verify that awid.ai serves the intended
site and both mirrored documents.

The agent guide is served from aweb.ai rather than awid.ai. Resolve current
ownership and review routing from the active team instructions and `aw
workspace status`; never rely on a teammate name recorded in this skill.
