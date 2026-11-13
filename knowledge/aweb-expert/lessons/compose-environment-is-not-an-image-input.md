---
type: Lesson
title: Compose environment is not an input to an image-backed service
description: A deployment bundle that extends the OATS agent image cannot add container environment on its own; the image accepts an exact list and forwards nothing wholesale, so a new variable needs an agreed image contract for acceptance and propagation before it goes in the bundle.
tags: [lesson, deployment, compose, review, contracts]
timestamp: 2026-11-13
---

A team deployment bundle added `AWID_REGISTRY_URL` to the `environment` of its
agent service, which extends the OATS agent image. The author claimed the bundle
side was correct whatever the image did with the variable. Two independent
reviews passed the bundle diff, and it landed on main (d92a7c40a). The image
refused the container.

The image owner's source trace showed why:

- **Acceptance.** The image supervisor accepts an exact environment list: its
  own variables plus the two CA variables. Any other variable refuses the
  container.
- **Propagation.** Even an accepted variable does not reach the agent's work.
  The image forwards nothing wholesale: SSH sessions build a fresh environment,
  login capture starts from a fixed seed, and oats.aweb strips the AWID
  variables it owns from harness launches.

None of this is visible in the bundle. A review that reads only the Compose
diff cannot catch it, however careful it is.

# How to apply

- Before you add environment to a service that extends someone else's image,
  check two things with the image's owner: that the image accepts the variable,
  and how its value reaches the process that needs it.
- Do not claim "the bundle side is correct either way". For an image-backed
  service, the bundle side is only correct if the image's contract admits it.
- When a variable is needed, agree the image contract first, then change the
  bundle. For the team registry the agreed contract (2026-11-13) has three
  parts:
  - one exactly-accepted variable;
  - a validated runtime data file that the image's immutable profile reads;
  - the harness launch environment, for the harness.
- As a reviewer of such a diff, ask for the image's acceptance and propagation
  evidence; a green bundle test is not that evidence.

This refines
[acceptance must exercise the claimed operation](/coordinator/acceptance-must-exercise-the-claimed-operation.md)
for image-backed deployments: the operation is the container starting and the
value arriving where it is used, not the Compose file parsing.

# Elimination route

The fix (eea14a7c5, on main) removed the variable. It also replaced the test
that asserted the variable was present with
`test_the_agent_passes_no_environment_the_image_does_not_accept` in
`server/tests/test_team_deployment_compose.py`. That test guards this one
service against any `environment` key. A guard that reads the image's published
acceptance list would also cover future accepted variables and other
image-backed services. Until one exists, this lesson carries the rest.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-team, 2026-11-13;
notes/compose-env-is-not-an-image-input.md. Commits d92a7c40a and eea14a7c5 and
the guard test were checked on main by the harvester. The rest is
source-reported and was not reproduced: the image owner's source trace at image
b2acd1e89 (mail b397a322), the fix's review ACK (9f01c2d2) and the registry
contract threads (546c7a8f, bd2f8b86). The trace was a source reading, not a
native runtime run.
