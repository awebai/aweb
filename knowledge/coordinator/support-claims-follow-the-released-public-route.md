---
type: Decision
title: Support claims follow the released public route
description: Before claiming aweb supports a third-party runtime, install it from scratch exactly as the published instructions say, using only released software and the public service; any gap is a bug fixed and rerun from scratch, an unreleased dependency is fixed and released by its owner rather than routed around, and support copy waits for that run.
timestamp: 2026-10-19
---

Ruled by the operator on 2026-10-19 while support for a third-party agent
runtime was being validated: "we need to make sure that the instructions work,
and that all the software released is up to date for hermes to work". When the
route turned out to need an unreleased fix, he refused a workaround: "no wait
until theuy sort it for you", and "please finish this correctly and without
workarounds".

Reading and pinned-commit tests had missed real problems: the installer had
never been run end to end, the third party's latest release was far behind the
tested pin, and the instructions gave no way to obtain the pinned version.

## Decision

- Install from scratch exactly as the instructions say, with the published aw,
  the third party's latest release (not a pinned commit) and the public
  service, using a disposable test agent.
- Any instruction gap is a bug: fix it, then rerun from scratch.
- If the route needs an unreleased dependency, stop and have its owner fix and
  release it. Do not route around it, even through a supported alternative,
  because a workaround hides the gap a real user would hit.
- Site or README support copy waits for that run to pass.

## Rejected

- Claiming support on the pinned commit that tests had used.
- Completing the run through an alternative admission route that ordinary
  users would not take.

Related: [separate publication, installation and live adoption](separate-publication-installation-and-adoption.md).

## Provenance

Harvested 2026-10-25 from the `integrations` coordinator seat (note
`hermes-support-findings.md`; Claude memory `no-workarounds-wait-for-fix.md`;
operator turns of 2026-10-19T04:41Z and 05:58Z in its session transcript).
