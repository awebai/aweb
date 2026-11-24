---
type: Decision
title: A real agent wake is proved occasionally, not on every run
description: The per-run deployment lab journey stops at "agents held" and spends no credential or model turn; a separate opt-in command proves a real agent wakes on a verified mail, before and after a reboot, at release qualification and before each customer install, taking the harness credential by path and name only and each use agreed with the operator first.
tags: [decision, deployment, testing, agents, credentials, cost]
timestamp: 2026-11-24
---

Decided by the operator on 2026-11-24 for the team deployment's lab journey.

# Decision

- The journey that runs on every lab run ends at "agents held". It uses no
  harness credential and spends no model turn.
- A separate command, never run by default, proves a real agent: it is
  admitted, gets a session, wakes on a verified mail and answers, and wakes
  again after a reboot.
- That command runs at release qualification and before each customer
  install, not on every run.
- It takes the harness credential by path and name only, refuses clearly when
  the credential is absent, and leaves nothing behind on the disposable guest.
  Each use is agreed with the operator first.

# Why

A model turn and a harness login on every lab run cost credential exposure
and spend, and add no evidence between releases. The wake matters at the two
points where a deployment is about to be trusted: a release, and a customer's
install.

# How to apply

- Do not add a credential, a login or a model call to the per-run journey to
  make it "more complete". The per-run journey proving less than a real wake
  is deliberate.
- A release qualification or customer install that has not run the wake
  command has not proved that agents wake. Say so rather than citing the
  per-run journey.

# Acceptance

Source-reported: the operator's decision of 2026-11-24, relayed by the
deployment coordinator in mail aaf50d9e. The harvester could not read the
mail.

# Provenance

Evidence: OKF proposal from aweb-expert/aweb-expert-deploy-repo, 2026-11-24;
notes/real-agent-check-is-occasional.md.
