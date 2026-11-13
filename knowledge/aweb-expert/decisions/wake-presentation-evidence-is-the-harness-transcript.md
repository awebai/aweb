---
type: Decision
title: Wake presentation evidence is the harness transcript
description: To prove a Claude session received a wake broker's presented event, find the user turn holding the full event text in Claude's own transcript; the pane is secondary, and a submit receipt, inbox read, ID-only or held notice, or send receipt proves nothing.
tags: [decision, wake, evidence, claude, oats, testing]
timestamp: 2026-11-13
---

Agreed on 2026-11-13 by the aweb-expert seat qualifying wake delivery, the
OATS expert (who supplied the transcript rule and the sign-in signal from OATS
source, not from a run) and the servers and deploy-team seats (who set the trust
split). Every later wake qualification needs the same proof: other images, other
harnesses, the load ramp, a real model wake. The easy proxies all over-claim,
and reviewers and owners rejected each of them here.

# Decision

**The evidence** that a Claude session received a broker-presented event is the
user turn in Claude's own transcript that holds the full event text: header,
message id, sender, trust status, verified flag and exact body.

- **Which transcript.** Use OATS's last-conversation rule: the newest JSONL
  under `$CLAUDE_CONFIG_DIR/projects` whose recorded `cwd` is the instance
  home's realpath, modified after the instance record's `createdAt`. Match on
  the `cwd` inside the file, not on the encoded directory name. A session whose
  `cwd` is `<home>/work` belongs to a helper, not to the instance.
- **Say what it rests on.** This reads Claude's own storage, not an OATS or
  aweb contract, so a receipt built on it says so.

**Not evidence** (each was proposed and rejected):

- The broker's submit receipt. OATS `submitted: true` means tmux accepted the
  paste and Enter, not that the model saw the event.
- An inbox read, an ID-only or held notice, or a send receipt.
- The pane on its own. Claude Code can collapse a long paste into a
  `[Pasted text #N +M lines]` placeholder, so a pane capture can miss a block
  the session did receive. The pane is secondary evidence.

# Consequences

- **Check sign-in first.** OATS has no state for a pane sitting at Claude's
  sign-in screen: the instance reads as running there too. Every launch submits
  a task, so a signed-in session writes a transcript within seconds of launch.
  No transcript after launch means the session is at sign-in or never started:
  send nothing, so nothing is typed into a sign-in prompt.
- **It costs a model turn.** The event is typed into a live session. Write the
  test mail as "no action needed", detect delivery from the transcript, and do
  not require a reply.
- **Trust is split.** The presentation check asserts only that presentation is
  never promoted to verified. Transport trust is a separate live CA negative in
  the journey, and sender trust is cited from channel-core's existing forgery
  and trust tests, not rebuilt.
- This is the wake-specific form of
  [distinguish presence from execution](/coordinator/distinguish-presence-from-execution.md)
  and of
  [delivery receipts and stream health](/aweb-protocol-expert/lessons/delivery-receipts-and-stream-health.md):
  a transport's acceptance is not the recipient's receipt.

# Limits

A design decision, not a measured run. The tests used channel-core's own
formatter output and ran the in-container transcript reader locally. Runtime in
the container was not run, because no authorized Claude login or model route
existed yet. The first real run should confirm the rule or supersede this
concept.

Evidence: OKF proposal from aweb-expert/aweb-expert-wake-fixes, 2026-11-13; notes/session-presentation-evidence-is-the-harness-transcript.md.
