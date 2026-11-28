---
type: Lesson
title: A watch on a held root key sits outside the holder's trust, and an invalidation feed misses additions
description: When a service holds an organisation's root key and a change watch is the compensating control, split it into a trigger inside the holder that only runs the existing freeze sooner and a keyless sentinel outside the holder's trust that reads public evidence and alerts on every change; a journal-based "change we didn't make" check inside the holder is forgeable by the compromise it guards against, and the registry's invalidation feed never shows additions made with a stolen root.
tags: [lesson, custody, review, registry, invalidation, compromise]
timestamp: 2026-11-28
---

A service may be allowed to hold an organisation's root key (its namespace
controller), with a watch accepted as the compensating control. The usual
form of that watch is the holder's own reconciler: it reads the registry
feed and alerts on any controller or key change that no journal row of the
holder explains. That is a good trigger for a prompt freeze. Against the
compromise it is meant to compensate for, it is useless. Whoever controls the
holder also controls the key ring, can write journal rows that "explain" the
change, and can drop its own alerts.

# The rule: split the watch in two

- **A trigger inside the holder.** It only makes the existing freeze rule run
  sooner. It adds no new freezing rule.
- **A sentinel outside the holder's trust.** It holds no key, no ring, no
  database credential and no write path into anything the holder reads. It
  reads only public evidence, alerts on every change, and the operator matches
  each alert to a planned ceremony. Root and key changes are rare, so alerting
  on all of them is cheap. A sentinel that reads no journal cannot be fooled
  by forged rows. It never freezes the service, because it shares no trust
  with it.

# The second limit: an invalidation feed misses additions

The registry's public feed carries opaque negative handles, emitted when a
fact stops being current: membership removal or replacement, team re-key or
deletion, identity-head change, namespace replacement and the like. A consumer
recognises a handle only for evidence it already holds. So the feed shows
changes to facts the watcher already holds. It never shows what a stolen root
*adds*: a new private team, a new root-certified agent, a new grant.
Anonymous reads do not show private teams either.

Closing that gap needs an inventory read of the namespace, authenticated by
the controller and diffed against the holder's planned changes. No such read
exists. Until one does, a design that relies on the watch must name the gap
and name the response to a confirmed compromise (for example, rotating the
controller through DNS).

# How to apply

Before accepting "a watch" as the mitigation for a custody decision, ask:

1. Can the compromised party suppress or explain away this watch? If yes, it
   is only a trigger, and an outside sentinel is still needed.
2. Does the watch's source show additions, or only invalidations? If only
   invalidations, name the additions gap and the inventory read that would
   close it.

This is the custody-side case of the rule in
[accepted guarantees change only by ruling](/aweb-protocol-expert/lessons/accepted-guarantees-change-only-by-ruling.md)
that a service-held summary cannot give independent verification: evidence
the holder can write proves nothing against the holder.

# Status

Design-level only, and the evidence is one design that is not yet reviewed;
its reviewers may refine the sentinel. The source reports that Juan decided to
let a hosted service hold an organisation's controller with a feed watch as
the compensating control (source-reported). The hosted custody design that
carries the split and names the additions gap is described generically here;
its document and commits are not cited. The feed semantics are in section 4
("Public feed") of `docs/design/standing-proof-and-feed.md` on the aweb
`one-organisation` branch (checked at 7cb8585657); they are not on aweb main
and nothing implements them yet.

Evidence: OKF proposal from aweb-protocol-expert/aweb-protocol-expert-pilot-custody, 2026-11-28; notes/a-watch-on-a-held-root-must-not-share-its-trust.md.
