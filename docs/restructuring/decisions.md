# Restructuring — decisions & questions (Juan's review surface)

This is where you make the calls. The full plan is in
[`../restructuring-sot.md`](../restructuring-sot.md); this page pulls out the
things that need *your* decision and gives you a place to write them.

How to use it: under each item, fill in the `> Decision:` line (and `> Notes:`
if you want). To take the suggested answer, just write `yes` or `accept`. To
change it, write what you want instead. Add questions anywhere with `> Q:`.
Either edit this file, or just tell me your answers and I'll fill them in.

A quick note on where things stand: the engineering plan has been checked by
two people — the consultant (is the architecture sound?) and the lead of the
team that will build it (can we actually build this, does it match the code?).
Both agree. So what's left below is **your product calls and your go-ahead**,
not open technical arguments.

---

## 0. The only thing needed to start the first work

**Do you approve the plan, and should the team start building the first piece?**

The "first piece" is two self-contained steps (they don't depend on any of the
bigger decisions further down):

1. **Define how an app describes itself to aweb** — a small spec (the "app
   manifest") so that one declaration powers both an app's tools-for-agents and
   its `aw <app>` command-line commands — plus tests that pin it down.
2. **Build the `aw` plugin system** so `aw <app> …` commands work at all (today
   there's no plugin mechanism).

Suggested answer: **yes, start** — both reviewers agree, and the build team is
waiting on your word.

> Decision: yes start

*(Everything in sections 1–3 below can wait — none of it blocks this first
piece. So you can say "yes, start" here even if you leave the rest blank.)*

---

## 1. Bigger product calls (these shape later work, not the first piece)

**1a. How we charge for the agent network.**
The plan: the network and apps are free up to a single bundled usage allowance
("X actions a month"); paid tiers just raise the allowance. For hosted A2A
gateway usage, the question is whether it is included in that same allowance or
is a separate paid-only feature.
Suggested answer: **include hosted A2A gateway usage in the allowance** (keeps
the "the whole network is free up to your allowance" story; heavy users
naturally need a paid tier). A2A itself is the open Agent2Agent interop
protocol, not aweb messaging or org-to-org federation.
> Decision: we charge for bundled mutations. A2A has nothing to do with messaging across orgs.
> Notes: __________

**1b. The developer app.**
There's a general "tasks" app for any team, and a developer-specific app (git
worktrees, branches, code review) on top of it. Should the developer app be its
own separate service, or just a "developer mode" of the tasks app?
Suggested answer: **its own service** — but this can be decided when we build it.
> Decision: __________
> Notes: __________

**1c. Pricing numbers.** The structure (one bundled allowance + tiers) is set;
the actual prices/tiers are yours.
> Decision (numbers, or "later"): __________
> Notes: __________

**1d. Which apps are open-source vs. private.** The identity/network core is
open-source; `atext` is the public example others copy; first-party apps like
`folio`, messages, mail, and chat can be decided app by app.
> Decision: folio is so not our flagship, where did you get that from? messaging probably is, mail and chat. but we do not know what people want.
> Notes: __________

**1e. Do we host the agents themselves?** Suggested answer: **not in this first
version** — running agent compute is a different business; the design leaves the
door open for it later.
> Decision: agree, we do not for now.
> Notes: __________

**1f. The word "anapp."** It's awkward; we'll likely rename it. Also: when do we
switch public wording from "team" to "network/web"? (Internally the identifier
stays the same either way.)
> Decision (a better word? / "later"): naapp maybe, native agentic app
> Notes: __________

---

## 2. Bring-your-own-team (customers who run their own identity authority)

**2a.** For customers who hold their own team's master key (rather than letting
us hold it), connecting a hosted agent requires them to approve that agent once
(a single signing step per agent). A smoother "delegate approval to us" option
is planned for later.
> Q: is "approve each agent once" acceptable for the first version?
> Decision: yes
> Notes: __________

**2b.** We'll show these customers clear status (connected / read-only /
delegated / migrated-to-fully-hosted) instead of making it feel like a broken
version of the hosted product.
> Q: is that the right set of statuses?
> Decision: i trust you can decide that.
> Notes: __________

---

## 3. Already decided unless you object (leave blank = you're fine with it)

**3a. The "contacts"/address-book feature stays in the core** (the trust layer
depends on it), rather than being a separate app.
> Object? (blank = fine): __________

**3b. Mail and chat become apps too** (like docs, tasks, secrets), rather than
being baked into the core — but this is the *last* and most delicate change,
done well after everything else.
> Object? (blank = fine): __________

---

## 4. Anything else — questions or changes

Write anything here and I'll answer it and update the plan.

>
>
>

---

*Once you've made the calls, I fold them into the plan, record your sign-off,
and (on section 0) the team starts the first piece.*
