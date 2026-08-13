# Proposal: block ordinary retirement when a retire hook reports incomplete cleanup

**Base** `6ac3386949b2b97787522e679a4369bca936d1ef` (`agents/cli-dev-strict-curriculum-spike`)
**Tip** `7b4fe6471fe875d1ac9c3339f582791061ff91f3`
**Size** `lib/core.mjs`: **+52 / −2**, touching two functions — `retireInstance`
and `quarantineInstanceHome`. Tests: **+95**.

## What this is not

**It does not ask for required retire hooks.** Your rejection at `lib/core.mjs:671` —
*"only the spawn hook is enforced (retire and soul-scaffold run outside a spawn
transaction)"* — is correct, and we are not asking you to weaken it. `required`
means *fatal to a spawn*; retire has no spawn transaction to be fatal to.
Overloading it would conflate two different guarantees.

It also adds **no manifest surface**, no new config, and no new vocabulary.

## The gap

`retireInstance` already computes structured hook failures, but reads them **only**
inside the quarantine-retry branch. On the ordinary path a *first* failure is
collected and then never consulted — so the home is deleted along with the
credential needed to undo whatever external state survived.

The consequence is already written in your tree, at `lib/core.mjs:4494`:

> *"the ordinary path, where hook failures do not retain, and deleted the
> credential while the external state survived"*

So this isn't a missing feature. It's an asymmetry: a **retry** of a quarantine is
careful, and a **first failure** is not.

## The change

The ordinary path now consults the same evidence the retry path does — the
structured failures, plus the existing convention where `retired: false` counts as
incomplete unless the reason is `nothing-to-delete` — and quarantines through the
**same `quarantineInstanceHome` writer**, not a second copy. That function's own
comment records that two copies of this logic caused a previous divergence, so
there is still exactly one.

**Backward compatible by construction.** A hook that reports nothing, or reports
`retired: true`, is unaffected. Only an explicit *"I did not finish"* changes the
outcome — and today that report is silently discarded.

**Self-retire is explicitly excluded, and its behaviour is unchanged.** This patch
preserves the existing self path exactly: local state is torn down and the existing
scheduled window teardown is reached, as on the base commit. The exclusion exists
because a self-retiring instance *is* the caller, so turning its exit into a
retained *owner* quarantine would change a path this patch does not otherwise
touch. The patch makes **no claim** about where or whether a capability journals
outstanding external owner cleanup after the home is removed; that is a capability
concern, outside this change.

One diagnostic correction: the shared writer's `reason` becomes an **optional**
parameter defaulting to the existing spawn wording, so every existing caller is
byte-identical. The quarantine shape is now reached from two events, and a fixed
`"spawn rolled back"` string mislabelled the retire one.

## Evidence

**Red → green → mutation.** The test failed on unfixed code at the intended
assertion (*"incomplete cleanup is reported, not discarded"*), passed after the
change, and two independent mutations attribute to different mechanisms:

| Mutation | Effect |
|---|---|
| Remove the blocking assignment | ordinary test reds |
| Weaken the guard to `if (!o.keepDir)` | ordinary test **+ 6 pre-existing quarantine tests** red |
| Remove the `self` exclusion | **only** the self-boundary test reds |

**Mirror case** in the same test: a hook reporting complete must still delete
exactly as before, so the change cannot pass by breaking ordinary retirement.

**Full suite at `5c8b724`** (the pre-amendment tip) vs a pristine control at base
`6ac3386`, both under `guard-bin` first on PATH, separate `TMUX_TMPDIR`,
`env -u TMUX`:

- `5c8b724`: **437 tests, 436 pass, 0 fail**
- control `6ac3386`: **436 tests, 434 pass, 1 fail**

Exactly one attributable delta: the `+1` test this adds. The control-only failure
(`hostile instance.json cannot steer the harvest cwd`) is **not attributed to this
change** — it passed 5/5 in isolation at 331–398 ms against 4234 ms when it failed
inside the full suite. Load-sensitive, pre-existing, and yours rather than ours;
flagging it only so it isn't mistaken for fallout.

**Independent review.** Reviewed twice by an agent who was not the author. The first
round returned *amendments required* and caught a real defect: the blocking path
reached self-retire, which we had claimed it did not. They established it with a
fixed-vs-control regression rather than by reading the diff.

**At final tip `7b4fe64`** the same reviewer returned **ACK — no blocking issues,
no non-blocking suggestions**, having executed the two regressions (2/2) and a
scoped suite of **460 tests / 459 pass / 0 fail / 1 optional skip**, with the
checkout verified restored clean. The full fixed-vs-control comparison above was
run at `5c8b724` and was not repeated at `7b4fe64`; the amendment between them is
the `self` exclusion, its regression, and the optional `reason` parameter.

## Why you might still say no

The honest counter-argument is that this makes a *first* retire failure retain a
home that previously disappeared, which is a visible behaviour change for anyone
whose hooks report `retired: false` today and who is relying — knowingly or not —
on the home going away regardless. We think that reliance is the bug, but it is
your call, and a release note may matter more than the diff.
