# aben shipment-gate evidence, third submission

Built to the re-entry protocol over the SECOND verdict's amendments
(C1-C6), on top of the second submission's closure of the first
verdict (A1-A9, all landed; ledger in section 7). Sections marked
STAMP-AT-SEND are completed at send time from a fresh fetch, per the
dated-stamp practice, and re-verified at any later landing.

## 0. Closure matrix - the second verdict's findings

| # | Finding | Fix (landed main SHA / STAMP) | Real-entry regression | Recorded red | Enforcing source |
|---|---------|-------------------------------|----------------------|--------------|------------------|
| 1 | Fixed continue commands cannot execute the AC digest/migration contract; env overrides live; marketplace skipped; correction unread | C1 `918f4e75` (+ carve chain STAMP-AT-SEND) | `test_digest_argv_composed_by_the_train_executes_the_real_ac_contract` (composed argv EXECUTED against the real AC script over the wire; bare tuple refused - the discriminating control), `test_fixed_continue_commands_are_the_reviewed_defaults` (hijack-attempt pin), `test_marketplace_edge_follows_the_card_not_command_presence`, `test_pending_correction_is_executed_not_recorded`, `test_unbound_correction_refuses_when_the_card_needs_it` (entry-tripwire form: pointer untouched, no provider command ran) | the critic's argparse exit-2 reproduction; the marketplace edge NEVER ran in production (command name absent from the fixed set) | `_CONTINUE_FIXED_COMMANDS` / `continue_commands` (fixed, no env), digest/marketplace call sites appending card argv, the entry validation, the correction fork |
| 2 | Terminal sweep cannot pass real authenticated images; inventory incomplete; omission unguarded; default gate untested | C2 STAMP-AT-SEND (branch `62eca468` + micros `8519b593`, `15c5d347`) | `test_bearer_reaches_every_oci_surface` (auth required at EVERY endpoint, both directions), `FactDomainEquality` (two-way over >40 facts + dropped-fact mutation), `test_full_fixture_continue_reaches_done_through_the_default_terminal_gate` (NO injected gate; dynamic derived-revision binding), `test_default_gate_refuses_a_lying_external_binding` (falsified sync stamp) | index PRESENT + platform rows UNAVAILABLE under auth; `_LATEST_PROMISED` as the untestable domain input | token threading in `_fetch/_fetch_manifest/_child_revision`; `expected_fact_keys` + the both-ways check INSIDE `_default_terminal_gate`; `image_alias_row`, `external_release_binding_rows`; `Artifact.promises_latest` |
| 3 | Continue not retryable after AC publication; partials source-unbound | C3 `1066af2a` | `SourceBinding.test_retry_after_derivation_binds_ac_to_the_adopted_sha`, `test_recovery_partial_from_the_wrong_source_stops`, `test_identityless_recovery_candidate_is_not_failed_closed` (+ the derivation pin) | the critic's retry reproduction: expected map permanently None | `expected_completion_sources(card, ac_derived_sha)`, `ArtifactResult.candidate_source_identity` on the serialized surface, the comparator's recovery branch |
| 4 | Projection not bound to selected SHAs; continue captures whatever is checked out | C4 STAMP-AT-SEND (branch `801ac65a` + carve `1ccd7303`/`333ec340` + micro `8519b593`) | `test_selected_older_sha_produces_a_card_for_that_selection` (the POSITIVE control: older-on-main override works, card names the older SHA, HEAD's movement absent), `test_projection_base_mismatch_refuses_by_name`, `test_local_checkout_not_at_the_card_sha_stops_by_name` (both directions at the rederive gate) | pre-fix the entry captured HEAD and answered PATCH NEEDED where the older card was owed | detached exact-object worktrees in `_main` (validation BEFORE the worktree per review), `prepare(projection_base=)`, the rederive checkout binding |
| 5 | Normalizer: networked lock regen; primary-only reobservation; empty-anchor ValueError | C5 `287048dd` | `OnlyMalformedAnchors` (the critic's pkg-v0.3 world, permanent), the offline=1 assertion in the cascade proof, `test_recovery_reobservation_classifies_progress_vs_conflict` (four directions, strict single-shot) | `ValueError: max() iterable argument is empty`, reproduced | the conforming-anchors guard in capture; `UV_OFFLINE=1` on the regeneration env; `reobserve_result(world=)` |
| 6 | Packet stamped one commit stale | administratively resolved (critic's own ruling on the dated addendum); this packet stamps at send from a fresh fetch | - | - | - |

## 1. Final heads - STAMP-AT-SEND
aweb main, AC main, both from ls-remote at send time, with the landing
ledger below them. AC quiescence stated for the audit pin.

## 2. Found-en-route defects, disclosed as their own lines
- C2 caught C1's marketplace-argv gap (the same class as the digest
  defect) before C1's flaw could ship - fixed and controlled in C2's
  round, not folded.
- `bases['pypi']` meant host root to observe/capture and host+`/pypi`
  to the builders - one dict, two semantics, unsatisfiable together; a
  latent production defect surfaced by the default-gate capstone and
  unified on host root.
- The falsified-stamp mutation proves the binding row is COMPARED, not
  merely present - the control that makes the capstone mean something.
- Two errors in MY OWN justifications, disclosed because a gate reader
  is weighing whether my claims can be trusted, not only whether the
  code is right. (a) I justified the source-commit-tag predicate with an
  inverted argument - that a swallowed tag "would have stopped anyway" -
  when swallowing a tag as a commit id is precisely what REMOVES the
  stop; release-review caught it. The predicate is right for structural
  and measured reasons instead (a dotless string cannot be
  version-shaped; ~90 such tags on the live registry), and the code
  comment states those, never the inverted one. (b) I twice sorted
  version strings lexically and read the result as an ordering; I caught
  the second myself and re-measured numerically before reporting. Both
  are the same failure mode - a plausible argument produced faster than
  it was checked.
- The `promises_latest` metadata gap: the one two-way-domain input the
  equality could never check, closed by declaring the promise on the
  canonical record (reviewer-found, alice-carve-reviewed).

## 3. The design-conformance audit - STAMP-AT-SEND
release-review's audit (criteria: docs/aben-design.md, which they did
not author) runs over the pinned pair before this packet is sent; its
findings and closures are listed here with the pin SHAs and the
auditor's own re-verification at deliverable time.

**COVERAGE, stated so "clause-by-clause" is not read as complete.**
Parts 1 and 2 walked design **section 1 and the migration lists**.
Sections **2, 3 and 5-10 were NOT walked.** A reader should treat the
unwalked sections as unaudited rather than as audited-and-clean; the
audit's findings (F1/F2/F3) come from the covered part only. Recorded
in the auditor's own terms at their request.

## 4. release.md conformance ledger

TWO touches in the epic, not one. This section said one until
release-review set-compared it against a baseline they had pinned by
blob digest before this packet existed; an undercounting ledger is
exactly what alice's ruling was written to prevent, so the correction
is recorded rather than quietly applied.

| Touch | Landed | What | Review record |
|---|---|---|---|
| Override-mechanics note in step 1, four lines | `e8b7478c` (micro-round `8519b593`) | the document stays true of mechanics this epic changed | release-review ACK of the `8519b593` round |
| `:197` marketplace-adapter correction + the `release-awid-site` line | `384865f6` | same bound: mechanics the rulings round changed | release-review ACK of the `1dc2aae9` round |

Both sit inside alice's scope ruling - each describes mechanics its own
round changed, neither touches a prohibition or the operator surface -
and both were ACKed. Nothing is wrong with either edit; the ledger was
wrong.

Measured over the two-touch range: `docs/release.md` blob `33867ef9`
at plan-critic's `cadfb4eb` baseline, `7d0e1ccf` at the landed head,
cumulative +9/-3 (not the +3/-1 of the single touch). The
"every other clause byte-unchanged" claim is STAMP-AT-SEND over THAT
range - computed over the one-touch range it would have omitted a real
edit and the empty-diff check would have been measuring the wrong
thing.

## 5. Final focused record - STAMP-AT-SEND
One warning-free run over the final landed heads, saved with SHA-256,
per grace's standing verdict-line practice.

## 6. First contact with the real world

Every section above this one is evidence from fixtures and stand-ins.
This section is the only one where the process met production, and it
is the section to read hardest, because it is the only one whose
instrument was not built by this epic.

**The run.** `make release-prepare` over a pair of clean checkouts of
the real landed heads, against the real registries with real
credentials, publishing nothing (the prepare phase moves no pointer;
the launcher is the reviewed one, unchanged between runs).

**What the first run did: it stopped, by name, in seconds.** Three
refusals, nothing published, no pointer moved. That is the designed
behaviour and not a disappointment - but two of the three refusals were
FALSE stops caused by defects in this epic's own code, and no fixture
had found them in eight days.

| Refusal | True or false stop | Cause |
|---|---|---|
| skills github member empty | FALSE | discovery stripped a bare `v` on its own authority while the status builder looked up `skills-v{version}` - two derivations of one fact |
| aw-cli version `0.0.0` | FALSE | a tag-history artifact's version read from a publish-time placeholder manifest that was never a version |
| ac-image `0.7` unparseable | TRUE, then ruled | a real channel line pointer, correctly refused; the ruling is that line pointers are dropped AT DISCOVERY so they can never become a release identity |

**The finding that matters more than the three fixes.** Two of these
were the DUPLICATE-DERIVATION family - the class this epic exists to
eliminate - and that makes three instances of one pattern inside the
epic itself: `_LATEST_PROMISED` as a bare set both sides read (invisible
to the two-way check precisely because it fed both sides), the bare-`v`
strip versus the canonical prefix lookup, and the aw-cli placeholder
read. Each was found by a DIFFERENT instrument, and the third only by
first contact. The honest reading is not that the epic is unusually
buggy; it is that a rule against duplicate derivation is not
self-enforcing, and that fixture confidence has a ceiling this run
found. Recorded unsoftened at release-review's request, and I agree
with them.

**Fixes and their controls** (landed `38a3b871`, release-review ACK):
one owner, `release_tag_prefix`, consumed by both discovery and
read-back with a contract test pinning spec-equals-owner for every
github target in the canonical inventory; the tag-history version
derived from tag history, with the placeholder read measured as the
inventory's only one; OCI line pointers (`v?MAJOR`, `v?MAJOR.MINOR`,
wholly numeric) dropped at discovery and proven dropped by a spy -
structural, not merely unreached. Three-component near-misses still
survive discovery to be refused BY NAME: drop what cannot be valid,
keep what might be invalid.

**The fixture check that settles it, run by the reviewer, not by me.**
I asked whether my fixture encoded the real tag shape. The stronger
question, which release-review asked and answered against the live
remote, is whether a COMPETING spelling exists: 15 `skills-v` tags and
no other skills tag form anywhere. Had two spellings existed, encoding
the real-but-wrong one would have looked identical to encoding truth,
and "the tag exists" could not have told them apart.

**The phase's cost, measured with both remote primitives
instrumented.** The first successful run took a quarter of an hour,
which is a broken release system rather than a slow one. Three
findings, in the order they were made, because the ORDER is the
lesson:

| | phase | remote calls | ghcr.io |
|---|---|---|---|
| first successful run | 695.5s | 1672 | 1601 |
| identity resolved only where compared | 60.7s | 111 | 41 |
| one bulk ref read per remote | 37.0s | 97 | 41 |

The first directive taken was to replace per-prefix ref queries with
one bulk read, reasoned from a correct measurement (a round trip costs
the same for 1 ref or 516) and a wrong model of where the volume was.
The profile said that change addressed 21 of 695 seconds - THREE
PERCENT - while 94% sat in per-tag OCI identity walks. It was done
second, and by then it was 37% of what remained. A fix can be correct
and still be the wrong thing to do first, and measuring before
choosing is the only way to tell which.

The bulk read is kept for a reason that is not speed: N sequential
reads are not a snapshot. A tag created midway is present for the
later queries and absent for the earlier ones, and the double-compute
check cannot see it, because both computations read the same
already-inconsistent capture.

**One check was deliberately NOT optimised away.** For awid-image and
a2a-gateway-image the anchor is a git tag and the target is a
registry, and those are two different facts: what the tag points at,
and what the published image says it was built from. Resolving the
second from the first would have made them equal by construction -
demonstrated against the engine: with a disagreeing label, today
conflicting-partial, under that change reconciled. Duplicate
derivation is two computations of ONE fact that must agree; this is
two observations of two facts compared BECAUSE they can disagree.
Cost of keeping it, measured: 12 of 97 calls, 3.7 of 37.0 seconds.
ac-image is the one artifact with no such cross-check, because
nothing independent exists to compare its label against.

**The AC tag backfill, done before the reader that produced it was
deleted** (plan-critic's boundary 1). Under Juan's ruling a release's
identity is the tag in its own repository, so ac-image's
revision-label path is removed; v0.7.13 and v0.7.14 had no AC tag, and
the image label was the only surviving record of what they were built
from. Read with the reader that is now deleted:

| AC tag | commit | source of the identity |
|---|---|---|
| `v0.7.13` | `6c1bbe5c1f6fbb17318186216c9d00ab8f523fc5` | `ghcr.io/awebai/ac:0.7.13` revision label |
| `v0.7.14` | `efd19f41bf6699264e6a7813df19c4b0070eb4a3` | `ghcr.io/awebai/ac:0.7.14` revision label, independently corroborated by the live `/health` endpoint |

THE CONTROL THAT MAKES THE BACKFILL TRUSTWORTHY, run before creating
either tag: `v0.7.12` already had both a tag and an image, and they
agree - the tag peels to `559b5f5c...` and the image label reads
`559b5f5c...`. So the label-equals-tag convention is demonstrated on a
case where both facts existed, rather than assumed on the two cases
where only one did.

Both tags are ANNOTATED, matching all 13 existing AC release tags; the
first attempt created them lightweight and was corrected before anyone
consumed them, leaving 15 of 15 uniform. The removal path was proven
before any real tag was created - a throwaway tag was pushed to
`awebai/ac`, observed on the remote, deleted, and confirmed gone -
because a cleanup obligation that has not been tested is not a
constraint.

**The image-to-source correspondence this removes, and where it now
lives.** Reconciliation no longer compares the published image's
revision label against its source tag. That property is enforced at
PUBLICATION instead - AC's release-image verification proves a built
image carries a label equal to its build SHA, with the publish-time
byte comparison as the exact-adopt gate. Durable status now proves two
required facts, the immutable registry object and the exact AC source
tag, and no longer proves the first was built from the second. Stated
that way deliberately, because the alternative is status language that
implies a check nobody runs any more.

**FOUR TIMES THE REAL WORLD CORRECTED A FIXTURE, and the fixtures
were not careless.** This is the epic's most durable finding and it
belongs above the individual defects:

| what was asserted | against | what the real pair said |
|---|---|---|
| version candidates are version-shaped | constructed tags | ~90 BARE commit tags on ghcr.io/awebai/ac |
| aw-cli's version is in its manifest | a manifest that existed | a publish-time 0.0.0 placeholder that was never a version |
| skills' github member reads back | a fixture using one prefix | discovery and read-back derived the prefix twice, disagreeing |
| aw's published tree equals aweb's cli/go tree | repositories I built | differ by exactly `.github`; tree ids hash the whole entry list, so the check could NEVER have passed |

Each was asserted against inputs the author constructed, and each was
wrong in a way only first contact could show. The fourth is the
sharpest, because the failure direction was invisible from inside: a
comparison that can never succeed passes every test that only ever
asks it to refuse, and the constructed fixtures agreed precisely
because one author built both sides. The design had already recorded
the correct form (section 2's "excluding `.github`... not a
subtree-hash shorthand unless byte-equivalence is separately proven")
and it was not read before implementing.

Measured after amendment, against the real repositories at three real
release tags: v1.34.7 and v1.34.6 at 506 paths, v1.34.5 at 505,
identical mode and object id, observed-present - the same three that
were conflict-unproven before.

**A CHECK THAT HAS NEVER BEEN ABLE TO FAIL IS INDISTINGUISHABLE FROM
A CHECK THAT PASSES**, and one of these lived inside the capstone this
packet cites as its strongest evidence. Removing the OCI identity path
surfaced three, all of the same family:

- the registry stand-in derived manifest digests from the TAG NAME,
  and omitted the digest header entirely on one path - so
  `latest == VERSION` compared two EMPTY strings, found them equal,
  and reported PRESENT. That row has been decorative for its whole
  existence. Digests are content-addressed in the stand-in now, so two
  tags naming one image share one and the comparison is real.
- an index-digest row could read `observed-present` with NO digest,
  because the old evidence string appended the source anchor and was
  therefore never empty. A missing `Docker-Content-Digest` is
  `unavailable` now, which is what it means.
- the platform fact key differed between the present and absent
  branches, so the family was not stable across outcomes - a
  RE-OCCURRENCE of C2's stable-family rule rather than a new finding.

**Two control failures of my own, same shape, same day.** A landing
check printed IDENTICAL for a base SHA I had hand-expanded and that
did not exist: both sides of the comparison errored to empty and
compared equal. And a landing gate printed the out-of-scope file
rather than refusing on it, so a held packet document landed
unreviewed alongside reviewed code. Both are now gates that refuse,
and both require their inputs to be non-empty before comparing. I
record them because the packet's evidence should be read as
calibrated, not as advocacy - and because they are the same defect the
code findings above describe, committed by the person auditing for it.

**The re-run** - STAMP-AT-SEND: the classification the same launcher
produces over the pair refreshed to `38a3b871` / AC `22ab8bbe`, with the
equality-group resolution stated explicitly, and any remaining stop
named. Instrument note, so a reader does not mistake it for a product
finding: the run produced no incremental output under my harness
because Python block-buffers to a pipe: that is my launcher's
redirection, not the tool's behaviour on an operator's terminal.

## 7. Ledger
First-verdict closure (A1-A9) as in the second submission (`2a43d235`,
fetchable on the branch): A1 `21e89fa6` .. A9 `e6e26295` + stamp
`612758b2`. Second-verdict rounds: C5 `287048dd`, C1 `918f4e75`, C3
`1066af2a`, then STAMP-AT-SEND for the carve chain, C2, and the
micro-rounds with each review record (including both recusals and
their independent carve reviews, and the reviewer's HOLD that
correctly prevented a partially-reviewed landing).
