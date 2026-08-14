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
release-review's clause-by-clause audit (criteria: docs/aben-design.md,
which they did not author) runs over the pinned pair before this packet
is sent; its findings and closures are listed here with the pin SHAs
and the auditor's own re-verification at deliverable time.

## 4. release.md conformance ledger
One touch in the entire epic: the four-line override-mechanics note in
step 1 (micro-round `8519b593`, release-review ACK; alice's scope
ruling: conformance edits bounded - the document must stay TRUE of
mechanics the epic changed; no prohibition or operator-surface change,
and none made). Every other clause byte-unchanged - STAMP-AT-SEND with
the empty diff over the full range.

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
