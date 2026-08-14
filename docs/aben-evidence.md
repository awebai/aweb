# aben shipment-gate evidence, third submission

Built to the re-entry protocol over the SECOND verdict's amendments
(C1-C6), on top of the second submission's closure of the first
verdict (A1-A9, all landed; ledger in section 6). Sections marked
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

## 6. Ledger
First-verdict closure (A1-A9) as in the second submission (`2a43d235`,
fetchable on the branch): A1 `21e89fa6` .. A9 `e6e26295` + stamp
`612758b2`. Second-verdict rounds: C5 `287048dd`, C1 `918f4e75`, C3
`1066af2a`, then STAMP-AT-SEND for the carve chain, C2, and the
micro-rounds with each review record (including both recusals and
their independent carve reviews, and the reviewer's HOLD that
correctly prevented a partially-reviewed landing).
