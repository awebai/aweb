# aben shipment-gate evidence (assembling; final-head fields stamp at the R6 land)

Built to plan-critic's six-item packet specification (their mail
af7e5b2b via alice). Sections marked STAMP-AT-LAND complete when the R6
code round lands; everything else is final.

## 1. Review ranges — STAMP-AT-LAND

aweb: final head, merge base vs main, non-merge count/list, three-dot
cumulative file list. AC: final head 35e204a5 lineage (derive script
round aa73f30a + stamper round). Composed heads stamped after the R6
land.

## 2. Column B index — one row per control

### B1 narrow card
- Test nodes: `test_release_column_b_assembly.B1NarrowCard.test_b1_emits_the_exact_expected_patch`, `...test_b1_control_no_scope_change_yields_no_ac_row`
- Fixture: `scripts/e2e/fixtures/aben-column-b/b1-narrow-card.json` (dev2; provenance in-file, per-value re-observed/record-sourced marking) + shared clones of the real repositories at aweb `5a55f7ce6b4dbb86dc2901f7c687e172e39db3af` / AC `47060200c53d30835cbb35cbcb5d073cbe3dc5d3`
- Red record: first run FAILED with FileNotFoundError on `cli/go/npm/package.json` — a REAL LANDED R3 DEFECT (derive_capture_specs guessed the wrapper manifest path; no mirroring test could see it). Fixed at cause (`cli/go/npm/aw/package.json`) with a per-spec existence check added (`test_every_spec_manifest_path_exists_in_this_repository`). **The acceptance run catching a landed defect is this packet's strongest line.**
- Green: the exact patch — awid-service and awid-image `0.5.15 -> 0.5.16`, independently derived ac-image `0.7.14 -> 0.7.15`; any other emitted version fails the assertion.
- Discriminating control: AC scope anchored at the fixture commit → NO ac-image row beside surviving awid rows.

### B2 stale pre-authorized CLI version
- Test nodes: `...B2StaleCliVersion.test_recorded_world_rederives_the_next_free_patch`, `...test_control_unpublished_accepts_the_original_intent`; engine root `test_release_normalizer_movement.test_cli_derivation_rederives_over_occupied_intent` (+ multi-occupied walk)
- Fixture: `b2-stale-cli-version.json` (aw composite unit at 1.34.5, tag at `2455e7a1...`, re-observed provenance) + `.control-unpublished.json`
- Green: the tag-history row derives `1.34.6` over the recorded occupancy; the control derives `1.34.5` when nothing occupies — the one-difference discrimination.
- DISCLOSED HARNESS BRIDGE: the control fixture's authored world lacks the prior tag history its own provenance requires; the harness supplies the implied `1.34.4` prior, commented in-test and mailed to dev2's lane (e06a8027). Clean fix deletes the bridge.

### B3 single-floor derivation near-miss
- Test nodes (AC repo): `scripts/test_derive_release_floors.py::test_incomplete_card_set_refuses_before_any_edit`, `::test_lock_resolving_stale_version_refuses_naming_wanted_and_got`, `::test_ac_version_mutation_inside_allowlisted_diff_refuses`
- Fixture: `b3-single-floor-derivation.json` (recorded pyproject/lock state) + the preserved launcher-string variant in the task record
- Red record: all 7 derive contracts written before the script existed (7 failures), then green; the near-miss reconstruction asserts BOTH `1.27.2` (wanted) and `1.27.1` (got) in the refusal.
- Discriminating controls: policy-row deletion refuses INCOMPLETE-DERIVATION against the raw card set before any lock work; the AC-version mutation inside an allowlisted diff refuses naming `0.9.9`.

### B4 impossible pre-registered shape
- Test nodes: `...B4ImpossibleShape.test_the_impossible_shape_refuses_before_any_card`, `...test_control_lagging_absent_reuses_m_with_no_patch`, `...test_control_lagging_conflicting_mints_once_with_driver`; engine roots in `test_release_normalizer_equality_groups`
- Fixtures: dev2's three b4 worlds, run VERBATIM.
- Red record — TWO REAL ENGINE DEFECTS caught by the independent controls, failures recorded against the unfixed engine before any edit: (a) movable-at-M members sent to the mint path (the phantom-release direction); (b) identityful anchorless occupancy at the intended version stopping flat instead of feeding the conflicting fork. Both fixed at cause; the reconciliation refinement (design sections 2/3 meeting point) is flagged for the gate's independent trace.
- Green: the impossible shape refuses `equality-invariant-violated` before any card exists; lagging-absent reuses M with recovery and NO patch; lagging-conflicting mints once to `1.27.3`, both manifests exactly once, driver-labeled `a2a-gateway-image`.

### B5 false publication status
- Test nodes: `test_release_status_report.B5.test_b5_fixture_renders_the_historically_true_world`; the two-failure injection `StopReport.test_two_injected_failures_both_visible` (+ reporter-bug case)
- Fixture: `b5-false-publication-status.json` loaded VERBATIM in the shape committed to dev2 before authoring.
- Green: the rendered table shows exactly THREE artifacts PRESENT (npm @awebai/aw 1.34.6, ghcr awid 0.5.16, ghcr a2a-gateway 1.27.2) and TWO ABSENT (pypi awid-service 0.5.16, pypi aweb 1.27.2); `done(rows)` is False. Rendered output included in section 3's saved record. The two-failure injection shows the original refusal primary, the probe failure as an UNAVAILABLE row, exit nonzero.

### Normalizer-drift named stop
- Test nodes: seam half `test_release_normalizer_orchestration.test_nondeterministic_compute_is_the_drift_stop` (deliberately data-free — identical inputs are the point); data half `...NormalizerDriftRow.test_exit_reobservation_race_stops_by_its_real_name`
- Fixture: `normalizer-drift.json` two-world race (capture-time absent, exit-time occupied) → `version-occupied` by name, never silent regeneration.

## 3. Final focused test record — STAMP-AT-LAND
Commands, exit status, duration, saved output path + SHA-256, run once
over the final landed head.

## 4. Design-to-code map
- §1 canonical metadata → `release_train.py` (Anchor/OwnedLock/Artifact fields, edge obligations); tests `test_release_artifact_metadata.py`
- §1 extractions → `check-release-floor.sh` (+`test_check_release_floor.sh`), `observe_public_target.py` (+CLI contract test), `release-tag-helpers.sh` (+executed test), AC `derive_release_floors.py` (+7 contracts); workflow one-line calls pinned in `test_release_gate_contract.py`
- §2 grammar/discovery/reconciliation → `release_normalizer.py` (parse_version, reconcile_unit), `release_normalizer_capture.py` (discover_*, bounded pagination); tests `test_release_normalizer_{movement,reconciliation,capture_registry}.py`
- §3 movement table + equality groups → `release_normalizer.movement_decision`, `group_decision`; tests movement/equality suites + b2/b4 rows
- §5 AC derivation → AC `derive_release_floors.py` with steps (a)-(f) incl. version preservation
- §6 normalizer phase → `release_normalizer_run.py` (double-compute, working-tree transport, fixed point, exit re-observation), `release_normalizer_main.py` (routing), Makefile `release-prepare` first line; exactly two operator commands preserved (no alias — tests invoke modules)
- §7 card + continue → `release_train.py` (disposition enum, PreviousCompleteAnchor variant, card format, `_resolve_anchor_identity`, `_default_rederive` before the release-FF), `release_continue_check.py` (progress allowlist + anchor-missing guard); tests card-schema/rederivation/anchor-resolver + the drift-refusal tripwire
- §8 status engine → `release_status.py` (uncollapsible four states, RemoteCompletion factory refusal, DONE), `release_status_builders.py` (per-fact pypi/npm/image rows), `release_status_gates.py` + the two continue gate sites (tripwire-proven), `release_status_report.py` (failure-preserving stops, recorded-observation loader), `read_oci_revision`
- §9 acceptance → this packet's section 2
- §10 gates → the round ledger (section 6)

## 5. Normative-doc conformance — STAMP-AT-LAND
`docs/release.md` diff over the full range (expected: unchanged clauses
listed); design-doc wording changes after cadfb4eb: the coverage-table
amendment (d14ef611, reviewed in R2's round) and the ac-image
both-halves correction (12fb4e56, reviewed in R3's round) — each with
its review record. The reconciliation refinement from the b4 controls is
CODE-side only; the design text's §2 blanket anchorless wording vs §3's
conflict classification meeting point is documented here for the gate's
trace.

## 6. Round review ledger — STAMP-AT-LAND completes SHAs
- R1 `b4c0daca` (4 commits incl. design doc) — release-review ACK; landed
- R2 aweb `d14ef611` (3) + AC `aa73f30a` (1) — ACK both repos; alice integrated
- R3 `12fb4e56` (11) — seam-scoped ACK; landed
- R4 `95d1fc0e` (4) — ACK with pre-registered criteria; landed
- comparator hardening `3af559ec` (1, alice's finding) — ACK; landed
- R5 `1f0a1e63` (6) — ACK, three invariants verified at source; landed
- R6 code round — STAMP-AT-LAND
- AC stamper round `35e204a5` (dev2's lane) — closes the ac-image anchor's stamper half
- Deferred anchor assertions: aw-cli's aw-v anchor → its own assertion rides the movement predicate (`test_release_normalizer_movement` CLI rows + `derive_capture_specs`); ac-image stamper → AC `verify_release_image.py` (dev2's round) + reader `read_oci_revision`
