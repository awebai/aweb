# aben shipment-gate evidence, second submission

Built to plan-critic's re-entry protocol (their mails 95300228 verdict,
de1e8dd9/48901647 alignment, and the protocol alice relayed): a fresh
complete cumulative packet over the amended final heads, opening with
the blocker-closure matrix. Every SHA is pasted from command output.

## 0. Blocker-closure matrix

Each of the seven verdict findings: the fix (landed main SHA), the
real-entry regression test that reproduces the gate's probe, the red
result recorded before the fix, and the enforcing source.

| # | Finding | Fix (aweb main) | Real-entry regression test | Recorded red | Enforcing source |
|---|---------|-----------------|---------------------------|--------------|------------------|
| 1a | OCI identity never captured; occupied-AC world cannot normalize | A1 `21e89fa6` | `test_release_normalizer_canonical_entry.CanonicalEntry.test_world_with_existing_ac_image_reaches_normal_form` (subprocess over OCI wire protocol) | `STOP anchorless-version (ac-image)` exit 1 where exit 0 was owed | `release_normalizer_main.route_discovery` GHCR branch; `assemble_captured_world` oci anchor derivation |
| 1d | Silent malformed filter | A1 `21e89fa6` | `...test_malformed_near_version_candidate_stops_by_name` | clean pass where the named stop was owed | `_version_namespace_candidates` (capture) + reconciler stop |
| 1b | Shared-manifest double apply crash | A2 `4fd621b0` | `...test_shared_manifest_pair_patches_once_and_converges` | `RuntimeError: expected exactly one 'version = "0.5.16"', found 0` | `release_normalizer_run` edits_by_path grouping + divergent-manifest-patch stop |
| 1c | Apply covers only versions | A4 `13d7f6d9` | `...test_awid_move_cascades_floor_lock_and_server_by_policy`, `...test_failing_invariant_stops_by_name_after_the_patch`, `...test_patch_output_prints_base_shas_and_the_exact_diff`, `...test_dirty_checkout_stops_by_name`, `...test_moved_main_stops_by_name`; unit `test_release_normalizer_main.Routing.test_exit_reobservation_covers_every_declared_target` | one awid commit produced no floor/lock/server movement; no transport output; preconditions silent; primary-only reobservation | `release_normalizer.normalize` R1 closure; `release_normalizer_run` floor/lock apply; `release_normalizer_main.worktree_stops` / `run_invariants` / `reobserve_result` |
| 2 | Prepare discards the projection; recovery cannot reach a card | A5 `322964cb` | `PrepareEntry.test_one_command_prepare_builds_the_card_from_the_projection`, `...test_patch_needed_ends_the_command_before_any_test` (the operator's subprocess); card bytes `test_release_prepare_projection` (5) | select_artifacts re-derived a weaker world; no moving-with-recovery construction path existed (select_artifacts DELETED) | `release_train.selections_from_projection`, `_main` prepare branch running `run_phase()` in-process |
| 3 | Dependency-only changes invisible | A3 `857e9d9a` | `...test_dependency_only_manifest_change_moves_the_artifact` + 5 unit controls both kinds both directions | exit 0 "normal form" where the dep move was owed | `release_normalizer_capture.content_changed(masked=)`, `_mask_version_field` (structurally anchored per review) |
| 4 | Wrong-source completion accepted | A6 `4ffa2ff5` | `SourceBinding` suite (7): wrong-source moving/recovery mutations, unproven, extra-artifact, patch-drift, card-SHA derivation | the gate's probe verbatim: fresh unmoved@V with arbitrary SHA returned no stops | `release_continue_check.verify_card_against_world(expected_sources=)`, `release_train.expected_completion_sources` |
| 5 | Status not terminal authority | A7 `dc067ec6` | `test_release_status_terminal` (12: github rows, observed source tags, bearer-required registry, assembly completeness, B5 real-path re-drive w/ false-state mutation); train pins `test_terminal_gate_refusal_keeps_the_card_and_names_the_rows`, `test_default_terminal_gate_is_the_real_status_sweep`, `test_continue_failure_path_preserves_the_refusal_through_the_entry` | organic red: the terminal gate refused DONE against the existing fixtures with the full 46-row inventory rendered; `del token`; unrouted github targets | `release_status_gates.rows_for_artifacts` (complete routing), `release_train._default_terminal_gate` + effect rows, `_continue_main` via `stop_report_with_probes` |
| 6 | Launcher strings the interface; opaque monitor | A8 `6409ea13` (aweb) + `22ab8bbe` (AC) | `test_fixed_continue_commands_are_the_reviewed_defaults`, `test_derive_receives_the_complete_card_projection` (argv-dumping stub), `test_monitor_record_is_required_typed_and_source_bound` (7 mutations incl. exactly-one), `test_release_workflow_monitor.sh` (stub-gh, both directions), AC `test_check_pending_migrations.sh` | the launcher's derive sed with versions baked in (quoted in ledger); monitor exec'd gh watch with no record | `release_train._CONTINUE_FIXED_COMMANDS` / `continue_commands` / `_require_monitor_record`; `release-workflow-monitor.sh` record emission; AC `check-pending-migrations.sh` |
| 7 | b2 bridged world; noisy record | dev2 `1397df80` (fixture self-contained, bridge deleted) + A9 `e6e26295` | dev2's b2 pair + 3 mutations; zero-ResourceWarning full-scope run | the bridge; ResourceWarnings in the first packet's record | dev2's fixtures; leak closes in capture/builders/suite teardowns |

## 1. Final heads and ranges

aweb main FINAL: `e6e2629575a1ef03e81ca09946cc4914ab1b62c5` (the A9
landing); full aben range `69e2fd80..e6e26295`. AC main FINAL:
`22ab8bbe3f22be47826edcf7fe1b9acf7a5bd615`. Amendment landings
in order, each the release-review-ACKed diff byte-identity-verified at
push time (the held-ancestor mechanism, adopted by the reviewer after
independent reproduction and used by alice for A8): A1 `21e89fa6`, A2
`4fd621b0`, A3 `857e9d9a`, A4 `13d7f6d9`, A5 `322964cb`, A6 `4ffa2ff5`,
A7 `dc067ec6`, A8 `6409ea13`; interleaved dev2 rounds `1397df80`,
`81cf8d47`. AC main: `22ab8bbe` (= A8 AC + `35e204a5` lineage). R1-R6
pre-verdict rounds as in the first packet's ledger (b4c0daca, d14ef611
+ aa73f30a, 12fb4e56, 95d1fc0e, 3af559ec, 1f0a1e63, 6f4a8bd0).

## 2. The assembled entry points are the acceptance path

Protocol item 4. Column B and the gate probes run through the ACTUAL
entries, not component fixtures:

- prepare-to-card: `release_train.py prepare` as a SUBPROCESS builds a
  nine-row card equal to the normalizer projection over the synthetic
  awebai pair and the wire-protocol stand-in; PATCH NEEDED ends the
  command before any test with no card and no gate run
  (`PrepareEntry`, both directions).
- capture/patch: the canonical entry (release_normalizer_main
  subprocess) carries B1's shape (AC image via real OCI reads), the
  malformed stop, the A2 crash, the A3 blind spot, the A4 cascade with
  locks and floor in one transport diff at a fixed point.
- continue-to-DONE: the full-fixture continue reaches DONE only through
  the terminal sweep; a blocking row refuses and keeps the card
  (`ContinueTrainTests` terminal pins); the failure path is proven at
  the operator's subprocess.
- Column B recorded rows: dev2's self-contained fixtures (bridge
  deleted, provenance per-value) run under `make test-column-b`; the
  aben suite and Column B are GATE ROWS now (release-aben 33s,
  column-b), so the acceptance evidence runs at every release.
- B5 through the REAL path: the historically true world served over the
  wire reads 3 present / 6 absent at exact cardinality, done() False,
  lying integrity = conflict (test_release_status_terminal.B5RealPath).

## 3. Live-wire evidence (alice-authorized read-only probes)

- `evidence/aben-live-ghcr-probe.txt` (sha256
  `7e2e3103caafaac844e5a537765a1cbf5650d1da4de5dd1b0f09d051e2c4f338`):
  BOTH halves preserved - the red 403 that exposed the raw-PAT gap
  (fixed as `ghcr_bearer` at every env boundary) and the green reads:
  live `awebai/awid:0.5.16` revision label == `e5524b4b...` and
  `awebai/ac:0.7.14` == `efd19f41...`, the recorded publication SHAs
  exactly. OPERATIONAL FINDING: live `awebai/ac` serves legacy tag
  `0.3` - a real near-matching candidate; the first real prepare stops
  malformed-version-candidate until the tag is removed (human-approved
  registry write) or the stop is accepted. On alice's desk.
- `evidence/aben-live-uv-lock-proof.txt` (sha256
  `d32f6a86d920c31bc8daefb10b104a8e0f03b5634b17fb33dae959f9c14d748a`):
  the A4 production lock command against a real awid copy with the
  patch-phase version bump: lock changed (own-version entry
  regenerated to 0.5.17), `uv lock --check` consistent.

## 4. Final focused test record

`evidence/aben-final-test-record-e6e26295.txt` — one run over the
final landed heads at the branch stamp commit (whose only deltas vs
main are this document and one test-teardown server_close line, in the
stamp micro-round with release-review): the gate's own aben targets as
the gate runs them (test-release-aben OK, test-column-b 13 OK with B1
running for real), the full 28-module aben scope under
`-W error::ResourceWarning` (OK), the four shell selftests (floor 7,
tag helpers 3, workflow monitor 2, AC pending-migrations 2), and AC's
derive contracts (7 OK). The first record of this run found ONE
residual interpreter-shutdown socket from the observe-CLI suite's
missing server_close; the source was closed and the record re-run -
the record's SHA below is the clean second run, with the first
preserved beside it as the red half
(`aben-final-test-record-e6e26295.txt.first-run`, sha256 in-file).

## 5. Evidence-reuse justifications (protocol item 5)

- First-packet component evidence (R1-R6): NOT reused - every A-round
  changed subject code beneath it; the closure matrix's tests are the
  replacements. The first packet remains fetchable at `7938cab9` for
  the verdict trail only.
- dev2's fixture provenance records: reused as landed on main
  (`1397df80`); their subject (fixtures + loaders) changed only by
  dev2's own reviewed rounds since.
- The two live-probe files: fresh this submission, sealed above.
- `aben-b5-rendered-output.txt` (first packet): SUPERSEDED by the
  real-path B5 suite; retained for history only.

## 6. Round review ledger — release-review ACKs

A1 d94a8f06→21e89fa6 (transfer verified 27690/27690 cmp 0); A2
6efd7f7d→4fd621b0 (3631/3631); A3 5a9f1b70→857e9d9a; A4
5f23a041→13d7f6d9 (6-commit range incl. landed A3); A5
ba5358a3→322964cb; A6 85924926→4ffa2ff5; A7 27071487→dc067ec6; A8
3a7abc27→6409ea13 + AC 22ab8bbe (alice integrated, AC-first per the
reviewer's measured constraint); A9 b03cadf1→`e6e26295` (landed minus this document, which rides the branch until the verdict - the same hold as the first packet). Reviewer
suggestions were never folded silently: each landed as its own
reviewed commit in the following round (json mask anchor, ls-remote
comment, invariant timeout, coupling guard, field rename, self-reported
marks, tag-branch keying, exactly-one record).
