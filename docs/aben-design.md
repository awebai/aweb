# aben: release normalization, extraction, re-derivation, and read-back

This is the single self-contained normative design for aweb-aben. It
supersedes every seam revision and review-thread file that preceded it;
nothing outside this document (plus, after approval, `docs/release.md`
and the code) is authoritative. Review lineage lives in the aben task
record and the plan-critic mail thread; it is history, not authority.

Authority position, unchanged from `docs/release.md`: exactly two
operator commands (`release-prepare`, `release-continue`); the transient
git-local card is the sole release artifact; no plan file, no release
IDs, no receipts or attestations, no snapshots, no persisted state of
any other kind. The normalizer is a phase of prepare; tests invoke its
module entry; no make alias exists.

## 1. Canonical artifact and edge metadata

`ARTIFACTS` in `scripts/release_train.py` remains the one owner of
artifact membership and gains these fields (all contract-tested with
nested exact keys and types):

- `content_scope`: repository paths whose change constitutes artifact
  content movement. Scopes exclude the artifact's own `version_source`
  manifest and its owned locks/version mirrors (normalized metadata,
  not content drivers) - this exclusion is what makes normalization a
  fixed point by construction.
- Anchor coverage table (what the bidirectional contract test proves,
  and its two named boundaries): the workflow-emitted tag prefixes
  (server-v, awid-service-v, awid-v, channel-v, pi-v, skills-v,
  a2a-gw-v) are verified against the publishers in both directions;
  aw-cli's aw-v anchor is EXCLUDED from that test because its tags are
  created by train/sync code, not those workflows - it carries its own
  assertion against the code that creates them (R3, with the movement
  predicate that consumes it); ac-image's `v` anchor is excluded from
  the same test for the same reason - continue creates it - and carries
  its own assertion against the code that pushes it.
- `anchor`: `tag_pattern` for EVERY artifact (server-v*,
  awid-service-v*, awid-v*, aw-v*, channel-v*, pi-v*, skills-v*,
  a2a-gw-v*, and ac-image's bare v* in the AC repository). A release's
  identity is the tag in its own repository: it is all in the repo, so
  the train never asks a registry what a release hash was. Identity
  resolution therefore makes NO network calls; registries are asked
  only which versions are published, which is the one fact git cannot
  answer. A bidirectional contract test asserts each canonical anchor
  value equals the actual publisher's tag emission, red on either
  side drifting.
- `occupancy_unit`: the same-version targets that must reconcile to one
  published P (composites: aw = external GitHub Release v* plus all
  seven npm packages; skills = npm package plus the zip release assets).
- `required_current_outputs`: the within-member completeness set
  (release binary assets, both OCI platforms, the five skill zips).
- `owned_locks`: lock path plus offline regeneration method. Populated:
  awid/uv.lock, server/uv.lock, ac backend/uv.lock (method: `uv lock`,
  measured 3ms, verified offline under UV_OFFLINE=1; uv lock --check
  fails on version mismatch, so these are real consumer invariants).
  channel and pi-extension entries are EMPTY: measured, `npm ci` exits 0
  on a root-version mismatch, so the npm lock root version has no
  consumer; the two-field JSON transformer (provably equivalent to
  offline npm output) is the named mechanism if that ever changes. The
  no-churn measurement becomes a regression fixture.
- Typed edge obligations: each `ReleaseEdge` carries a SET of
  obligations from {publication-order, conditional-publication-order,
  consumer-version-policy, post-publication-consumer-derivation,
  consumer-no-mutation-decision, same-commit-content, version-equality,
  deploy-order}, each holding a key into the rule table (section 4) or
  the enforcing invariant. Domain equality per obligation type, both
  directions: an obligation without an enforcement/rule row fails, and
  an orphaned rule fails.

Extraction boundaries (one implementation, executed as shared pure
predicates on the same semantic inputs wherever applicable; phase-
specific orchestration remains distinct, names its own inputs and
postconditions, and preflight never pretends to run a post-publication
resolution):

- `scripts/check-release-floor.sh`: the declared-floor==expected-version
  predicate (parse exactly one `awid-service>=` literal; refuse
  multi/absent; equality check). Callers: the pypi workflow step
  (one-line, unconditional, status-propagating - contract-tested
  including absence of suppression patterns) and the normalizer.
  Public-served observation is a SEPARATE predicate (next item).
- `scripts/observe_public_target.py`: ~10-line CLI over the train's
  `observe_public_target` with exit contract present=0 / absent=1 /
  unavailable=2 / malformed=3. Callers: workflow served-checks, the
  normalizer, the status engine.
- `remote_tag_sha` (direct/peeled tag resolution): consolidated to one
  script sourced by the workflows and the reconciler.
- AC repo `scripts/derive_release_floors.py`: section 5.
- The launcher digest/verify strings are retired: the train passes
  `versions["ac-image"]` and its derived `ac_derived` SHA as argv to the
  existing repo scripts. The migrate launcher string is retired; the
  train's migrate edge invokes the fixed repository command
  (`prod-migrate-direct` -> `aweb_cloud.cli migrate`; credentials via
  PROD_ENV_FILE, never argv; postcondition is the migration executor's
  database-backed state).
- Deliberate non-extractions: publish_tag/require_release_sha (publisher
  -only actions with no second caller), the two-line .gitignore cleanup
  (position-pinned by contract test), gateway==server (train code,
  imported not copied).

## 2. Version grammar, discovery, and anchor reconciliation

Grammar: `^v?MAJOR.MINOR.PATCH$`, numeric components, no prerelease or
build metadata; ordering is numeric tuple comparison, implemented once.
In OCI NAMESPACES ONLY, `v?MAJOR` and `v?MAJOR.MINOR` with wholly
numeric components are LINE POINTERS - moving channel tags, not
releases. They are logged and dropped at discovery, never occupancy,
never P, never a source anchor, never previous-complete or recovery
evidence, and never an expected release output. Dropping them at
discovery is what makes that structural rather than merely unreached:
a tag that never enters the world cannot be dereferenced, so a channel
pointer's digest or revision label can never be adopted as a release's
identity. Exactly three numeric components remain strict release
candidates and occupy; three-component near-misses (`0.7.15rc1`),
four-or-more components (`1.2.3.4`), and other digit-led shapes still
stop by name. PyPI, npm, GitHub releases and source tags do NOT inherit
this exception.

Non-matching candidates in non-version namespaces never occupy and are
logged: `latest`, `sha-*`, and BARE source-commit tags (`^[0-9a-f]{7,40}$`
- the AC image publisher pushes its `:SHA` unprefixed, so roughly half
of them begin with a digit and would otherwise read as near-versions).
A source-commit tag is a commit identifier, not a version, and the
`:SHA` output has its own inventory row rather than an occupancy claim. A near-matching candidate in a version namespace
is a named stop (`malformed-version-candidate`) unless it is PROVABLY
below the candidate in play, in which case it is history and is logged
- the same principle as "absence below P is history", which this rule
previously failed to apply. Provably below means: comparing numeric
components pairwise, the FIRST differing component is lower. Equal-but-
incomplete (`0.7` against 0.7.15) and equal-with-suffix (`0.7.15rc1`
against 0.7.15) are ambiguous rather than lower and still stop; so does
a candidate with no numeric prefix, and so does any near-match in a
unit carrying no conforming version to place it against. Ignored
history is ignored completely: it can never become P, a content anchor,
previous-complete evidence, or recovery evidence. The rule applies to
every version-bearing unit and source-anchor namespace, not to images
alone. Registries keep old shapes
(ghcr.io/awebai/ac serves a two-component `0.3` from 2026), and the
train does not mutate the published world to quiet its own checker. Yanked PyPI releases,
deprecated npm versions, and draft/prerelease GitHub releases with
grammar-conforming tags ALL occupy (a yanked version is a burned
number). A deleted registry version with a surviving source tag: the tag
occupies.

Discovery: one listing document per version-bearing target (pypi package
doc, npm package doc, GHCR v2 tags list, GitHub releases list),
paginated reads bounded at 5 pages / 500 entries per namespace;
cursor/Link traversal must prove end-of-list; hitting the bound is the
named stop `history-exceeds-discovery-bound`, distinct from
`unavailable`. Roughly 13-15 reads per pass; seconds.

Anchor reconciliation per artifact, before the movement table: discover
the greatest relevant version per unit member; candidate P = max
occupied over unit members and source anchor; then classify:

- all required members + anchor at P: reconciled published P;
- some members at P (any required member missing, anchor presence
  irrelevant): recoverable or conflicting partial (below);
- anchor only at P: partial;
- all members at P, anchor absent: `anchorless-version` stop;
- absence below P: history, never a stop.

Partial states fork on evidence:

- RECOVERABLE: candidate equals current reviewed manifest intent; every
  occupied member with observable source identity matches it; no
  conflicts; previous complete anchored P identifiable (it is the
  content-diff anchor during recovery). Disposition
  `moving-with-recovery`, derived at card time like everything else;
  recovery is a rerun of the two commands through the existing
  exact-adopt publishers. For pypi/npm members (no source identity in
  listings) recoverability is provisional by occupancy; the staged-byte
  comparison at publication decides authoritatively.
- CONFLICTING/AMBIGUOUS: occupied member proves different source/bytes;
  source unboundable; version disagreement; previous complete P
  unidentifiable. Named stop.

aw cross-repository binding (executable, no stored claims): peel the
aweb `aw-v{P}` tag and the external `v{P}` tag; the external Release
must resolve to the external tagged commit; the external tree excluding
`.github` must equal the `cli/go` subtree of the aweb tagged commit via
the exact mode/blob/path listing transform the sync workflow itself uses
(aw-release.yml's ls-files -s comparison) - not a subtree-hash shorthand
unless byte-equivalence is separately proven.

## 3. The movement/version table and equality groups

Content-to-version guards that exist today: server
(`check-server-version-bump.sh`) and the CLI tag-history +
content-diff rule. All other artifact scopes have none; the normalizer
supplies the generalized predicate from canonical scopes. Per artifact,
with P from reconciliation, M the manifest version, C = content differs
between the anchor at P and HEAD over the scope:

- C=false, M==P: normal.
- C=false, M>P: named stop `contentless-or-predeclared-version` (no
  mechanical rollback of reviewed intent).
- C=false, M<P: named stop `manifest-version-behind-public`, always.
- C=true, M>P: accept iff M free on every declared target and monotonic
  against the reconciled maximum; occupied -> `version-occupied` stop.
- C=true, M<=P: deterministic patch to next-patch(P) ONLY when the
  compatibility input is `none`; otherwise named stop
  (`compat-version-decision-needed`).

CLI exception, explicit: aw-cli's next version remains mechanically
derived from tag history plus content diff (the existing rule). An
occupied lower intent (the 1.34.5 case) mechanically re-derives the next
free patch and normalization continues; the manifest-backed
`version-occupied` stop applies to human-chosen manifest versions, not
to the CLI's derived row. These are different rows of the same table and
do not contradict.

Equality groups (awid-service/awid-image via the card invariant;
aweb-server/a2a-gateway-image via the train invariant), shared-candidate
algorithm:

1. validate current manifest equality (failure is the invariant stop);
2. M := shared manifest version; reconcile each member independently in
   its own unit;
3. if every moving/lagging member can publish or recover AT M and every
   complete member is exact at M: candidate is M, no patch (lagging
   members marked moving/recovery at M);
4. next-patch(max complete/occupied across the group) only when M cannot
   serve (conflicting occupancy at M, or non-monotonic);
5. compatibility stop rule applies before any minting;
6. patches labeled with the driving member; second pass empty.

Mutation controls: lagging-member-absent-at-M must produce recovery at M
with no patch; lagging-member-conflicting-at-M must produce one shared
next patch with both manifests moved exactly once.

## 4. Same-cycle consumer policy (total; silence is not a rule)

- awid-service -> aweb-server (R1): when awid moves, server's floor
  literal := awid's version (the extracted equality predicate);
  server/uv.lock re-locks (workspace-honest pre-publication).
- awid-service -> AC backend (R2), aweb-server -> AC backend (R3):
  post-publication derivation in continue via
  `derive_release_floors.py` (section 5).
- aw-cli -> pi-extension (R4): NO range move (caret ^1.22.x is a
  compatibility minimum admitting 1.x by intent); NO lock move (measured:
  the shipped tgz's files allowlist excludes the lock; the built bundle
  contains zero aw imports - aw is an installed-binary dependency; both
  measurements are regression fixtures). The publication-order edge is
  enforced iff a reviewed pi change moves the floor - exactly what the
  publisher implements.
- channel-core -> channel/pi, skills-sources -> pi/skills,
  server-source -> awid-image: same-commit bundled inputs, enforced by
  build provenance and the bundle-identity package gates, never floors.
- Non-moving consumers are never churned; a floor is a minimum-
  compatibility claim.

## 5. The AC derivation script (post-publication, in continue)

`derive_release_floors.py` in the AC repository owns the artifact-to-
floor policy as a TOTAL map over the card artifact set: every accepted
artifact key maps to a floor rule or the literal `none`. The train
passes the complete raw card artifact set with versions and
dispositions - never pre-derived pairs. Order: (a) require incoming key
set == policy key set exactly (either-direction mismatch refuses - this
is the independent completeness fact; a policy row deletion fails HERE,
before any lock work, and a new train artifact without an AC decision
fails closed); (b) filter to moving rows with non-none rules and derive
targets; (c) edit exactly the allowlisted floors; (d) `uv lock`; (e)
verify the lock resolves each target package at exactly the served
version (refusal names package/wanted/got); (f) prove the AC project
version is byte-equal before and after derivation AND equals the card's
approved ac-image version - the derive edits allowlisted FILES, but the
version field inside them is not the derivation's to touch, and
`final_ac_sha` is REJECTED if it changed. The card is the holder of the
approved AC version throughout: the ac-image `:VERSION`/`:SHA` output
rows derive their expected version from the card, never by rereading the
post-derivation manifest. Compute and local-apply only; commit/push
remain the train's. Controls: policy-row deletion ->
incomplete-derivation refusal at (a); forced partial floor application
-> lock verification refusal at (e); a mutation changing the AC project
version inside an otherwise-allowlisted derive diff -> refusal at (f);
no-move card -> empty derivation, no lock regeneration.

## 6. The normalizer (first phase of release-prepare)

Inputs: exact aweb/AC main SHAs from clean checkouts; live registries
via the observation boundary; canonical metadata and policies. Three
outcomes: NORMAL FORM (proceed to gate); PATCH NEEDED (below); NAMED
STOP. Patch allowlist, exhaustive: artifact manifest versions; owned
locks (section 1); the server awid floor (R1). Anything else needed is
a named stop, never a patch.

Patch transport: the normalizer edits only allowlisted files in the
current clean worktrees, prints base SHAs and the exact changed-file
diff to stdout, exits PATCH-NEEDED before any test, and leaves ordinary
working-tree changes for normal review, commit, and integration. It
writes no file of any other kind. The next prepare recomputes from
current mains; there is no stored patch to go stale.

Determinism and races: capture observations once in memory; compute the
patch twice from the captured inputs; require byte-identical output
(resolver-nondeterminism detector - alice's named stop in its ruled
within-invocation form); local apply; fixed-point pass (second
derivation on the patched tree must emit an empty patch; anything else
is `non-convergent-normalization`); immediately before leaving the
cheap phase, re-observe load-bearing registry facts and stop under real
names (`version-occupied` / `registry-conflict`) if the world moved.
Dirty checkouts and mains movement stop; reruns recompute.

Invariant pass (read-only, after patch computation): gateway==server and
the awid card equality via imported train/card code; moving artifacts
free on every declared target; unmoved artifacts present at exactly
their manifest version; the release-coupled floor equality; the
same-cycle lock property via `check-python-locks.sh`'s check half under
UV_OFFLINE=1 (measured 0.14s; its self-test is the gate's mutation
control); the two inventory checks by exact single-test selectors
(canonical migration chain, suite-map exactness; 0.75s and 0.08s
measured). Budget: seconds, with the 13-15 discovery reads bounded.

## 7. Card schema and continue-start re-derivation

The card (transient, git-local, consumed; closed exact schema,
contract-tested to nested keys and types) changes minimally:

- `moves` becomes a disposition enum: `moving` / `unmoved` /
  `moving-with-recovery` (strict extension).
- `previous_complete_anchor` {version, kind, source_identity}: an exact
  tagged variant - REQUIRED for `unmoved` and `moving-with-recovery`
  rows, FORBIDDEN for `moving` rows. Current expected identities for
  moving artifacts derive from the card's SHAs plus the canonical
  resolver; nothing polymorphic is stored; no diagnostics, snapshots,
  or status ever enter the card.

Continue-start, before the release-branch fast-forward (the first
irreversible edge - it triggers every publisher): invoke the SAME
normalizer in no-apply mode over the exact card SHAs with freshly
captured observations; exact-compare its complete result to the card's
projection with ONLY these permitted transitions per artifact: absent ->
complete at card version; absent -> recoverable partial at card version;
recoverable -> complete. Any other difference stops with the
reconciler's own vocabulary (newly discovered greater version,
same-version conflicting identity, changed anchor, unbounded history,
conflicting partial). Historical lower complete versions are never
conflicts. A normalizer result field not classified into the allowlist
makes any drift a stop; a contract test asserts the allowlist names only
existing fields. The existing continue_environment base checks remain.

## 8. Output inventory, PRESENT semantics, and DONE

Registry-as-authority, alice's ruling, stated in full: (1) at
publication the exact publisher builds once, compares staged bytes to
every registry file/tarball, fail-closed on mismatch/extra/missing; (2)
the workflow monitor establishes that publisher ran to success at the
exact release SHA - a necessary precondition for moving/recovery
packages in that invocation, never publication status; its result is a
strictly typed remote-completion record {workflow, run_sha, conclusion}
and carries no artifact identity; (3) fresh registry read-back is the
durable terminal authority: pypi - exact package/version, exactly one
sdist `{normalized}-{v}.tar.gz` and exactly one wheel matching the
exact-publish script's three-tag-segment regex, no extras, and the
registry-reported per-file sha256; npm - exact package/version and the
registry's declared integrity verified against freshly fetched tarball
bytes; the source tag/anchor is a separate required row; (4) on later
retries the immutable registry identity plus source anchor ARE the
public release identity - no historical staged-byte claims without a
receipt, and no receipt exists; (5) status language is "registry
artifact present with immutable public identity and source anchor",
never reproduction or rebuild claims.

The complete output/effect inventory (each independently checkable fact
is its own four-state row: OBSERVED-PRESENT / OBSERVED-ABSENT /
CONFLICT-or-UNPROVEN / UNAVAILABLE; UNPROVEN never renders PRESENT;
unavailability is never absence and never success):

- aweb-server: pypi sdist+wheel rows per the filename contract, per-file
  sha256 rows, served-version row; tag `server-v{V}`.
- awid-service: same shape; tag `awid-service-v{V}`.
- awid-image: version-tag index digest; both platforms in the index;
  source tag `awid-v{V}` as its own row; mutable `latest` digest equal
  to the version digest (the publisher promises latest).
- a2a-gateway-image: same shape; tag `a2a-gw-v{V}`; latest row.
- aw-cli: aweb tag `aw-v{V}`; external tag `v{V}`; the exact tree
  binding row; GitHub Release with the exact canonical asset template
  the publisher enforces (aw-release.yml:87, contract-tested against
  it): aw_{V}_linux_amd64.tar.gz, aw_{V}_linux_arm64.tar.gz,
  aw_{V}_darwin_amd64.tar.gz, aw_{V}_darwin_arm64.tar.gz,
  aw_{V}_windows_amd64.zip, aw_{V}_windows_arm64.zip, checksums.txt;
  wrapper plus six platform npm packages, each with integrity rows.
- channel-plugin / pi-extension: npm rows; tags `channel-v{V}` /
  `pi-v{V}`.
- skills: npm rows; the `awebai/aweb` repository release at tag
  `skills-v{V}` with every required zip asset - source tag and release
  object are the same repository and namespace, stated so they cannot
  be checked in different ones.
- ac-image: `:VERSION` and `:SHA` rows (the workflow publishes exactly
  these two, no latest); `:SHA` digest must equal `:VERSION` digest;
  index platforms; source tag `v{V}` in the AC repository as its own
  row, created by continue at the exact final derived AC SHA.
Durable status proves two required facts per image - the immutable
registry object and the exact source tag - and does NOT prove the
first was built from the second. That correspondence is enforced at
PUBLICATION, by the release-image verification and the publish-time
byte comparison that gates exact-adopt, rather than re-derived on
every prepare from a label the registry happens to carry.

- Effects: aweb release pointer == card aweb SHA; ac release pointer ==
  final AC SHA; marketplace repository pointer via the
  pointer-adapter-marketplace-pointer read (claim limited to repository
  pointer state; no consumer-served probe exists and none is claimed);
  site branch pointers when the card requests them (branch-pointer state
  only; provider-served-commit is not claimed - no observable exists);
  production configured digest, provider-running digest, live /health
  sha+digest, and the migration executor's database-backed postcondition
  through its own command's verdict.

Ordering enforcement (three kinds, used precisely): predecessor-rows
gates - the complete per-output read-back table PRESENT for all
intended aweb/AWID outputs immediately before AC derivation and gate,
and complete channel+skills rows before marketplace mutation; consumer
proofs - floor equality and lock-resolution as derivation
postconditions; remote-completion - the monitor record, necessary for
operation completion, never predecessor-state evidence. No obligation's
enforcement is loop position.

DONE: fresh OBSERVED-PRESENT for every output of every artifact the
card relies on - moving, recovery, AND unmoved - plus every requested
effect, at the resolved identities. Absence, conflict, or
unavailability anywhere is not DONE. Stop reporting: the original stop
code and message are primary; the bounded sweep renders failed probes
as UNAVAILABLE rows; exit is nonzero for the original stop regardless of
reporting; mutation-tested with an edge refusal and an independent probe
failure injected in one run, both visible.

## 9. Acceptance (Column B, red-first, pinned)

Every fixture names its exact subject; none is authored against a
lookalike:

- B1 narrow card. Repository state: aweb
  `5a55f7ce6b4dbb86dc2901f7c687e172e39db3af`, AC
  `47060200c53d30835cbb35cbcb5d073cbe3dc5d3` (the pre-bump mains).
  Expected: each artifact's OWN content predicate over its OWN scope
  drives its row, and the patch is EXACT: awid-service and awid-image
  0.5.15 -> 0.5.16 (awid/ content differs from the 0.5.15 anchors), and
  independently derived ac-image 0.7.14 -> 0.7.15. A resolver emitting
  any other version fails the fixture. AC's movement evidence, measured
  at the fixture commits (efd19f41..47060200): 14 files in the whole
  diff; 12 after this design's own exclusions (backend/pyproject.toml
  as version source, backend/uv.lock as owned lock); 5 under
  backend/src + backend/tests, among them
  backend/src/aweb_cloud/migration_paths.py - product source the image
  ships, which alone justifies movement. The exhaustive in-scope count
  is fixed by the canonical `content_scope` populated in R1 and the
  fixture binds to that field, not to a prose count. No wide-release
  policy exists and none is encoded: an AC fixture WITHOUT scope
  changes since its anchor must yield no AC row in the patch, and that
  variant is part of the fixture pair. Control: the same SHAs with EACH
  artifact's scope content anchored at its own prior tag/label ->
  normal form.
- B2 stale pre-authorized CLI version. Fixture: recorded registry
  document set - npm @awebai/aw serving 1.34.5, aweb tag `aw-v1.34.5`
  at `2455e7a127ab5f216477a0af114cb69e5b0caa74` (provenance: the cycle
  record, verified 2026-08-13). Expected: the CLI tag-history row
  mechanically derives 1.34.6 and normalization CONTINUES - no stop, no
  human choice, and no contradiction with the manifest-backed
  version-occupied stop (different table rows). Control: fixture without
  1.34.5 published -> 1.34.5 derived.
- B3 single-floor derivation. Fixture: the preserved launcher-string
  variant (verbatim in the task record) and AC
  `158504ae1f18a7105adc2bbd579381357805b4d9` with pypi serving aweb
  1.27.1. Expected: control one - policy-row deletion refuses
  incomplete-derivation at the domain check before lock work; control
  two - forced partial floor application refuses at lock verification
  naming aweb/1.27.2/1.27.1.
- B4 impossible pre-registered shape. Fixture: intent server 1.27.2 +
  a2a-gateway 1.27.3 (provenance: alice's recorded fourth-revision
  expectation). Expected: the equality-group validation refuses before
  any card exists. Control pair (the phantom-release directions): server
  complete at M with a2a lagging absent -> recovery at M, no patch;
  a2a conflicting at M -> one shared next patch, both manifests moved
  exactly once.
- B5 false publication status. Fixture: the recorded registry
  observation set from the first continue stop of 2026-08-13 ~21:30Z
  (provenance: the review-thread inventory, each fact verified against
  its public source at the time): npm @awebai/aw@1.34.6 present; ghcr
  awid 0.5.16 present; ghcr a2a-gateway 1.27.2 present; pypi
  awid-service 0.5.16 ABSENT; pypi aweb 1.27.2 ABSENT. Expected: the
  status table renders exactly those THREE artifacts' rows PRESENT and
  the TWO pypi rows ABSENT - the historical packet's "nothing was
  published" is unwritable because the table is the only status path.
  Control: probe layer failing -> UNAVAILABLE rows plus the original
  refusal plus nonzero (the two-failure injection).
- Normalizer-drift stop: a deliberately nondeterministic resolver stub
  must trigger the within-invocation double-compute refusal; a registry
  document changed between capture and the exit re-observation must
  stop as version-occupied/registry-conflict by name.

Column A rows remain owned by their existing mechanisms; Column C
(vacuous/skipped guards) is explicitly not discharged by aben and its
ownership question sits with Juan.

## 10. Implementation plan and gates

Engineering decomposition in six rounds: R1 canonical metadata +
contract tests; R2 extractions and workflow call replacements; R3 the
normalizer phase with fixtures B1/B2/B4 and the drift stop; R4 card
schema + continue re-derivation; R5 the status engine, predecessor-row
gates, and B5; R6 assembly of the complete Column B evidence.

Gates, exactly as Juan ordered and no stricter: each round receives
ordinary independent review (release-review), with alice integrating
production-tooling and cross-repo rounds; plan-critic holds TWO binding
gates - this consolidated design, and the finished implementation with
its complete Column B evidence - and may inspect intermediate work when
a concrete design risk arises, without per-round alignment gates.

After the final implementation gate, alice and Juan decide whether and
when to resume releasing; a fresh prepare derives the actual next card
from the mains as they then stand, and no prose expectation - including
anything this document could have said - overrides it.
