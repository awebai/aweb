
# coordinator knowledge

Accepted expertise of the aweb OSS coordinator soul: decisions about how the
team's work is routed, reviewed and integrated, with their rationale, and
lessons that generalise beyond the task they came from. Code and contract facts
live in the repository; hosted-application facts live with the hosted-product
team.

* [operating-continuity.md](operating-continuity.md) — Find current decisions and preserve the historical coordinator record.

Historical record, preserved in the repository as written and not converted to
OKF: `agents/coordinator/decisions/`, `agents/coordinator/docs/` and
`agents/coordinator/memory/`.

## Decisions about coordination

* [Harvest before retire](harvest-before-retire.md) — Every seat, coordinators included, is harvested before it is retired; open-framework knowledge goes to the public OSS base and hosted knowledge to the private hosted base, and turning harvest on in configuration covers only future spawns, so existing seats need an explicit harvest.
* [Lane trains share main](lane-trains-share-main.md) — A lane whose work is decoupled from the server builds and lands its own train instead of queueing behind the repository train; it pushes only after the repository-train owner OKs the slot, runs the full candidate gate whenever the train touches the shared naapp library, and never re-gates a tree that already failed.
* [Migration number collisions](migration-number-collisions.md) — When unlanded branches pick the same migration numbers, the first to land keeps them and the later branch renumbers as a reviewed rename-only delta; no lower number lands after a higher one, the landing coordinator assigns ranges when lanes overlap, and authors re-check numbers at every main merge.
* [Prove a generic core with two consumers](prove-a-generic-core-with-two-consumers.md) — Shared architecture is designed and built against two real consumers at once, so the generic core is validated before review; reusable runtime lives once in the shared library, and existing apps adopt each shared piece as it lands.
* [Required invariants belong on the fix](required-invariants-belong-on-the-fix.md) — A reproduction only has to be red on released code with the reported failure; when a plausible wrong fix could turn it green by breaking a security invariant, assertions of that invariant and a refusal control are required on the fix head, not on the reproduction.
* [Scope belongs to the operator](scope-belongs-to-the-operator.md) — A reviewer, another coordinator or a relay can recommend cutting or deferring requested features, but only the operator decides; a reduced first version is not a cheap prefix of the full product because its architecture differs, so the team designs for the full scope.
* [Support claims follow the released public route](support-claims-follow-the-released-public-route.md) — Before claiming aweb supports a third-party runtime, install it from scratch exactly as the published instructions say, using only released software and the public service; any gap is a bug fixed and rerun from scratch, an unreleased dependency is fixed and released by its owner rather than routed around, and support copy waits for that run.
* [The coordinator does not build](the-coordinator-does-not-build.md) — When urgent work appears, the coordinator assigns an owner seat instead of implementing it; the coordinator's context is the scarce resource for routing, sequencing and rulings, and is also why reviewers send verdicts to authors rather than copying the coordinator.

## Lessons from coordination and integration

* [Recover work from action receipts](recover-work-from-action-receipts.md) — A message marked read can still contain unfinished work; recover exact messages and reconcile side effects before retrying.
* [Distinguish presence from execution](distinguish-presence-from-execution.md) — Presence, message delivery, runtime activity and useful task progress require different evidence.
* [Resolve full review anchors before integration](resolve-review-anchors-before-integration.md) — Resolve the complete commit object and compare the reviewed diff and ancestry; a matching short prefix is insufficient.
* [Preserve acceptance artifact provenance](preserve-acceptance-artifact-provenance.md) — Keep the tested executable, source, build context and harness together so a source claim can be traced to the accepted bytes.
* [Acceptance must exercise the claimed operation](acceptance-must-exercise-the-claimed-operation.md) — Use realistic boundary values and inject the claimed fault on the real operation path; mocked agreement is not compatibility proof.
* [Reproduce the whole test context](reproduce-the-whole-test-context.md) — A child command only reproduces a gate failure when its prerequisites, environment and boundary behavior match the failed run.
* [Cleanup needs resource recovery evidence](cleanup-needs-resource-recovery-evidence.md) — Removing owned resources and recovering the affected host resource are separate acceptance conditions.
* [Identify the resource measurement subject](identify-the-resource-measurement-subject.md) — A recovery threshold is meaningless when the measurement selects the wrong process or mixes counting units.
* [Preserve stash objects and dispositions separately](preserve-stash-objects-and-dispositions.md) — Proving that stash changes were incorporated does not preserve the stash object graph, and unreachable does not mean lost.
* [Recover partial lifecycle actions from receipts](recover-partial-lifecycle-actions.md) — A failed lifecycle command can already have completed irreversible side effects; inspect each effect before retrying.
* [Verify migration as an operating contract](verify-migration-as-an-operating-contract.md) — A package upgrade does not prove that the successor can consume its knowledge, receive work and retain the intended authority.
* [Resolve the component before diagnosing it](resolve-the-component-before-diagnosing-it.md) — Identify the dispatcher, frozen capability, executable and target scope before attributing a refusal or accepting an inherited procedure.
* [Separate publication, installation and live adoption](separate-publication-installation-and-adoption.md) — A successful publisher is not proof that every platform can install the artifact or that a running consumer uses it.
* [Plan the daemon executable replacement gap](plan-the-daemon-executable-replacement-gap.md) — Replacing the executable of a running macOS daemon can stop delivery before the planned restart.
* [Verify identity selection at every process boundary](verify-identity-selection-at-every-boundary.md) — An explicit identity selected in one layer does not automatically scope subprocesses, streams or later lifecycle operations.
* [Preserve capability boundaries through adapter changes](preserve-capability-boundaries-through-adapter-changes.md) — A transport or adapter refactor must not infer mutation or custody authority from permission to read.
* [Ask the operator self-contained questions](ask-the-operator-self-contained-questions.md) — A status report or decision request to the operator stands on its own (what the thing is in plain words, why it needs deciding now, the options and their consequences, one agreed recommendation) with no task ids or option labels; only questions that need the operator's context go to the operator.
* [Check the shipped path a design finding implies](check-the-shipped-path-a-design-finding-implies.md) — When a design review finding implies that an already-shipped mechanism has the same flaw, verify the shipped path at once instead of parking it behind the design, and split a pre-existing defect into its own task, review and landing rather than bundling it into the feature.
* [Fix the harness, do not route around it](fix-the-harness-do-not-route-around-it.md) — When a seat's harness fails to spawn, check the installed CLI itself before reasoning about packages, and reinstall it rather than switching harness; new seats keep their soul's declared launch, because a ruling to restart particular seats on another runtime does not extend to new spawns.
* [Main CI is a separate signal](main-ci-is-a-separate-signal.md) — Green local train gates do not show that main's hosted CI is green, and branch protection that exempts admins turns a required check into an advisory one for train pushes; after every landing, read CI for the landed SHA and treat red main as a P0 owned by the lane that landed it.
* [One voice per cross-lane contract](one-voice-per-cross-lane-contract.md) — When two coordinators can both rule on a shared contract, the lane that owns the artifact issues the single instruction, rulings wait until every owner has answered, crossed rulings are settled synchronously with one mail naming every superseded message, and implementers hold rather than choose.
* [Review requests carry their content](review-requests-carry-their-content.md) — aw mail is per-recipient, so a reviewer cannot open mail that was sent to the coordinator; a review request pastes the referenced content instead of citing a message id, and message ids are only ever cited as captured from tool output.
* [Shared checkout hazards](shared-checkout-hazards.md) — A Go build's read-only module cache inside a worktree blocks worktree removal and seat retirement; a failed retire can leave a .git file that git later points at another seat's worktree; and push.default=matching in a clone shared by seats pushes everyone's branches.
* [Staff by reviewed dependencies](staff-by-reviewed-dependencies.md) — Staff every task whose dependencies are at least ACKed, stacked on those branches, instead of waiting for them to land; break serial chains by having the provider publish its consumer interface first so consumers fit-check it and build in parallel.
