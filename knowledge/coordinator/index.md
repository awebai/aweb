
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
