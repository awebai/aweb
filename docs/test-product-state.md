Tests create their worlds through shared builders using the product's routes,
service owners, or SDK registration; missing operations and failing signatures
are fixed there once. Direct product-table writes are allowed only for states
the product can no longer produce but must survive: historical rows, corruption,
or an interrupted operation. Put `# unreachable-state: <specific state>`
immediately above the containing `await` or assignment, one marker per write
call; a marker explains the exception and grants no current identity or
membership authority. The gate's AST check reports writes per file and table,
including unresolved targets and helpers under `scripts/test-egress/`. Marked
and unmarked writes have separate per-file ceilings that only decrease against
main; new files start at zero for both. A missing marked budget grants zero,
including during the initial bootstrap. Remove setup inserts rather than
making them idempotent.

The initial 2,051-write unmarked baseline is a bootstrap with no reviewed ceiling
on main. It includes the existing egress seed helper's literal write and budgets
its dynamic insert as an unresolved call. Once the baseline lands, subsequent
heads ratchet against it; marking a write cannot grant a new allowance.
Before release, add only the ceiling check and shared fixtures needed by current
failures, without competing with the core chain; conversion of existing writes
continues after release, without a target count or sweep.
