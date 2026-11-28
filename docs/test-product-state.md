Tests create their worlds through shared builders using the product's routes,
service owners, or SDK registration; missing operations and failing signatures
are fixed there once. Direct product-table writes are allowed only for states
the product can no longer produce but must survive: historical rows, corruption,
or an interrupted operation. Put `# unreachable-state: <specific state>`
immediately above the containing `await` or assignment, one marker per write
call; a marker explains the exception and grants no current identity or
membership authority. The gate's AST check reports writes per file and table,
including unresolved targets and helpers under `scripts/test-egress/`. Unmarked
writes and unmarked nonliteral calls have separate per-file ceilings that can
only decrease against main, with zero for new files. A marked write ceiling can
increase only when the filename contains `migration`, its declared count
matches the file's `# unreachable-state:` markers, and the scanner finds exactly
that many marked product writes. Review the historical state and its declared
count together, including when a new file first enters the manifest. A missing
marked budget grants zero.
Remove setup inserts rather than making them idempotent.

Use `# nonliteral-call: <specific reason>` only for reviewed reads and query
plans, such as `SELECT` statements built from product constants and `EXPLAIN`
of those statements. Writes must follow the product-write rules above.
Put the marker on the line where the SQL call starts. Name the query, such as
`EXPLAIN of GOVERNANCE_BEFORE`. Declare the exact number of marked calls for
that file in `marked_nonliteral_files` in `scripts/product-table-write-ceilings.json`.
Review the call, its marker and the manifest change together. Each marker must
identify one unresolved call. Missing or stale ceilings fail the check.
Statically recognized writes, including writes with unresolved table names,
continue through the write scanner.

The initial 2,051-write unmarked baseline is a bootstrap with no reviewed ceiling
on main. It includes the existing egress seed helper's literal write and budgets
its dynamic insert as an unresolved call. Once the baseline lands, subsequent
heads ratchet unmarked writes and unmarked nonliteral calls against it.
Before release, add only the ceiling check and shared fixtures needed by current
failures, without competing with the core chain; conversion of existing writes
continues after release, without a target count or sweep.
