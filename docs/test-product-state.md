Tests create their worlds through shared builders using the product's routes,
service owners, or SDK registration; missing operations and failing signatures
are fixed there once. Direct product-table writes are allowed only for states
the product can no longer produce but must survive: historical rows, corruption,
or an interrupted operation. Put `# unreachable-state: <specific state>`
immediately above the containing `await` or assignment, one marker per write
call; a marker explains the exception and grants no current identity or
membership authority. The gate's AST check reports writes per file and table,
including unresolved targets, with marked writes listed separately and never
enlarging unmarked allowances. Existing unmarked ceilings only decrease; new
files start at zero. Remove setup inserts rather than making them idempotent.
Before release, add only the ceiling check and shared fixtures needed by current
failures, without competing with the core chain; conversion of existing writes
continues after release, without a target count or sweep.
