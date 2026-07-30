# Instance worktrees need an explicit push before review

Developer instance checkouts under `agents/instances/<alias>/` do not
share refs with the main checkout or origin. A branch that exists in the
main checkout under the instance's name is the stale spawn-time ref, not
their work. Pushing it publishes nothing.

When a developer reports "ready for review", require the pushed commit
hash and verify with `git ls-remote origin <branch>` before routing the
review — reviewers on other machines can only see origin.

Related local-env fact: pyproject uv.sources `../aweb` resolves from the
checkout root; `pgdbm` lives at `/Users/juanre/prj/pgdbm` (not under
`awebai/`). Developers fix this with uncommitted symlinks in their
instance home. `uv run --no-sources pytest` sidesteps it entirely for
review/merge validation.
