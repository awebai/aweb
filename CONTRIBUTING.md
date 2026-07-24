# Contributing

External contributions are welcome. Open an issue to discuss a problem or send
a focused pull request with the implementation, tests, and documentation needed
to review it.

## Start with the architecture

Read [`docs/oss-boundary.md`](docs/oss-boundary.md) before deciding where a
change belongs. [`docs/README.md`](docs/README.md) indexes the canonical
architecture and engineering sources of truth. For repository layout, local
development commands, migrations, and test guidance, see
[`docs/contributing.md`](docs/contributing.md).

Keep changes narrow and update the relevant source of truth when behavior or a
public contract changes. Preserve the repository's `.aw/` state invariant: only
sanitized fixtures below `test-vectors/` may contain tracked `.aw/` paths.

## Review gate

The same review gate applies to every contribution, whether it comes from a
maintainer or an external contributor. A change must receive maintainer review
and pass the relevant automated and manual checks before merge. Review may ask
for tests, documentation, compatibility evidence, or a smaller scope.

## License

This repository is licensed under the [MIT License](LICENSE). By submitting a
contribution, you agree that it is provided under that license and confirm that
you have the right to submit it.
