# Python static analysis

`make check-python-static` is the single release checks-stage entry point for
the server and AWID library/registry service. It runs Ruff 0.15.0 and
mypy 1.19.1 from the frozen server environment. Each package's `pyproject.toml`
owns its configuration. Mypy uses that package's prepared Python environment
to discover installed dependency types, and targets Python 3.12.

The shared floor is Ruff E4/E7/E9/F/B/BLE and mypy `check_untyped_defs`.
Imported pytest fixtures may shadow their registration import (`F811`);
FastAPI `Depends` and `Body` defaults are intentional declarations. The holder
owns its separate import/upgrade lint, formatting and `disallow_untyped_defs`
through `make -C key-holder check`. The urgent server/registry entry does not
prepare the holder or depend on its service relock.

Ruff discovers Python files throughout each package, including tests. Mypy
checks each package's explicit production source roots. Imported dependencies
are followed silently, so their diagnostics are owned by their own package.
Unlike Cloud's historical configuration, OSS does not exclude migrations or
hide legacy module/code findings in overrides. The repository-wide formatter
has its own scope and entry point; a diagnostic ceiling is not a formatting
exclusion.

`tools/python-static-ceilings.json` records the initial observed findings by
tool, repository-relative file and rule code. New files and rule codes have
zero allowance. The raw Ruff scan ignores inline `noqa` directives. Configured
mypy module/code suppression is refused instead of masking a count increase.
A tool failure, malformed configuration, unstructured output or an exit status
that contradicts the diagnostics is a setup failure, never a clean result.

The current allowances also cannot exceed the checked-in allowances on the
already synchronized `origin/main`. The checker reads that reference without
fetching or changing it. Main's first reviewed baseline bootstraps the counts;
later heads cannot add or enlarge groups, even when the source would fit a
manually raised budget. Missing Git/reference evidence fails as setup.

When clearing findings, lower or remove the affected counts in the same
reviewed change. Do not raise a ceiling, move an allowance to another file or
regenerate this data during a gate run. An initial inventory does not make an
existing finding acceptable forever; its rule owner fixes it in the owning
head. Cleared groups disappear. The normal command never writes its input
configuration or ceilings.

`make check-python-static` prepares the server and AWID checkout environments
with `uv sync --frozen`, then invokes the offline checker. Preparation preserves
`UV_OFFLINE`, so a prepared gate does not gain a network fallback. Callers do
not maintain another package list. No database, Redis or Docker is used.

Authors can select repository-relative changed files with the same ceilings:

```sh
make check-python-static PYTHON_STATIC_ARGS='--files server/src/aweb/messaging/mail_send.py'
```

Ruff checks the selected Python files, including tests; mypy checks selected
files within the declared production source roots and follows imported types
silently. Other files' existing findings do not block this focused command.
Omitting `--files` checks the complete package scope in the gate. Deleted files
should be omitted from the selection. The checker never writes the ceiling.

`make test-python-static` needs no database, Docker or network once those
dependencies are installed. Its controls use the actual pinned tools on
disposable sources with the canonical server configuration: same-file/code
growth, a new untyped body, blind handlers, valid FastAPI declarations, inline
suppression, reductions and malformed input. The CLI refusal controls assert
the recovery sentence. These controls establish the static-analysis boundary;
they do not replace the product's admission or delivery tests.
