# Python static analysis

`make check-python-static` is the single release checks-stage entry point for
the server, AWID library/registry service and key holder. It runs Ruff 0.15.0 and
mypy 1.19.1 from the frozen server environment. Each package's `pyproject.toml`
owns its configuration. Mypy uses that package's prepared Python environment
to discover installed dependency types, and targets Python 3.12.

The shared floor is Ruff E4/E7/E9/F/B/BLE and mypy `check_untyped_defs`.
Imported pytest fixtures may shadow their registration import (`F811`);
FastAPI `Depends` and `Body` defaults are intentional declarations. The holder
also owns import/upgrade lint, formatting and `disallow_untyped_defs` through
`make -C key-holder check`; the root delegates to that command. It does not
carry a second holder rule configuration.

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

Before running offline, prepare all three package environments using their
committed locks:

```sh
uv sync --frozen --project server
uv sync --frozen --project awid
uv sync --frozen --project key-holder
make check-python-static
```

`make test-python-static` needs no database, Docker or network once those
dependencies are installed. Its controls use the actual pinned tools on
disposable sources with the canonical server configuration: same-file/code
growth, a new untyped body, blind handlers, valid FastAPI declarations, inline
suppression, reductions and malformed input. The CLI refusal controls assert
the recovery sentence. These controls establish the static-analysis boundary;
they do not replace the product's admission or delivery tests.
