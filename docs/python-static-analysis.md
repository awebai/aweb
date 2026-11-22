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

The checker compares allowances with the checked-in baseline on the already
synchronized `origin/main`, without fetching or changing that reference.
Main's first reviewed baseline bootstraps the counts. A later head may relocate
allowances by adding or enlarging groups only when its same ceiling diff removes
more allowances than it adds: the total must strictly decrease. The checker
prints the before/after totals and every changed tool/file/code group so the
reviewer can verify which old groups the new owner replaces. A bare increase
or a relocation with an unchanged total is refused even when the tools fit the
candidate budget. Missing Git/reference evidence fails as setup.

The candidate gate owns supplying `refs/remotes/origin/main` in its private
checkout at the exact synchronized main commit recorded in the gate inputs.
A local clone does not copy the source checkout's remote-tracking refs. The
gate must materialize and verify that recorded ref before running the checker;
a missing or changed source ref must be refused by gate preparation. The checker
only reads the supplied ref: it never fetches, repairs a checkout or substitutes
the candidate's own ceiling. Its real CLI control starts with a detached
candidate and no remote refs, observes the missing-baseline setup refusal,
then supplies the recorded main ref and distinguishes it from a candidate
budget increase.

## Source exemptions

Mypy source exemptions are findings under the same reviewed ceiling. Python's
parsed `type: ignore` entries count as `source-type-ignore`; module `# mypy:`
directives count as `source-mypy-directive`. Module directives are counted by
mypy's pinned lexical rule, including directive lines inside multiline strings.
This keeps source-level overrides visible without copying or rewriting product
source. The first main baseline retains its five existing type-ignore entries;
new per-file exemption counts have zero allowance.

Mypy runs with unused-ignore warnings off: an existing exemption stays counted
even when the underlying code is valid. Removing one lowers its allowance in
the same change. No source comment can add a budget. Ruff's `--ignore-noqa`
acquires the underlying lint findings despite inline or file-level `noqa`.
Real CLI controls cover all these forms and valid neighbors.

When clearing findings, lower or remove the affected counts in the same
reviewed change. Relocate allowances only under the strictly decreasing,
reviewed-diff rule above; do not regenerate this data during a gate run. An
initial inventory does not make an existing finding acceptable forever; its
rule owner fixes it in the owning head. Cleared groups disappear. The normal
command never writes its input configuration or ceilings.

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
