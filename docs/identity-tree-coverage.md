# Identity-tree source coverage

The canonical inventory is [identity-tree-coverage.json](identity-tree-coverage.json).
Its row IDs belong in implementation handoffs. A source-discovered pending row
does not claim conversion, identity authority, a passing journey or a release.
The inventory's release requirements remain separate from source-call coverage.

## Python source guard

`make test-identity-python-inventory` runs in the candidate checks stage. It
scans every tracked Python source, plus new nonignored Python files awaiting
`git add`, using the Python AST. New packages, all naapp apps, runner source
and scripts are included without extending an allowlist. Exclusions are test
paths/names (`tests/`, `test/`, `test_*`, `conftest.py`) and the explicitly
reviewed `EXCLUDED_SCRIPTS` set, currently the scanner itself. Below `src/`,
only directories named `tests` are excluded: production `test_*.py`, `test/`
and `conftest.py` modules stay scanned. The primitive API catalog is
`PRIMITIVE_NAMES` and `PRIMITIVE_MODULES` in
`scripts/check_identity_python_inventory.py`: raw Ed25519 signing/verification
and constructors (including raw `nacl.bindings` APIs), DID construction, public identity/certificate verification
and registration calls. Direct DID string construction is also inventoried.
Comments and docstrings are excluded. Other string literals beginning with
`did:key:` or `did:aw:` are inventoried conservatively, including validation
patterns, named prefixes and format templates. Primitive references passed as
callbacks, assigned aliases or used with `partial` are inventoried too.

The version-1 `python_guard` section contains exact entries:

```json
{"row":"S1.PY.CODEC","file":"awid/src/awid/id_certificates.py","symbol":"verify_id_certificate","calls":{"VerifyKey().verify":1}}
```

This is illustrative; the inventory stores the import-resolved callee names
actually observed. Each entry maps to that row's exact `{file,symbol}` site,
with positive call counts. Function and method names include their enclosing
class/function names; module-level calls use `<module>`. An existing file or
function is not a blanket exemption: a new primitive call, changed count,
missing mapping or stale entry fails. Import aliases and chained constructors
are resolved syntactically, including relative imports resolved against each
source file's package path. Wildcard imports from primitive modules refuse.
Metadata cannot downgrade the strict ID-certificate
module or add a raw verifier there outside its shared verification function.

When a legitimate change fails, review the new call's authority, update its
row/site/call entry and proving test, and obtain the ordinary slice review.
The checker has no auto-update, suppression or CI bypass mode. Adding a legacy
row records an existing signed family; it never exempts a new ID-family proof
from the shared verifier. These checks help reviewers catch source drift;
they do not prove control flow or discover arbitrary dynamic Python dispatch.

## Go source guard

`make test-identity-go-inventory` runs in the ordinary test target and candidate
checks stage. The standard-library Go AST parser scans every tracked or new
nonignored `*.go` file, including tools and new packages. Only `*_test.go`,
`testdata/` fixtures and the scanner itself are excluded. Build tags do not
hide source from the guard. The scanner has no catalog-update mode.

`go_guard` uses the same versioned row/file/symbol/calls entries as Python.
Import aliases are resolved to module paths; methods use `(*Type).method` or
`Type.method`, and closures belong to their enclosing function. Package-level
initializers use `<module>`. Identity calls and callback references are pinned,
as are executable string literals beginning with `did:key:` or `did:aw:`.
`primitive` in `cli/go/internal/identityinventory/main.go` defines the API name
families (sign/verify/register/revoke, key generation, DID construction and
ID-certificate/chain helpers). Dot imports from identity/crypto modules refuse.

New sites, changed primitive counts, stale entries and missing exact row
mappings fail. Strict rows cannot add raw verification outside the shared
`VerifyIDCertificate` function; the codec and ancestry modules cannot downgrade
their profile. Existing released families remain explicitly `legacy` pending
their owner and the acmz ruling. Newly discovered rows marked `pending` are
source coverage, not converted behavior or passing journey evidence. This is
syntactic discovery: reflection, dynamically chosen methods and full data-flow
analysis are outside its scope.

## Remaining release work

Python and Go source-call guards are implemented. S8b is incomplete until
the TypeScript call guard, the complete status/head/tag/test schema,
per-path chain-or-refuse tests, external repository pins and equivalent guards,
and verified fleet enrollment under Juan are qualified. Unmerged candidate
files and owner-reported external tests remain candidate evidence, not files
or tests proven present on the eventual release head. Rows marked
`owner_to_refine` must be classified and tested by their owners. Source-call
coverage alone cannot satisfy any of those requirements.
