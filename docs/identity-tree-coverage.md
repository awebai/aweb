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
reviewed `EXCLUDED_SCRIPTS` set, currently the scanner itself. The primitive API catalog is
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
source file's package path. Metadata cannot downgrade the strict ID-certificate
module or add a raw verifier there outside its shared verification function.

When a legitimate change fails, review the new call's authority, update its
row/site/call entry and proving test, and obtain the ordinary slice review.
The checker has no auto-update, suppression or CI bypass mode. Adding a legacy
row records an existing signed family; it never exempts a new ID-family proof
from the shared verifier. These checks help reviewers catch source drift;
they do not prove control flow or discover arbitrary dynamic Python dispatch.

## Remaining release work

This checkpoint is Python source-call coverage only. S8b is incomplete until
Go and TypeScript call guards, the complete status/head/tag/test schema,
per-path chain-or-refuse tests, external repository pins and equivalent guards,
and verified fleet enrollment under Juan are qualified. Unmerged candidate
files and owner-reported external tests remain candidate evidence, not files
or tests proven present on the eventual release head. Rows marked
`owner_to_refine` must be classified and tested by their owners. Source-call
coverage alone cannot satisfy any of those requirements.
