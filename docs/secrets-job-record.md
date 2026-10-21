# secrets job record v1

The record implements [secrets §9.4 and §9.5](design/secrets.md#94-job-definitions).
A job is owner-confirmed, immutable and installation-scoped. Editing it stores a
new digest and moves its one CURRENT pointer. Admission and release resolve that
pointer and compare the approved pin; the historical lookup never grants authority.

The change/1 item's `ref` is `job_id`. Its `after` has exactly these fields:

| Field | Shape |
| --- | --- |
| `v` | Integer `1` |
| `job_id` | Lowercase slug, at most 64 characters |
| `runner_ids` | Nonempty sorted distinct runner IDs |
| `kind` | `exec` or `oci` |
| `exec` | `{path, sha256, files:[{path, sha256}]}`, or null for OCI |
| `oci` | `{image, read_only_paths}`, or null for exec |
| `argv` | Ordered strings or `{$param:name, slot:positional\|option_value}` |
| `env` | Names to strings, `{$param:name}`, or `{$credential:secret_ref}` |
| `cwd` | Absolute path |
| `timeout_s` | Positive safe integer |
| `output` | `{max_bytes, projection}`; 1 byte to 16 MiB, nonempty distinct JSON pointers |
| `params` | Parameter names to `{schema, charset}`; bounded inline schemas, optional fixed string character class |
| `credentials` | Ordered distinct `{secret_ref, delivery, mint}` slots |
| `allow_durable` | Explicit owner-confirmed boolean |

Executable and declared-file paths are absolute, with SHA-256 pins. Declared file
paths and read-only OCI paths are sorted and distinct; OCI images name a digest.
Paths contain no NUL or `..` segment. Parameters used as arguments or environment
values are scalar. Positional argument slots follow a literal `--`, and their
string values cannot start with `-`. An option-value slot immediately follows a
fixed option name, before the `--`. Code-loading and resolution-changing environment
names listed by §9.4 are refused. Every parameter and credential has a declared
use; a credential is placed only in a declared environment target.

For `durable`, `mint` is null and `allow_durable` is true. For `short_lived`,
`secret_ref` is the fixed parent/slot label and `mint` is exactly
`{operation_id, digest, params}`. Each recipe parameter is exactly
`{value:typed_literal}` or `{$param:job_parameter_name}`. The record's syntactic
check validates these tags and job-parameter references; expansion never coerces
values. Confirming and executing a recipe additionally resolve its parent and
CURRENT issuer, validate the complete issuer parameter set, literal constraints,
reference types and expanded actual values, and require token issuance with
`store_as_secret`. The shared dispatch/confirmation path supplies those source and
authority checks; syntactic parsing or storage alone is never mint authority.

The digest is SHA-256 of `aweb.secrets.job/1\n` followed by canonical JSON of
`after` without `v`. It includes all recipe literals, mappings and ordered slots.
A returned `after` is a fresh mapping; mutating it cannot change the stored snapshot
or its digest. PostgreSQL refuses updates to immutable definition rows.

Server-managed run-bound child metadata and the paired child/grant receipt stay
outside job/1. The stable slot label maps by signed array ordinal to the actual
delivered ref, under §9.5. The runner independently checks its local job pin.
