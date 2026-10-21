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
| `env` | Names to strings, `{$param:name}`, or `{$credential:secret_ref, field:name}` |
| `cwd` | Absolute path |
| `timeout_s` | Integer 1 to 3600 seconds |
| `output` | `{max_bytes, projection}`; 1 byte to 16 MiB, nonempty distinct JSON pointers |
| `params` | Parameter names to `{schema, charset}`; bounded inline schemas, optional fixed string character class |
| `credentials` | Ordered distinct `{secret_ref, delivery, mint}` slots |
| `allow_durable` | Explicit owner-confirmed boolean |

Executable and declared-file paths are absolute, with SHA-256 pins. Declared file
paths and read-only OCI paths are sorted and distinct; OCI images name a digest.
Paths contain no NUL or `..` segment. Read-only mounts additionally refuse `/`,
repeated separators, `.` segments and trailing separators; they must already be
normalized. Every string in the record, including nested literals and schema
values, is NUL-free before it reaches PostgreSQL JSONB. Parameters used as
arguments or environment values are scalar. Positional argument slots follow a literal `--`, and their
string values cannot start with `-`. An option-value slot immediately follows a
fixed option name with no `=`, before the `--`. Code-loading and
resolution-changing environment names listed by §9.4 are refused. The denylist also includes `NODE_PATH`,
`PERL5LIB`, `PERLLIB`, `RUBYLIB`, `PYTHONHOME`, `PYTHONBREAKPOINT`, `CLASSPATH`,
`GCONV_PATH`, `BASHOPTS`, `SHELLOPTS`, `PS4` and `PROMPT_COMMAND`.
Names ending in `_PROXY` in any case are refused because they can redirect a
job's credential-bearing network traffic. These refusals deliberately cover
fixed literals too, including `PATH` and `GIT_*`: a pinned job cannot declare a
loader or resolution override through this environment surface. Its executable
and declared files already use absolute paths. The runner starts with an empty
environment. S13's runner dispatch sweep bound must exceed the exported
`MAX_TIMEOUT_S` plus its sweep margin. Every parameter and credential has a
declared use; a credential is placed only in a declared environment target.

Every credential reference has exactly the keys `$credential` and `field`, even
for a single-field value. Each slot selects at least one field, all from one
structured-value family: `value`; `username`/`password`;
`client_id`/`client_secret`; or `access_key_id`/`secret_access_key`/`session_token`.
Subsets and repeated bindings are permitted. The shared codec's field table is
the authority; no dictionary-order selection or empty fallback is inferred.
The field binding is part of the immutable digest. The confirming/release path
must additionally check the actual delivered kind, selected-field presence and
NUL refusal under [runner protocol §4.4](secrets-runner-protocol.md#44-explicit-environment-fields).
The runner validates the whole structured mapping with that sole codec before
selecting env values. Old one-key bindings are invalid; stored pins are never
silently rewritten.

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

For an ordinary derived child used outside its issuing run, the shared lineage
check supplies the selected child's and all ancestors' refs within the same
installation and team. `unique_durable_slot` collects every durable slot matching
any of those refs and requires exactly one; zero or multiple matches refuse with
`job_not_allowed`. Exact-child selectors have no priority over ancestor selectors.
The frozen run plan stores that unique ordinal and actual child ID; other slots
keep their fixed selectors. This pure selection helper is not a grant, lineage or
run-binding check: the shared admission/release path still checks them all.

Jobs remain excluded from `ChangeSets.APPLICABLE_KINDS` until the confirming
source/issuer validation and trusted dispatch integration are implemented and
reviewed. `validate_mint_mapping(slot, issuer)` supplies the record's pure
exact-parameter coverage, literal-schema/charset, reference-type and operation
pin comparisons against a resolved `OperationTemplate`. It proves no CURRENT
lookup or source authority: the common confirming/planning path must resolve
that issuer under its own locks and require token-issuing `store_as_secret`,
then validate expanded actual values at admission. Both durable and short-lived drafts refuse `change_kind_not_applicable`
at this stage. Adding the kind requires definition-time exact issuer parameter
coverage, typed literals, same-type parameter references, CURRENT issuer digest
and token-issuing `store_as_secret` checks; admission additionally validates the
expanded actual values. A syntactically valid job cannot bypass that gate.

Derived-grant template snapshots and their recording fence use this same CURRENT
job registry. Every run-job pin must match, and every pinned job must have exactly
one durable slot selected by the supplied recorded ancestry. A missing, edited,
cross-installation or incompatible job refuses `job_not_allowed`; the child
policy and complete template pins still apply. This replaces `job_unavailable`
inside the existing compatibility helper only. It does not enable job changes,
credential capture, internal minting or independent use of run-bound children;
those keep their shared admission/capture/release gates.
