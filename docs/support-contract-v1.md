# Support Contract v1

Shared JSON vocabulary for `aw doctor` output, `aw id` registry
read commands, and cloud support endpoints. This is the
machine-readable contract that lets humans and agents parse output
from any of these tools without learning per-tool field names.

**Registry agnosticism.** The awid protocol is one thing; awid.ai
is one implementation. Registries are discovered via DNS TXT at
`_awid.<domain>` or via `identity.yaml`. Nothing in this contract
assumes awid.ai specifically. Payloads that cite a registry MUST
include the `registry_url` that served the call so callers can see
which registry instance answered.

The mental-model companion is
[`ac/docs/support-tools.md`](https://app.aweb.ai/docs/support-tools)
(cloud repo). The implementation plan is
[`ac/docs/support/agent-lifetime-support-epic.md`](https://app.aweb.ai/docs/support/agent-lifetime-support-epic).
This doc is the byte-level contract those docs assume.

## Scope

- **OSS `aw doctor`** output (JSON + human).
- **`aw id` registry read commands** (resolve, addresses, namespace
  state/addresses/resolve — any awid-protocol registry, not only
  awid.ai).
- **Cloud support read endpoints** under `/api/v1/admin/support/…`.
- **Cloud lifecycle dry-run output** (`repair-managed-address`,
  `replace-agent`, `archive-agent` dry-runs).

Write operations emit an audit record whose JSON shape is covered
in **AC-04**, not here.

## Envelope

Every response (single-shot tool output or endpoint body) wraps
its payload in an envelope:

```json
{
  "version": "support-contract-v1",
  "source": "aweb | awid | aweb-cloud | local",
  "authority_mode": "anonymous | did-key | namespace-controller | team-controller | support | user | user-admin",
  "authority_subject": "<did:key | user id | support actor id>",
  "authoritative": true,
  "generated_at": "<RFC 3339 UTC, millisecond precision>",
  "request_id": "<string; echo of incoming id or server-generated>",
  "target": {
    "type": "agent | workspace | team | address | did | namespace | identity",
    "identifier": "<canonical identifier of the target>",
    "label": "<human-readable label, optional>"
  },
  "redactions": ["<dotted JSON path of any redacted field>", "..."],
  "payload": { ... }
}
```

Field contracts:

- **`version`**: literal string `"support-contract-v1"`. Version
  bumps are not breaking for the envelope; payload shape changes
  go under per-tool schemas.
- **`source`**: the authoritative system for the *payload*. A cloud
  endpoint returning awid registry data uses `source: "awid"` (the
  protocol name, not an implementation URL); a cloud endpoint
  returning its own operational state uses `source:
  "aweb-cloud"`; doctor checks that observe local files use
  `source: "local"`. When `source: "awid"`, the payload MUST
  include `registry_url` naming the registry instance that served
  the call.
- **`authority_mode`**: how the caller was authenticated. `anonymous`
  means no caller credential. `did-key` is a DIDKey signature.
  `namespace-controller` and `team-controller` are controller-key
  signatures. `support` and `user-admin` are hosted-operator roles.
  `user` is a human-held authority lower than admin.
- **`authority_subject`**: the concrete identifier corresponding to
  `authority_mode`. For `anonymous`, omit or set to `null`.
- **`authoritative`**: `true` if the payload is served from its
  source of truth. `false` if it's a cached or derived projection
  — in that case the payload MUST also state the originating
  source as a nested field so the caller can fetch fresh.
- **`generated_at`**: wall clock. Used for cache freshness decisions.
- **`request_id`**: set by the server or echoed from the client's
  `X-Request-ID` header. Always present. Support audit trails
  reference this.
- **`target`**: what the response is *about*. If the response is a
  list, `target` describes the scoping entity (e.g. the team
  whose agents are listed). Per-item targets live inside `payload`.
- **`redactions`**: every field that was in the data model but
  omitted from output. Dotted JSON path syntax
  (`"payload.agent.signing_key_enc"`). If nothing is redacted,
  empty array — NOT null, NOT omitted.

## Status vocabulary (doctor checks)

```
ok       — the check ran and the state is correct.
info     — the check ran; state is acceptable but worth noting.
warn     — the check ran; state is degraded or unusual; not broken.
fail     — the check ran; state is wrong; action required.
unknown  — the check could not run (offline, dependency unreachable,
           insufficient input). Never a claim about state.
blocked  — the check could not run because the caller lacks authority.
           Distinct from `unknown` so the next-step guidance is
           correct.
```

Order from best to worst (for rollup badges): `ok < info < warn <
fail < unknown < blocked` — i.e. `blocked` outranks `fail` because
an unknown-authority state is more ambiguous than a known failure.

## Payload schemas

Per-tool payload shapes are named schemas nested under the
envelope `payload` field. Known schemas in v1:

- **`registry_read.v1`** — response shape for `aw id` registry
  read commands (resolve-key, list-did-addresses, namespace
  addresses, resolve-address, namespace-state). MUST include:
  - `registry_url` — the registry instance that served the call.
  - `operation` — the read op (matches command name).
  - `target` — the requested identifier (did_aw, domain,
    domain/name).
  - `ownership_proof: false` for anonymous/public views — prevents
    public listing being misread as ownership evidence.
  - One typed raw registry field: `did_key`, `addresses`,
    `address`, or `namespace`.
- **`doctor.v1`** — per-check entries (see Per-check structure
  below).
- **`audit.v1`** — support audit records (defined by AC-04,
  referenced here for completeness).

New payload schemas may be added without bumping the envelope
version; consumers MUST handle unknown `payload.schema` values
gracefully.

## Per-check structure (doctor output)

Each entry under `payload.checks[]` for an `aw doctor` run:

```json
{
  "id": "<stable.dotted.id>",
  "status": "ok | info | warn | fail | unknown | blocked",
  "source": "aweb | awid | aweb-cloud | local",
  "authority": "<mode used by this specific check>",
  "target": { "type": "...", "identifier": "...", "label": "..." },
  "authoritative": true,
  "message": "<one-line human summary>",
  "detail": { "<arbitrary diagnostic JSON>" },
  "next_step": {
    "kind": "run_command | open_url | contact_support | none",
    "command": "<shell command, when kind == run_command>",
    "url": "<URL, when kind == open_url>",
    "summary": "<one-line what this next step does>"
  },
  "fix": {
    "available": false,
    "safe": false,
    "authority_required": "<enum from authority_mode>",
    "apply_command": "<shell command>",
    "refusal_reason": "<string if not available or not safe>"
  }
}
```

- `id` is stable across releases. Format:
  `<category>.<subcategory>.<name>` with dots; lowercase snake_case
  within segments. Example: `local.workspace.signing_key_present`.
- `message` is ≤120 chars, human-readable, no secrets.
- `detail` may contain structured diagnostics. Any field in here
  that was redacted must appear in the envelope `redactions` list.
- `fix.available = true` means the doctor has a mechanical repair.
  `fix.safe = true` means the caller can apply it without escalating
  authority. If `fix.available = false`, `refusal_reason` must
  explain why.

## Per-target reference shapes

For cross-tool references, use these stable shapes:

**Agent**:
```json
{"type": "agent", "identifier": "<agent_id UUID>", "label": "<alias>"}
```

**Workspace**:
```json
{"type": "workspace", "identifier": "<workspace_id UUID>", "label": "<path or host>"}
```

**Team**:
```json
{"type": "team", "identifier": "<canonical team id: name:domain>", "label": "<display name>"}
```

**Address**:
```json
{"type": "address", "identifier": "<domain/name>", "label": "<domain>/<name>"}
```

**DID**:
```json
{"type": "did", "identifier": "<did:aw:...>", "label": "<did:key:... or null>"}
```

**Namespace**:
```json
{"type": "namespace", "identifier": "<domain>", "label": "<domain>"}
```

## Error responses

On 4xx/5xx, the envelope still applies; payload is an error object:

```json
{
  "version": "support-contract-v1",
  "source": "...",
  "authority_mode": "...",
  "generated_at": "...",
  "request_id": "...",
  "target": { ... or null },
  "redactions": [],
  "payload": {
    "error": {
      "code": "<stable.dotted.code>",
      "message": "<one-line human summary>",
      "detail": { "<optional structured context>" },
      "next_step": { ... same shape as checks[].next_step }
    }
  }
}
```

Error codes are stable. First-version codes both repos should agree on:

- `auth.unauthenticated`
- `auth.forbidden`
- `auth.authority_insufficient`
- `target.not_found`
- `target.ambiguous`
- `state.stale`
- `state.inconsistent`
- `registry.unavailable`
- `registry.conflict`
- `operation.refused.high_impact`
- `operation.refused.authority_mismatch`
- `operation.refused.dry_run_only`
- `internal.unexpected`

## Contract tests

Both repos land a shared test helper that validates response bytes
against this contract. Suggested location:

- **aweb**: `cli/go/internal/supportcontract/v1_test.go` (Go) and
  `server/src/aweb/support_contract/v1_test.py` (Python).
- **ac**: `backend/tests/support_contract_v1_test.py`.

Helper checks:
- Envelope has all required fields.
- `version == "support-contract-v1"`.
- `redactions` is a list (possibly empty), not null.
- `generated_at` is RFC 3339 UTC with millisecond precision.
- For doctor outputs, each check's `status` is one of the six
  values; each has a stable `id`.
- Error envelopes carry a code from the approved list.

## Versioning

This is v1. Breaking changes bump to v2 and are advertised via a
top-level `version` field. Additive changes (new enum values, new
next_step kinds) are allowed within v1 as long as consumers handle
unknown values gracefully (log and treat as the worst of the
neighboring statuses, or as a no-op for next_step kinds).

## Cross-references

- Epic: [`ac/docs/support/agent-lifetime-support-epic.md`](https://app.aweb.ai/docs/support/agent-lifetime-support-epic).
- aweb tracking subtask: `aweb-aaka.29` (CROSS-01).
- Consumers blocked on this contract: AWEB-05 (`aw doctor`), AC-10
  (support CLI/API wrappers).
