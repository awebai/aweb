# OSS Support Tools

This page documents the OSS `aw` support surface: lifecycle semantics,
`aw doctor`, registry reads, and redacted support bundles. Hosted dashboard
actions are intentionally described only as boundaries here. Cloud support
APIs and operator runbooks live in the cloud support documentation.

## Lifetime Semantics

aweb separates workspace lifetime from identity lifetime.

- An **ephemeral identity** is team-local and workspace-bound. It has an alias
  such as `alice`, but no public address or trust-continuity promise.
- A **persistent identity** is durable. It has a `did:key`, a stable `did:aw`,
  and may hold public addresses such as `acme.com/alice`.
- A **workspace path** is only a local binding. Losing, moving, or deleting a
  path does not prove that a persistent identity should be deleted, archived,
  replaced, unclaimed, or reassigned.

Ephemeral workspace deletion is a lifecycle event. When the server confirms a
gone ephemeral workspace, OSS aweb soft-deletes the workspace and bound
ephemeral agent row, clears presence, and releases task claims with the normal
unclaim events.

Persistent workspace disappearance is not a lifecycle event. The server
rejects persistent workspace delete/archive attempts in OSS because persistent
identity lifecycle requires explicit authority and a reviewed lifecycle flow.
Missing local files alone are never enough evidence for archive, replacement,
address reassignment, or task/presence cleanup.

## `aw doctor`

`aw doctor` diagnoses local files, identity registry state, workspace/server
connectivity, team membership, coordination, and safe messaging prerequisites.

Common forms:

```bash
aw doctor
aw doctor --json
aw doctor --online
aw doctor local
aw doctor registry --online
aw doctor support-bundle --output support-bundle.json --json
```

Mode behavior:

- Default/auto mode avoids surprise online probes for checks that require
  registry or server calls.
- `--offline` must not contact the network.
- `--online` allows read-only registry/server checks using the caller's local
  credentials. It does not use support, admin, or service bypass authority.

Doctor statuses use the shared support vocabulary:

| Status | Meaning |
| --- | --- |
| `ok` | The check ran and the state is correct. |
| `info` | The check ran and found acceptable state worth noting. |
| `warn` | The check ran and found degraded or unusual state. |
| `fail` | The check ran and found wrong state requiring action. |
| `unknown` | The check could not run, for example offline mode or dependency unavailable. |
| `blocked` | The check could not run because the caller lacks authority. |

JSON output follows `doctor.v1` today and uses the same status vocabulary as
[`support-contract-v1`](support-contract-v1.md). Support tooling should read
check IDs, statuses, sources, targets, details, fixes, and handoffs as stable
machine-readable fields.

## `aw doctor --fix`

`aw doctor --fix` is intentionally bounded.

Allowed local fixes in OSS are conservative caller-authorized repairs:

- Select `active_team` when exactly one unambiguous membership exists.
- Normalize a local workspace `aweb_url` by stripping unsafe URL parts.
- Normalize `identity.yaml` `registry_url` by stripping unsafe URL parts while
  preserving identity continuity fields and signing key material.

Dry-run first:

```bash
aw doctor --fix --dry-run
aw doctor --fix --dry-run local.workspace.active_team
```

Apply only root doctor fixes:

```bash
aw doctor --fix
aw doctor --fix local.workspace.active_team
```

The fix framework refuses high-impact or sensitive mutations, including:

- persistent identity delete/archive/replace/retire/reassign
- private key or signing key rewrites
- task unclaim and presence cleanup
- server, registry, dashboard, support, or service-authority mutations

Category subcommands remain diagnostic-only for fix mode unless a future slice
explicitly exposes scoped fixes.

## Registry Read Commands

The awid protocol is registry-agnostic. A registry may be the public awid.ai
service or a BYOD registry discovered through DNS TXT at `_awid.<domain>`.
Registry read output includes `registry_url` so support can see which registry
instance answered.

Read commands:

```bash
aw id resolve <did_aw> --json
aw id addresses <did_aw> --json
aw id namespace <domain> --json
aw id namespace addresses <domain> --authority anonymous --json
aw id namespace addresses <domain> --authority did --json
aw id namespace addresses <domain> --authority namespace-controller --json
aw id namespace resolve <domain>/<name> --authority anonymous --json
aw id namespace resolve <domain>/<name> --authority did --json
aw id namespace resolve <domain>/<name> --authority namespace-controller --json
```

Registry JSON reads use the shared `support-contract-v1` envelope with
`source: "awid"` and `payload.schema: "registry_read.v1"`.

Authority modes:

- `anonymous`: public registry view. `ownership_proof` is `false`.
- `did`: signs with the local `.aw/signing.key`, emits
  `authority_mode: "did-key"`, and proves only control of that DID key.
- `namespace-controller`: signs with the local namespace controller key and is
  the only current registry read mode that reports `ownership_proof: true`.

Structured registry outcomes return JSON with `payload.status`:

- `ok`: registry returned a record.
- `fail` with `target.not_found`: registry authoritatively returned 404.
- `unknown` with `registry.unavailable`: transport failure or registry
  unavailable.
- `blocked` with an auth error: registry rejected the caller's authority.

These structured registry outcomes are command output, not shell failures.
Usage errors and missing local signing/controller keys still exit nonzero
before contacting the registry.

Public namespace listing is discovery, not ownership proof. Do not use it as
evidence that a caller owns or may mutate a namespace or address.

## Support Bundles

`aw doctor support-bundle --output <file> --json` writes a redacted JSON bundle
that can be shared with support. Offline generation works and preserves the
same no-surprise network behavior as the selected doctor mode.

The bundle may include:

- doctor output and checks
- non-secret platform metadata
- non-secret `.aw` metadata such as team IDs, aliases, DID/address fields,
  lifetime, custody, and parsed certificate metadata
- redaction paths and reasons
- narrow request IDs from structured error details when available

The bundle must not include:

- private keys or signing key contents
- API keys, bearer tokens, cookies, or auth headers
- raw team certificate blobs, signatures, or encrypted private key material
- URL userinfo, query secrets, fragments, request bodies, or arbitrary registry
  response bodies

Before writing the output file, the bundle is redacted in memory and scanned
for known secrets. If the final scan finds a known secret, the command fails
without writing a partial bundle.

## High-Impact Handoffs

Doctor may emit `handoff` guidance for actions it will not perform. These are
review prompts, not automatic repairs.

Examples:

- `persistent_lifecycle_review`: persistent archive/delete/replace requires
  external authorized review; missing local state alone is not sufficient.
- `persistent_identity_registry_repair_review`: if the local DID key is valid,
  caller-authorized DID registration or registry repair is preferred before
  replacement. When local caller authority is present, the explicit command is
  `aw id register`.
- `managed_address_repair_review`: address repair requires namespace authority.
  Repair is first-line when the existing DID key is valid.
- `namespace_controller_recovery_review`: BYOD namespace recovery requires the
  namespace-controller owner. Doctor does not recover or rotate controller keys.
- `suspected_key_mismatch_review`: investigate key mismatch before rotate,
  replace, or registry repair.

Hosted-only dashboard actions must be labeled as hosted-only and conditional
on hosted authority. OSS doctor does not perform cloud archive, replacement,
managed-address repair, service cleanup, support bypass, or dashboard actions.

## Related Docs

- [Identity and Security](identity.md)
- [Support Contract v1](support-contract-v1.md)
- [aweb SoT](aweb-sot.md)
- [awid SoT](awid-sot.md)
