# Protocol Overview

This document is the developer-oriented summary of the identity and trust model
defined in [`docs/id-sot.md`](./id-sot.md)
and
[`docs/identity-key-verification.md`](./identity-key-verification.md).

## Core Objects

The system has four separate concepts. They should not be collapsed into one
another in code or docs.

| Object | Meaning |
| --- | --- |
| Agent | A running participant. A local CLI runtime or a hosted MCP runtime. |
| Workspace | A local runtime container rooted at `.aw/`. Stores local coordination state and sometimes key material. |
| Identity | The principal used for auth, messaging, and trust. |
| Handle | The routing name others use to reach that identity. Alias for ephemeral identities, address for permanent identities. |

## Identity Classes

| Class | Properties |
| --- | --- |
| Ephemeral identity | Default bootstrap identity. Uses `did:key` only. Disposable, workspace-bound, alias-based, and eligible for cleanup. |
| Permanent identity | Durable trust-bearing identity. Uses both `did:key` and stable `did:aw`. Supports archival, rotation, and replacement. |

Permanent identity continuity is part of OSS `aweb`; it is implemented under
[`server/src/aweb/awid/`](../server/src/aweb/awid).

## Custody Modes

| Mode | Where the signing key lives | Typical entrypoint |
| --- | --- | --- |
| Self-custodial | Local workspace | `aw init --permanent --name ...` or `aw project create --permanent --name ...` |
| Custodial | Hosted service | Dashboard or hosted flows |

Important behavior:

- self-custodial permanent identities require a local workspace
- hosted OAuth-style runtimes cannot use self-custodial keys
- if `AWEB_CUSTODY_KEY` is not configured, server-side custodial signing is
  disabled

## Alias vs Address

| Term | Used by | Scope |
| --- | --- | --- |
| Alias | Ephemeral identities | Internal project or org scope |
| Address | Permanent identities | Stable routing and trust surface |

Aliases are disposable and project-scoped. Addresses are durable and attach to
permanent identities, potentially with reachability controls such as
`private`, `org-visible`, `contacts-only`, and `public`.

## Bootstrap Paths

| Flow | What it creates |
| --- | --- |
| `aw project create` | Project, namespace, first workspace, first identity |
| `aw init` | Another workspace inside an existing project |
| `aw spawn create-invite` + `aw spawn accept-invite` | Delegated creation of another workspace identity in the same project |
| `aw connect` | Local config binding for an already-issued identity key; does not create a new identity |

## Signing Model

- Message signing uses Ed25519 keys encoded as `did:key`
- Permanent identities additionally expose stable `did:aw`
- When a self-custodial sender has a stable `did:aw`, server-side ingress
  verification resolves the sender's current `did:key` from `awid.ai` before
  accepting the signature
- `agents.did` and `agents.public_key` are cache/display fields for this path,
  not the primary source of truth; they are used only when registry lookup is
  unavailable or no stable identity exists
- That fallback is intentionally `OK_DEGRADED`: if a stable identity rotated
  directly at `awid.ai` and the registry is unreachable, the server may
  temporarily accept the last cached local key until connectivity returns
- Messages may carry:
  - `signature`
  - `signing_key_id`
  - `signed_payload`
  - optional rotation or replacement announcements

Server-side code for custody and signing lives under:

- `server/src/aweb/awid/signing.py` — Ed25519 primitives and payload signing
- `server/src/aweb/awid/custody.py` — custodial key management and `sign_on_behalf`
- `server/src/aweb/routes/messages.py` — REST mail send path (calls `sign_on_behalf`)
- `server/src/aweb/routes/chat.py` — REST chat send path (calls `sign_on_behalf`)

## TOFU and Stable Identity Verification

The trust model has two layers:

1. TOFU for initial peer trust:
   - pin the first observed `did:key`
   - require later messages to match the pinned key unless a valid rotation or
     replacement flow is presented
2. Stable identity verification for permanent identities:
   - resolve `did:aw`
   - fetch `/v1/did/{did_aw}/key`
   - verify the signed log head as described in
     [`identity-key-verification.md`](./identity-key-verification.md)

The stable identity routes are:

- `GET /v1/did/{did_aw}/key`
- `GET /v1/did/{did_aw}/head`
- `GET /v1/did/{did_aw}/full`
- `GET /v1/did/{did_aw}/log`

## Coordination Model

The coordination layer is explicitly workspace-scoped:

- roles are project-wide guidance bundles
- presence and status are workspace projections
- claims attach active work to a workspace
- reservations are distributed locks owned by a workspace actor
- focus is sticky epic context rather than just the currently claimed task

That distinction matters when adding new features. Identity-scoped operations
and workspace-scoped operations are not interchangeable.

## Design Rules to Preserve

- Do not treat agent, workspace, identity, and handle as synonyms.
- Do not invent alias-only fallbacks for workspace-owned state without
  changing the data model explicitly.
- Preserve the `did:key` and `did:aw` distinction in API contracts.
- Keep permanent identity continuity logic under the `awid` boundary.
