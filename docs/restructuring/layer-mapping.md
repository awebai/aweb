# Layer mapping — how aw CLI + channel stack map onto the restructuring SOT

Purpose: synthesis over the two familiarization maps
([cli-go-map.md](cli-go-map.md), [archive/channel-stack-map.md](archive/channel-stack-map.md) — archived)
that ties the current `aw` Go CLI and the channel stack onto the destination
layers in [restructuring-sot.md](../restructuring-sot.md). It exists to make the
milestone 1–2 boundary (app contract/manifest + `aw` plugin dispatch) concrete
before tasks are cut. Nothing here is task work until Juan approves (SOT gate).

Authored by aw-coordinator from the two maps, first-hand grounding in `cli/go`,
and the design convergence with aweb-coordinator (SOT owner) on 2026-06-16.

## 1. The spine: the app manifest is one declaration, three front-ends

The single idea everything in m1/m2 keys off (SOT §7): an app's **manifest** is
one declaration that drives three surfaces.

```
                       app manifest (§7)
        name, description, inputSchema, method+path,
        param placement (path/query/body), scopes, mutation-flag,
                  id/version/origin, /llms.txt + /skills
                            |
        +-------------------+-------------------+
        |                   |                   |
   gateway MCP         aw <app> <verb>      aweb.ai hub
   tool composition    plugin verbs         listing
   (§6.5, hosted)      (§10, cli)           (catalog)
```

Consequence that orders the work: **the manifest field set must freeze in m1
before m2 builds dispatch**, and it must freeze *once* — with the gateway's and
billing's needs included from day one (`scopes` + `mutation-flag`, consumed by
the §6.5 gateway and §9 billing), even though the CLI plugin path consumes it
first. Freeze once, not twice.

## 2. aw plugin dispatch (SOT §10 / milestone 2)

### 2.1 Current state — greenfield, but the backend already exists

Plugin / external-binary dispatch is **absent today** (verified first-hand and in
[cli-go-map.md](cli-go-map.md)): no `aw plugin` command, no `~/.aw/plugins/`
search, no `AW_DID/AW_TEAM/AW_SERVER/AW_HOME/AW_HELPER` env contract, no
`aw <name>` → `aw-<name>` fallback. `aw` is a closed Cobra tree that errors on
unknown commands (`cli/go/cmd/aw/root.go:137`).

But the **generic signed-request backend already exists**:
`aw id request <method> <url> --body … --team-auth`
(`cli/go/cmd/aw/id_request.go:65`, `:268`) takes a URL + body across the standard
HTTP methods and emits the full v2 team-auth envelope
(`aud/method/path/team_id/body_sha256/v:2` plus
`Authorization`/`X-AWEB-Signed-Payload`/`X-AWID-Team-Certificate`). This is the
only current generic app-call primitive — and it is exactly what a dispatcher
needs. **This de-risks m2 substantially: dispatch is a thin mapper over a proven
primitive, not new auth code.**

Scope note for m1: the backend supports exactly `GET/POST/PUT/PATCH/DELETE`
today (`id_request.go:110`). So the m1 manifest `method` enum should be those
five for v1; `HEAD/OPTIONS`/etc. would require extending the signed-request
backend first and should not be assumed available.

### 2.2 The dispatch model — manifest-driven generic (not per-app binaries)

The folio brief (`folio/docs/aw-plugin-brief.md`) defaults to hand-written
per-app `aw-<name>` binaries. The destination model is **manifest-driven
generic** instead: one generic `aw <app> <verb>` driver reads the installed app's
manifest, maps the verb to `(method, path-template, params)`, and invokes the
existing `aw id request --team-auth` path **in-process** for first-party generic
apps (no shell-out). The external `aw-<name>` binary stays as an **escape hatch**
only for apps needing custom client logic.

This is *less* work than per-app binaries (one driver vs N binaries) and keeps
signing keys/team certs inside `aw`.

### 2.3 Manifest constraint the dispatcher imposes on m1

**Param placement is explicit, never inferred.** Each `inputSchema` field must
declare whether it lands in the path, query, or body. The dispatcher must not
guess; the gateway needs the same explicit placement to build MCP tool calls
(reinforces freeze-once). Now recorded in SOT §7.

### 2.4 Two CLI-structural design points for m2.1 (easy to miss from design side)

- **(a) Interception point.** Cobra errors on unknown commands today
  (`root.go:137`); the static tree has no fallback. `aw <app> <verb>` needs
  arg-routing before/around Cobra's dispatch — one clean touch to the command
  tree. Name it in m2.1 scope so it is not a surprise.
- **(b) Resolution precedence**, with two security refinements (dispatch sits
  next to auth):
  1. built-in command →
  2. installed-manifest app (generic dispatch) →
  3. external `aw-<name>` binary →
  4. unknown-command error.
  - **Built-in names *and aliases* are reserved**: an installed app must never
    register a name that shadows a built-in (esp. `id`/`team`/auth verbs — an app
    shadowing `aw id request` could intercept the auth path) **or a built-in
    alias** (e.g. `introspect` aliases `whoami`, `introspect.go:30`). Collision is
    **rejected at install**, not resolved at runtime; built-ins always win.
  - **External `aw-<name>` resolves only from a trusted dir** (`~/.aw/plugins/`),
    **never arbitrary `PATH`** — prevents PATH-injection of a fake `aw-<name>`.
  - **Dispatch builds the target from the granted app *origin* + a *relative*
    path template; user params can never supply or override scheme/host.**
    `aw id request --team-auth` signs `aud` + `path` from the absolute URL it is
    handed (`id_request.go:118`, `:286`), so a manifest/param that could inject a
    host would redirect a *signed, authenticated* request to an attacker. m2 must
    reject absolute path templates / host overrides in manifest dispatch.

## 3. The core event/SSE channel (SOT §3) and its consumers

From [archive/channel-stack-map.md](archive/channel-stack-map.md) (archived snapshot; verify against current code before relying on it):

- **`channel-core` ↔ `claude-channel`/`pi` is already the right shape**:
  host-agnostic subscriber/runtime + thin host adapters. The host-neutral
  `ChannelAwakening {kind, content, meta, deliveryIntent}` contract should
  survive the restructure as the adapter boundary.
- **The server event source is not yet app-generic.** `server/.../routes/events.py`
  hard-codes mail/chat/control polling and emits only those, even though
  `channel-core` already defines `work_available`/`claim_update`/`claim_removed`
  kinds. Making the stream carry app-emitted wake events (while preserving the
  awakening abstraction) is the §3 / milestone-3 platform-formalization work.
  aweb-coordinator has folded this into SOT §3 + milestone 3.
- **Transport vs messaging boundary is still mixed** in the client APIs (core
  fetches `/v1/messages` + `/v1/chat`, and the local-decrypt provider shells to
  `aw mail show`/`aw chat history`). Correct for the bundled-comms transition,
  but the seam to untangle when messages/chat become apps — which happens **last**
  (SOT §12 step 10), because federation/events/E2EE are fused. E2EE boundary
  (metadata-only wake unless local decrypt succeeds) must be preserved.

## 4. Current CLI surface → SOT layer

Condensed from [cli-go-map.md](cli-go-map.md) §"Coordination surface and SOT
movement":

| Current `aw` surface | SOT target |
|---|---|
| `id` / identity / AWID / bootstrap, `roles`, `instructions` | **core** (authority + runtime team facts) |
| `task` / `work` / claims | **tasks app** (compat aliases during transition) |
| `lock` (reservations) | **drop from core** or rebuild in `dev`, with deprecation path |
| `workspace status` | **split**: core presence/identity/location/role; tasks/dev supplies claims/focus/locks |
| repo/dev metadata in workspace structs | **dev app** / split from core presence |
| `mail` / `chat` | **messages/chat app** (split last, §12.10); core keeps the signed-envelope transport |
| `contacts` | **core** addressability (§3, §4.2); trust/registry depends on it — §13.7 open thin-app decision |
| `events` | **core** Event/SSE channel consumer (`events.go:18`); current comms-specific event payloads are the seam to make app-generic (§3/m3) |
| `aw a2a` / `aweb-a2a-gw` | **A2A interoperability** (§3.2), split three ways: core/AWID owns publication assertions + signer verification; gateway owns the `aweb-a2a-gw` bridge (separate from MCP); CLI owns `aw a2a` (verify/publish + outbound). **Guardrail: A2A is a separate contract — do NOT conflate with app manifests / MCP tool publication (§7).** Billing decided: hosted mutations, no separate bit (§9) |

## 5. Proposed milestone 1–2 slice (pending Juan's approval)

Converged with aweb-coordinator; **not cut until Juan approves** (SOT gate).
Consultant validation pass precedes cutting.

- **m1.1** (coordinator-led; cli + consultant review): freeze the app manifest
  schema — fields + verb→HTTP mapping rules (method, path-template, **explicit
  param placement**, scopes, mutation-flag). The literal first task; everything
  keys off it.
- **m1.2** (atext + folio teams): conformance vectors against the frozen schema;
  reuse `aweb/test-vectors/`; ≥2 real apps green.
- **m2.1** (cli): `aw plugin` management (list/install/remove) + generic
  manifest-driven dispatch + `aw-<name>` escape hatch + the env contract;
  includes the §2.4 interception point and resolution-precedence/security rules.
- **m2.2** (cli): wire dispatch to consume the frozen manifest.

Dependency: m1.1 freezes before m2.1/m2.2 code dispatch. m1/m2 are independent of
SOT §6 (still draft) — they need only `aw id request --team-auth`, which exists.

## 6. Open items feeding the cut

- Confirm atext + folio teams can produce the m1.2 conformance vectors.
- SOT + inventories are on main (`51a4f8f1`); tasks may reference them.
- No §13 open decision gates m1/m2: they're independent of §6, billing, and
  dev-shape. (A2A billing is now decided — §9. The §13.3 "anapp" rename is
  cosmetic and non-blocking — `team_id` stays the protocol subject.)
