# Team Create & Membership Model (SOT)

Status: v1 (2026-06-20), owned by the aw CLI lane (aw-coordinator). Grounded in
the awid + aw CLI source on main. The shipped command surface is the generated
[CLI reference](../cli-command-reference.md); this pairs with it and with the
agent-home composition contract.

This is the decided model for how teams are created and populated, and the
contract `aw team create` / `aw team add` / `aw team invite` must satisfy. It
corrects a real bug: `aw team create` without an API key wrongly errored
"requires a local awid registry."

## 0. Principle

Two facts drive everything.

1. **Team lifecycle is three SEPARABLE operations, not one:**
   - **Provision an identity** — mint a signing keypair (did:key), optionally
     register it globally (did:aw + address). Happens ~once.
   - **Create a team** — register a team you control. A signed operation;
     repeatable.
   - **Populate a team** — add members: agents you mint, or external identities
     you invite. Repeatable.

   `aw init` *fuses* all three for a brand-new user. The standalone verbs
   (`aw team create` / `add` / `invite`) are the repeatable operations for an
   identity that **already exists**.

2. **awid does not know or care where it runs.** Which registry you point at
   (default `https://api.awid.ai`) is orthogonal to how you create or manage
   teams. There is no "localhost path" on the server. The variable that actually
   matters is the **namespace** and **who controls it** — not registry location.

## 1. The awid mechanics (verified)

Auth at the awid layer is Ed25519 signatures, never an API key.

- **Default registry**: `https://api.awid.ai` (`cli/go/awid/registry_dns.go:16`);
  override via `--awid-registry`, `AWID_REGISTRY_URL`, or a domain's DNS TXT
  record (BYOT).
- **Register identity**: `POST /v1/did`, self-signed proof by the new did:key
  (`awid/src/awid_service/routes/did.py`).
- **Create team**: `POST /v1/namespaces/{domain}/teams`, authorized by an
  Ed25519 signature from the namespace's `controller_did` — **no API key**
  (`awid/src/awid_service/routes/teams.py`, `_require_namespace_controller`;
  client `cli/go/awid/registry_team.go` `CreateTeam`). The team itself gets a
  fresh team keypair, minted per team.
- **Register member cert**: `POST /v1/namespaces/{domain}/teams/{name}/certificate`,
  signed by the team key.
- The awid server is deployment-agnostic; only `delivery_origin` validation
  flips on `APP_ENV`.

Local key material (self-custodial):
- Identity: `.aw/identity.yaml` (`WorktreeIdentity`) + `.aw/signing.key`
  (`cli/go/awconfig/identity.go`). A **global** identity has `identity_scope:
  global`, `stable_id` (did:aw), and `address`; a **local** identity has
  `identity_scope: local` and `did` (did:key). Older identity configs may still
  contain deprecated-read-compat `lifetime: persistent|ephemeral`.
- Namespace controller key: `~/.awid/controllers/<domain>.key`
  (`cli/go/awconfig/controllers.go`).
- Team key: `~/.awid/team-keys/<domain>/<name>.key`
  (`cli/go/awconfig/team_keys.go`).

## 2. Two custody models

Every operation behaves according to which model the identity is in. **This is
the real axis — not localhost.**

**A. Self-custodial (you control the namespace).** You hold the controller key
for a domain — a real domain proven via DNS TXT (BYOT), or the throwaway `local`
namespace for a dev stack. Create-team and add-member are **local signed
operations** against the configured registry, no API key.

**B. Hosted-managed (aweb.ai controls the namespace).** You signed up via
`app.aweb.ai`; your teams live under aweb.ai's namespace, whose controller key
you do **not** hold. Creating another team or adding members cannot be a local
awid signature — it must go through the hosted layer on `app.aweb.ai` (AC's
onboarding/management surface), keyed by the credential that layer issues.

The `local`/localhost flow is just **model A with a throwaway namespace on a
local registry**. It is NOT a third architecture.

## 3. `aw init` — the from-nothing bundle (what to reuse)

`aw init` (no API key, fresh workspace) branches:
- **API key present** → bootstrap into the team that key maps to.
- **localhost registry + no onboarding flags** (`initShouldUseImplicitLocalFlow`,
  `cli/go/cmd/aw/init.go:428`) → self-custodial local: register the `local`
  namespace + `default` team + cert, all signed (`runImplicitLocalInit`,
  `init_local.go`; domain/team hardcoded at `init_local.go:12-13`). **Model A.**
- **otherwise — the default for a real user** → guided hosted onboarding:
  `cli-signup` on `app.aweb.ai` provisions a new account + first team under
  aweb.ai's namespace (`cli/go/awid/onboarding_cli_signup.go`; the endpoint
  itself is AC's, not in this repo). **Model B.**

From the user's view `aw init` is "set me up," defaulting to a working hosted
team. The localhost branch is a special case of model A; the default branch is
model B.

## 4. `aw team create` — corrected contract

`aw team create <name>` is "give me a team." It must **reuse `aw init`'s
branching, not reimplement a subset.** The branch key is **identity existence**,
then **namespace control** — never localhost.

1. **No identity yet** → run `aw init`'s bundle: hosted onboarding by default
   (model B), or the local self-custodial flow if the registry is localhost
   (model A). *This is the path the current code wrongly dropped.*
2. **Identity exists and controls a namespace** (model A — `.aw/identity.yaml`
   has an `address`, and a controller key exists for its domain) → mint a NEW
   team under that domain, signed, against the identity's registry — **no
   re-signup.** Like the from-nothing path, create **enrolls the caller as the
   first member** of the new team: a member certificate signed by the new team
   key (e.g. `bootstrapLocalTeamMemberWithScope` with the existing identity's
   signing key as the member key), persisted **additively** alongside existing
   memberships (never clobber), with the new team set active. The machinery
   exists: `resolveLocalSigningIdentity` (`cli/go/cmd/aw/id_request.go:251`) to
   detect the identity + load its key, the loaded controller key, and the
   team-member bootstrap. The wiring is into the human `aw team create <name>`
   (auto-detect domain + controller key instead of requiring `--namespace`).

   **Create must yield a usable team, not just a registered one.**
   `ensureLocalTeamRegistered` alone registers the team but leaves no member
   cert — the caller controls the namespace but cannot act in the team
   (coordination needs a member cert). That silent half-create is a trap and is
   not acceptable.
3. **Identity exists but is hosted-managed** (model B — no controller key for its
   namespace) → route to the hosted "create another team" path on
   `app.aweb.ai`. Whether that endpoint exists is an open cross-lane item (§7);
   until confirmed, fail with a clear message rather than the bogus "requires a
   local awid registry."

The localhost gate and the "requires a local awid registry" error are
**removed**: they conflated registry location with namespace ownership.

`--byot` / `--namespace` is the explicit model-A create for a domain you
control. Like every other `aw team create` branch, it **must yield a usable
team, never a register-only half-create**:

- **Local member identity present** (`.aw/identity.yaml` + `.aw/signing.key`) →
  enroll the creator as the first member, exactly as the auto-detect model-A
  path does (member cert + additive membership + active + binding). The
  `--namespace` is taken explicitly instead of auto-detected from the address.
- **No member identity, controller key only** (a pure operator minting a team
  for a domain they control) → do **not** silently register-only. Fail closed
  with a clear message: use `aw id team create` for a controller-only team, or
  `aw init` / `aw id create` first to get a member identity.

The register-only primitive is **`aw id team create`** (the protocol/admin
controller surface), which intentionally stops at team registration with no
member enrollment. The human `aw team create --byot` must not collapse into it.

No `--profile` → empty-profile team (hard invariant, unchanged).

## 5. Populating a team — `aw team add` / `aw team invite`

Member-adding is a **separate** concern from create, and the verbs already
exist:
- **`aw team add a b c …`** — mint a bunch of new team-owned agent members into
  the active team (local identity + team cert + home each). Needs the team key
  (model A: held locally; model B: via the API-key path the dashboard emits).
- **`aw team invite` → `aw team join <token>`** — bring in a separate
  workspace / machine / external identity (someone with their own key).

Create makes the team and makes you its controller; add/invite populate it. We
do **not** bake member-adding into create.

## 6. The bug this corrects

`cli/go/cmd/aw/team_human.go:258`: `aw team create` (no key, no `--byot`)
handled only the API-key branch and the localhost-implicit branch, and errored
"requires a local awid registry" for everything else — dropping `aw init`'s
default hosted-onboarding branch and offering no existing-identity branch. A
normal user got an error where `aw init` would have created their team.

## 7. Open cross-lane items

- **Hosted "create another team"** (model B, §4.3): does `app.aweb.ai` expose
  creating an additional team under aweb.ai's namespace for an already-existing
  identity, and with what credential? `cli-signup` is signup (account + first
  team), not "add a team." Coordinate with the AC lane.
- **Hosted member-add custody** (§5): confirm whether `aw team add` / `invite`
  against a hosted team use a locally-held team key or the API-key path. Trace
  end to end before relying on it.

## 8. Tasks

- `default-aaas.3.14` — `aw team create`: reuse `aw init` branching; add the
  existing-identity model-A mint; drop the localhost gate and the bogus error.
- `default-aaas.3.15` — hosted team lifecycle facts (model B): create-another-
  team + add-member on `app.aweb.ai`; coordinate with AC.
