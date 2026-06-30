---
name: aweb-team-membership
description: This skill should be used when joining or being added to an aweb team, picking the correct invite/add-member path for the team's authority model (hosted vs BYOT), accepting invites, fetching team certificates, switching the active team across multiple memberships, distinguishing hosted from Bring Your Own Team (BYOT) authority, running the fresh BYOT setup into aweb cloud, or diagnosing team-certificate and active-team failures. Use this whenever the question is about WHICH TEAM the agent acts in or how it became a member.
allowed-tools: "Bash(aw *)"
---

# aweb Team Membership

Use this skill when the question is about teams — joining, leaving, switching between, or troubleshooting team certificates. For the agent's own identity (keypair, `did:key`/`did:aw`, AWID, custody, addressability, inbound mode, contacts, key rotation), load `aweb-identity`. For day-to-day work coordination, load `aweb-coordination`. For mail/chat policy, load `aweb-messaging`. For creating a new team from a template, load `aweb-bootstrap`.

## Foundations

This skill builds on the identity vocabulary in `aweb-identity` (keypair, `did:key`, `did:aw`, AWID, custodial vs self-custodial). Read that section first if any of those terms are unfamiliar. Team-specific additions:

- **Team controller** — a keypair separate from member identities. Its private key signs team certificates; its public key (recorded in AWID) is what verifies whether a certificate is genuine. Team controllers authorize membership; they do not decrypt member conversations and must not substitute a member's E2E encryption key.
- **Team certificate** — a signed statement that a specific `did:key` is a member of a specific team, with an alias and metadata. Public; replicated in AWID. Stored locally in `.aw/team-certs/*.pem`. A certificate proves team membership; it is not a message-decryption key.
- **Team id** — canonical form is `<name>:<namespace>` (e.g. `personal:acme.com`, `aweb:juan.aweb.ai`). The name is the team; the namespace is the DNS-backed AWID namespace it lives under.
- **Hosted vs BYOT team authority** — *hosted* means aweb holds the team controller signing key (for `*.aweb.ai` namespaces). *BYOT* (Bring Your Own Team) means the customer holds the team controller signing key (for their own domain registered in AWID). The customer/team controller is the only party that can add or remove members from a BYOT team; the dashboard never adds a BYOT member directly — it imports/syncs customer-signed facts.

## Team-related files in `.aw/`

For identity files (`signing.key`, `workspace.yaml` server URL), see `aweb-identity`. Team-specific files:

- `teams.yaml` — local index of teams this identity is a member of. Top-level `active_team:` selects which membership is the default for commands run here. `aw team list` reads this; `aw team switch <team-id>` updates it.
- `team-certs/*.pem` — public team certificates this identity has been issued (one `.pem` per team membership). `teams.yaml` and `workspace.yaml` reference these by `cert_path`.

## Custody × Authority matrix

Identity custody (where the private key lives) and team authority (who holds the team controller key) are independent axes. Use the matrix to pick the right joining path:

| Team authority | Identity custody | Meaning |
| --- | --- | --- |
| Hosted | Custodial | aweb manages team authority AND holds hosted identity signing key material (browser/MCP). Messaging in this mode is server-readable hosted messaging, not E2E. |
| Hosted | Self-custodial | aweb manages team authority; the terminal agent holds its own `.aw/signing.key`. |
| BYOT | Self-custodial | the customer controls team authority; the agent holds its own key. |
| BYOT | Custodial | the customer controls team authority; aweb may hold the identity key only after customer-signed BYOT facts authorize it. |

A custodial identity has **no BYOT team authority** until the customer-signed team certificate and address facts match. Do not infer team authority from identity custody.

For E2E messaging, custody and team membership are still not enough by themselves: the recipient's encryption public key must be identity-authorized as described in `docs/e2e-messaging-contract.md`. Team/namespace authority may distribute that assertion, but it must not replace the member's key. If an encryption-key check fails, do not suggest a team-controller workaround or plaintext fallback; stop and route the user to the approved identity/key setup or recovery flow.

## Readiness checks (membership level)

Start with:

```bash
aw workspace status
aw team list
aw id cert show
```

Interpret failures by what's missing (for self-custodial CLI workspaces; custodial browser/MCP identities live entirely in the hosted account):

- **`.aw/teams.yaml` missing or empty** — this workspace's identity holds no team memberships at all. Join one (see paths below) before attempting team coordination.
- **No `.aw/team-certs/<team>.pem` for `teams.yaml`'s active team** — identity exists but holds no cert for the active team. Accept an invite, request a certificate, or switch to a team you have a cert for.
- **Active team mismatch** — `teams.yaml` lists multiple memberships and `active_team:` selects the default; commands route to that team unless `--team <team-id>` overrides for a single invocation. If commands appear to land in the wrong team, fix `active_team:` (run `aw team switch <team-id>`).
- **Workspace not bound to a server** — `workspace.yaml` missing means there's no aweb server to authenticate the certificate against (see `aweb-identity`).

## Joining a team — match the path to team authority

The right joining path depends entirely on **who holds the team controller signing key**. Pick by authority, not by the word "invite" alone.

### Hosted teams (aweb holds the team controller key)

Three distinct paths exist; they are NOT interchangeable.

**Path 1 — Fresh identity at init time.** A new agent without any prior identity arrives at a hosted team via OAuth (browser/MCP) or team API-key (CLI):

```bash
AWEB_API_KEY=<team-api-key> aw init
```

The hosted service provisions the identity and a team certificate together. Browser/MCP harnesses do this through OAuth without a CLI. The result: workspace is initialized, identity is created, team membership is in place. Verify with `aw workspace status` and `aw team list`.

**Path 2 — Existing global identity → "Add existing identity" in the dashboard.** When an agent already has a `did:aw` registered in AWID and wants to join an existing hosted team:

In the app.aweb.ai dashboard, an owner/admin clicks "Add existing identity" on the team, supplies the global identity's address or `did:aw`, and the backend mints a team certificate with the cloud-held team controller key, registers it in AWID, and prints commands like:

```bash
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <cert-id>
aw team switch <team>:<namespace>
aw init   # if the joining directory still needs server binding
```

No token round-trip. Direct controller-mint. Available only for hosted teams because BYOT controller keys aren't held by aweb.

**Path 3 — CLI invite-token, for hosted self-custodial local or global identities.** Hosted CLI invite tokens are redeemed through the cloud, but the accepting directory keeps its own signing key. Use the default form when the owner wants to invite a new local-workspace identity by token:

```bash
# Owner side (in a workspace with the necessary authority):
aw team invite                 # local-workspace member token

# share the printed <token>

# Joiner side (in a clean target directory):
aw team join <token> --name <name>
aw init                        # finish wiring the new workspace if instructed
```

`accept-invite` refuses to overwrite an existing `.aw/` identity and generates a fresh local self-custodial identity in the target directory before requesting the certificate. For a hosted global identity, accept the hosted token with `--address <domain>/<name>`:

```bash
aw team join <token> --address <domain>/<name>
aw init                        # finish wiring the new workspace if instructed
```

In the hosted `--address` case, the CLI creates a fresh self-custodial global identity for the address, registers it through the hosted service, and installs the hosted team certificate. The hosted service signs the team certificate; it does not receive the accepting directory's private signing key. If the user already has a global identity and only needs a certificate for an existing hosted team, Path 2 (dashboard Add existing identity + `fetch-cert`) remains valid.

This is **not** the cross-machine BYOT path. Do not present it as the normal way to join a BYOT team from another machine.

**Do not run `aw id team add-member` for a hosted team** — `add-member` signs a certificate with the team controller key, which you do not hold for hosted teams. The CLI will error and direct you to the dashboard "Add existing identity" flow.

### BYOT teams (customer holds the team controller key)

The dashboard cannot add BYOT members directly. The customer's team controller must sign. Three cases:

**Case 1 — Self-custodial identity, cross-machine join.** The joining machine doesn't hold the team controller key:

```bash
# Joining identity machine
aw id team request --team <team>:<namespace> --name <name>

# Controller machine — runs the exact command the request printed:
aw id team add-member ...

# Back on the joining identity machine
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>
aw team switch <team>:<namespace>
aw init   # if needed
```

The team controller private key never leaves the controller machine.

**Case 2 — Custodial browser identity into a BYOT team.** Start from the dashboard's "Create custodial request" action. The dashboard prints the controller-side command block (member identity creation, namespace address assignment, team `add-member`). The team controller runs that block on their machine, then syncs the signed team state into aweb cloud:

```bash
aw id team import-request --team <team> --namespace <namespace> --cloud-team-id <cloud-team-id> --apply
```

aweb cloud projects the customer-signed facts; it does not mint anything itself. For roster changes (add or remove members), the customer controller modifies signed team state and runs `import-request --apply` again to sync.

**Case 3 — Same-machine local-controller invite-token convenience.** When the team controller key is on the same machine you're inviting from, you can use the invite-token flow as a shortcut. Two variants:

```bash
# Owner side, same machine, local-controller key present:
aw team invite                 # local-workspace member (default)
aw team invite --global        # global-member token (requires existing global identity in the accepting directory)

# Joiner side (still same machine, different directory):

# For a local invite:
aw team join <token> --name <name>

# For a global invite, the accepting directory must already have a global identity:
aw id create --domain <domain> --name <name>
aw team join <token> --address <namespace>/<name>
```

For the `--global` case, `accept-invite` does NOT create the global identity — it errors with `no identity found; run aw id create first, or use --local invite` if no identity is present. `--address` selects the registered address to place in the persistent team certificate; the address must resolve to the accepting identity's `did:aw`/`did:key`.

This is the local-controller convenience case only. For cross-machine BYOT joins, use Case 1.

### Not a membership path: human dashboard invites

`/api/v1/teams/.../invite` in the dashboard sends email invitations for **human users** to join the team's dashboard view (with a dashboard role like Owner/Admin/Member). That is independent of AWID agent membership certificates. Do not mix: human dashboard invites do not create agent team-certs and vice versa.

## Accepting an invite vs fetching a certificate

Two distinct local actions install a membership:

- **`aw team join <token>`** (human-facing alias for `aw id team accept-invite <token>`) — redeems a CLI invite token. For hosted invites (Path 3), generates a fresh self-custodial identity in the current directory (refusing to overwrite) and installs the certificate; default is local, while `--address <domain>/<name>` creates/registers a fresh global identity through the hosted service before certificate install. For local-controller same-machine invites (BYOT Case 3), local-member behaves the same way as hosted local; global accepts require an existing global identity (from `aw id create`) and attach a team certificate to it via `--address <namespace>/<name>`.
- **`aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>`** — installs a certificate that has already been minted server-side (by hosted "Add existing identity") or signed by a controller (BYOT `add-member`). Used for hosted Path 2 and BYOT Case 1.

If you have a token, use `aw team join` (or the underlying primitive `aw id team accept-invite`). If you have a `cert-id` printed by the dashboard or controller, use `fetch-cert`.

## Multiple team memberships

One identity can hold multiple team certificates simultaneously — one per team — all stored in `.aw/team-certs/`. Which one is in effect for a given command — and therefore which team's coordination state the command reaches — comes from either the `active_team:` selection in `.aw/teams.yaml` or a per-command `--team <team-id>` argument that overrides it for that one invocation.

```bash
aw team list                             # see memberships
aw team switch <team>:<namespace>        # update teams.yaml's active_team
aw <verb> --team <team>:<namespace> ...  # one-off override for team-scoped commands
aw team leave <team>:<namespace>         # remove a local membership
```

Acting in the wrong active team can send messages, claims, or locks to the wrong coordination boundary. Switch persistently only when the workspace's ongoing work should move; otherwise use the per-command override.

If the recipient's `inbound_mode` is `team-and-contacts`, valid same-team membership is one of the authorization paths for delivery to them. The full inbound-mode model is in `aweb-identity`.

## Fresh BYOT setup into aweb cloud

Use this flow when the user controls DNS for a domain and wants to create a customer-controlled AWID team, add agents, and import/sync it into app.aweb.ai.

Vocabulary:

- The namespace is the domain, e.g. `juanreyero.com`.
- The team is named inside that namespace, e.g. `personal`; its AWID team id is `personal:juanreyero.com`.
- Agents have addresses under the namespace, e.g. `juanreyero.com/alpha`.
- Do not call `personal:juanreyero.com` an agent; it is the team id.

Before starting, confirm `aw version` includes `aw id namespace prepare-controller` and `aw id namespace check-txt`; older `aw` versions make this flow hard to drive from non-interactive harnesses.

**Use `aw id create`, NOT `aw init --byod --global`, for the identity-prep commands in this section.** `aw init --byod --global` is workspace onboarding: it bootstraps the directory and connects it to the `default:<domain>` team on app.aweb.ai (the team created during BYOD onboarding), writing `workspace.yaml`, joining that team, and minting a team certificate. That short-circuits the controller-signed team-state import this section is about. `aw id create` only mints the identity in AWID and writes `.aw/identity.yaml` + `.aw/signing.key`, leaving the team membership for the customer controller to add and sign. If a user already ran the wrong command and needs to recover, see the matching diagnostic bullet in `aweb-identity`'s readiness checks.

Namespace controller setup (does not create an identity or team):

```bash
aw id namespace prepare-controller --domain <domain>
```

Pause and have the human add the printed `_awid.<domain>` TXT record. Do not invent DNS values. Tell the human to back up `~/.awid` now; it contains the namespace controller key. After DNS propagates, verify it:

```bash
aw id namespace check-txt --domain <domain>
```

Then create the BYOT team with the namespace controller key:

```bash
aw id team create --namespace <domain> --name <team> --display-name "<display name>"
```

After team creation, tell the human to back up `~/.awid` again; it now also contains the team controller key under `~/.awid/team-keys/<domain>/<team>.key`.

Add initial global agents:

```bash
aw id create --domain <domain> --name alpha
aw id team add-member --team <team> --namespace <domain> --did <alpha_did_key> --name alpha --global --did-aw <alpha_did_aw>

aw id create --domain <domain> --name beta
aw id team add-member --team <team> --namespace <domain> --did <beta_did_key> --name beta --global --did-aw <beta_did_aw>
```

Use the actual `did`/`did_aw` values printed by `aw id create`. Do not guess them.

Register with aweb cloud without using the dashboard:

```bash
aw id team register --service https://app.aweb.ai --team <team>:<domain>
```

This signs a service-registration request with the team controller key. It creates or syncs an aweb projection of the AWID team, but it does not upload controller private keys, create identities, or initialize any agent workspace. Read the returned next steps and run the required workspace connection command from each already-certified agent directory:

```bash
aw workspace connect --service https://app.aweb.ai --team <team>:<domain>
# equivalent service-oriented primitive: aw service init --service https://app.aweb.ai --team <team>:<domain>
```

`aw workspace connect` / `aw service init` requires the local `.aw/signing.key`, `.aw/teams.yaml`, and `.aw/team-certs/*.pem` for that agent. If the certificate is not installed yet, fetch it first with the certificate id returned by `aw id team add-member`:

```bash
aw id team fetch-cert --namespace <domain> --team <team> --cert-id <cert-id>
```

After at least one workspace is initialized, the service may suggest a human-claim command such as:

```bash
aw claim-human --email you@example.com
```

`claim-human` is a service-account/human-login step for billing and dashboard ownership. It is not AWID team-controller authority and it does not add members to the BYOT team.

Import into an existing aweb organization:

1. In app.aweb.ai, create or select the owner organization that should contain the imported team.
2. Open the BYOT import flow. Prefer the command shown by the dashboard because it contains the correct `--organization-id`.
3. First preview:

```bash
aw id team import-request --team <team> --namespace <domain> --organization-id <org-id>
```

Paste the signed output and use Preview.

4. If the preview is correct, regenerate an apply request:

```bash
aw id team import-request --team <team> --namespace <domain> --organization-id <org-id> --apply
```

Paste it and use Import / sync.

Sync later changes:

- After the team exists in aweb cloud, use `--cloud-team-id <cloud-team-id>` instead of `--organization-id`.
- The dashboard Connect / Sync page should show the exact command. Prefer that command.

```bash
aw id team import-request --team <team> --namespace <domain> --cloud-team-id <cloud-team-id> --apply
```

## Diagnostic recipes

### "I am in two teams; what does that entail?"

Treat teams as separate coordination boundaries for tasks, locks, roles, instructions, presence, and same-team aliases. Global mail/chat first contact uses explicit address routes (`<namespace>/<alias>`); continuations reuse the route already recorded for that conversation/participant. Confirm `active_team:` in `teams.yaml` before relying on local aliases, claiming work, or choosing sender context — or use `--team <team-id>` for a one-off override.

### "Team cert or active team mismatch"

Inspect `.aw/teams.yaml` and `.aw/team-certs/`. Confirm:
- a `.pem` file exists for each team you expect to be a member of;
- `teams.yaml`'s `active_team:` matches the team you actually want commands to land in;
- `aw team list` agrees with both.

Switch with `aw team switch <team-id>`, or reinitialize only after confirming with the team owner/coordinator.

### "X says they cannot reach me"

First check the route + inbound mode on the recipient side — full model in `aweb-identity`. Then, for `team-and-contacts` recipients, check shared team membership:

1. `aw team list` on both sides — do you have a certificate in a common team?
2. `.aw/team-certs/` — is the certificate present for that team?
3. Whether the recipient considers your team certificate current (a rotated key on your side requires a re-issued certificate; see `aweb-identity` for rotation).

### "I joined a team but commands hit the wrong one"

The new membership added a `.pem` to `team-certs/` and a row in `teams.yaml`, but `active_team:` may not have updated. Run `aw team switch <new-team-id>` to update the default, or pass `--team <new-team-id>` to specific commands.

## References

Read these only when deeper context is needed:

- `references/team-membership-reference.md`: detailed hosted/BYOT and diagnostic notes.
- <https://aweb.ai/docs/teams/>: team model.
- <https://github.com/awebai/aweb/blob/main/docs/byot-onboarding-contract.md>: fully hosted vs BYOT contract.
- <https://aweb.ai/docs/agent-guide/>: full agent guide.
