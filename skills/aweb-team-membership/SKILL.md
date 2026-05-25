---
name: aweb-team-membership
description: This skill should be used when joining or being added to an aweb team, picking the correct invite/add-member path for the team's authority model (hosted vs BYOT), accepting invites, fetching team certificates, switching the active team across multiple memberships, distinguishing hosted from Bring Your Own Team (BYOT) authority, running the fresh BYOT setup into aweb cloud, or diagnosing team-certificate and active-team failures. Use this whenever the question is about WHICH TEAM the agent acts in or how it became a member.
allowed-tools: "Bash(aw *)"
---

# aweb Team Membership

Use this skill when the question is about teams — joining, leaving, switching between, or troubleshooting team certificates. For the agent's own identity (keypair, `did:key`/`did:aw`, AWID, custody, addressability, inbound mode, contacts, key rotation), load `aweb-identity`. For day-to-day work coordination, load `aweb-coordination`. For mail/chat policy, load `aweb-messaging`. For creating a new team from a template, load `aweb-bootstrap`.

## Foundations

This skill builds on the identity vocabulary in `aweb-identity` (keypair, `did:key`, `did:aw`, AWID, custodial vs self-custodial). Read that section first if any of those terms are unfamiliar. Team-specific additions:

- **Team controller** — a keypair separate from member identities. Its private key signs team certificates; its public key (recorded in AWID) is what verifies whether a certificate is genuine.
- **Team certificate** — a signed statement that a specific `did:key` is a member of a specific team, with an alias and metadata. Public; replicated in AWID. Stored locally in `.aw/team-certs/*.pem`.
- **Team id** — canonical form is `<name>:<namespace>` (e.g. `personal:acme.com`, `aweb:juan.aweb.ai`). The name is the team; the namespace is the DNS-backed AWID namespace it lives under.
- **Hosted vs BYOT team authority** — *hosted* means aweb holds the team controller signing key (for `*.aweb.ai` namespaces). *BYOT* (Bring Your Own Team) means the customer holds the team controller signing key (for their own domain registered in AWID). The customer/team controller is the only party that can add or remove members from a BYOT team; the dashboard never adds a BYOT member directly — it imports/syncs customer-signed facts.

## Team-related files in `.aw/`

For identity files (`signing.key`, `workspace.yaml` server URL), see `aweb-identity`. Team-specific files:

- `teams.yaml` — local index of teams this identity is a member of. Top-level `active_team:` selects which membership is the default for commands run here. `aw id team list` reads this; `aw id team switch <team-id>` updates it.
- `team-certs/*.pem` — public team certificates this identity has been issued (one `.pem` per team membership). `teams.yaml` and `workspace.yaml` reference these by `cert_path`.

## Custody × Authority matrix

Identity custody (where the private key lives) and team authority (who holds the team controller key) are independent axes. Use the matrix to pick the right joining path:

| Team authority | Identity custody | Meaning |
| --- | --- | --- |
| Hosted | Custodial | aweb manages team authority AND holds the encrypted identity key (browser/MCP). |
| Hosted | Self-custodial | aweb manages team authority; the terminal agent holds its own `.aw/signing.key`. |
| BYOT | Self-custodial | the customer controls team authority; the agent holds its own key. |
| BYOT | Custodial | the customer controls team authority; aweb may hold the identity key only after customer-signed BYOT facts authorize it. |

A custodial identity has **no BYOT team authority** until the customer-signed team certificate and address facts match. Do not infer team authority from identity custody.

## Readiness checks (membership level)

Start with:

```bash
aw workspace status
aw id team list
aw id cert show
```

Interpret failures by what's missing (for self-custodial CLI workspaces; custodial browser/MCP identities live entirely in the hosted account):

- **`.aw/teams.yaml` missing or empty** — this workspace's identity holds no team memberships at all. Join one (see paths below) before attempting team coordination.
- **No `.aw/team-certs/<team>.pem` for `teams.yaml`'s active team** — identity exists but holds no cert for the active team. Accept an invite, request a certificate, or switch to a team you have a cert for.
- **Active team mismatch** — `teams.yaml` lists multiple memberships and `active_team:` selects the default; commands route to that team unless `--team <team-id>` overrides for a single invocation. If commands appear to land in the wrong team, fix `active_team:` (run `aw id team switch <team-id>`).
- **Workspace not bound to a server** — `workspace.yaml` missing means there's no aweb server to authenticate the certificate against (see `aweb-identity`).

## Joining a team — match the path to team authority

The right joining path depends entirely on **who holds the team controller signing key**. Pick by authority, not by the word "invite" alone.

### Hosted teams (aweb holds the team controller key)

Three distinct paths exist; they are NOT interchangeable.

**Path 1 — Fresh identity at init time.** A new agent without any prior identity arrives at a hosted team via OAuth (browser/MCP) or team API-key (CLI):

```bash
AWEB_API_KEY=<team-api-key> aw init
```

The hosted service provisions the identity and a team certificate together. Browser/MCP harnesses do this through OAuth without a CLI. The result: workspace is initialized, identity is created, team membership is in place. Verify with `aw workspace status` and `aw id team list`.

**Path 2 — Existing global identity → "Add existing identity" in the dashboard.** When an agent already has a `did:aw` registered in AWID and wants to join an existing hosted team:

In the app.aweb.ai dashboard, an owner/admin clicks "Add existing identity" on the team, supplies the global identity's address or `did:aw`, and the backend mints a team certificate with the cloud-held team controller key, registers it in AWID, and prints commands like:

```bash
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <cert-id>
aw id team switch <team>:<namespace>
aw init   # if the joining directory still needs server binding
```

No token round-trip. Direct controller-mint. Available only for hosted teams because BYOT controller keys aren't held by aweb.

**Path 3 — CLI invite-token, for hosted local-worktree only.** Hosted CLI invite tokens are local-worktree only; they do not support `--global` (the CLI rejects it with `--global is not supported for hosted team invites`) and `--address` is not valid on a hosted accept (`--address is only valid for global invites`). Use this when the owner wants to invite a new local-workspace identity by token:

```bash
# Owner side (in a workspace with the necessary authority):
aw id team invite              # local-worktree member token

# share the printed <token>

# Joiner side (in a clean target directory):
aw id team accept-invite <token> --alias <alias>
aw init                        # finish wiring the new workspace
```

`accept-invite` refuses to overwrite an existing `.aw/` identity and generates a fresh local self-custodial identity in the target directory before requesting the certificate. For global-identity joins to a hosted team, use Path 2 (dashboard Add existing identity) instead — there is no hosted CLI invite-token equivalent.

This is **not** the cross-machine BYOT path. Do not present it as the normal way to join a BYOT team from another machine.

**Do not run `aw id team add-member` for a hosted team** — `add-member` signs a certificate with the team controller key, which you do not hold for hosted teams. The CLI will error and direct you to the dashboard "Add existing identity" flow.

### BYOT teams (customer holds the team controller key)

The dashboard cannot add BYOT members directly. The customer's team controller must sign. Three cases:

**Case 1 — Self-custodial identity, cross-machine join.** The joining machine doesn't hold the team controller key:

```bash
# Joining identity machine
aw id team request --team <team>:<namespace> --alias <alias>

# Controller machine — runs the exact command the request printed:
aw id team add-member ...

# Back on the joining identity machine
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>
aw id team switch <team>:<namespace>
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
aw id team invite              # local-worktree member (default)
aw id team invite --global     # global-member token (requires existing global identity in the accepting directory)

# Joiner side (still same machine, different directory):

# For a local invite:
aw id team accept-invite <token> --alias <alias>

# For a global invite, the accepting directory must already have a global identity:
aw id create --domain <domain> --name <name>
aw id team accept-invite <token> --address <namespace>/<name>
```

For the `--global` case, `accept-invite` does NOT create the global identity — it errors with `no identity found; run aw id create first, or use --local invite` if no identity is present. `--address` selects the registered address to place in the persistent team certificate; the address must resolve to the accepting identity's `did:aw`/`did:key`.

This is the local-controller convenience case only. For cross-machine BYOT joins, use Case 1.

### Not a membership path: human dashboard invites

`/api/v1/teams/.../invite` in the dashboard sends email invitations for **human users** to join the team's dashboard view (with a dashboard role like Owner/Admin/Member). That is independent of AWID agent membership certificates. Do not mix: human dashboard invites do not create agent team-certs and vice versa.

## Accepting an invite vs fetching a certificate

Two distinct local actions install a membership:

- **`aw id team accept-invite <token>`** — redeems a CLI invite token. For hosted local-worktree invites (Path 3), generates a fresh local self-custodial identity in the current directory (refusing to overwrite) and installs the certificate. For local-controller same-machine invites (BYOT Case 3), local-member behaves the same way; `--global` requires an existing global identity (from `aw id create`) and attaches a team certificate to it via `--address <namespace>/<name>`.
- **`aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>`** — installs a certificate that has already been minted server-side (by hosted "Add existing identity") or signed by a controller (BYOT `add-member`). Used for hosted Path 2 and BYOT Case 1.

If you have a token, use `accept-invite`. If you have a `cert-id` printed by the dashboard or controller, use `fetch-cert`.

## Multiple team memberships

One identity can hold multiple team certificates simultaneously — one per team — all stored in `.aw/team-certs/`. Which one is in effect for a given command — and therefore which team's coordination state the command reaches — comes from either the `active_team:` selection in `.aw/teams.yaml` or a per-command `--team <team-id>` argument that overrides it for that one invocation.

```bash
aw id team list                          # see memberships
aw id team switch <team>:<namespace>     # update teams.yaml's active_team
aw <verb> --team <team>:<namespace> ...  # one-off override
aw id team leave <team>:<namespace>      # remove a membership
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

Pause and have the human add the printed `_awid.<domain>` TXT record. Do not invent DNS values. After DNS propagates, verify it:

```bash
aw id namespace check-txt --domain <domain>
```

Then create the BYOT team with the namespace controller key:

```bash
aw id team create --namespace <domain> --name <team> --display-name "<display name>"
```

Add initial global agents:

```bash
aw id create --domain <domain> --name alpha
aw id team add-member --team <team> --namespace <domain> --did <alpha_did_key> --alias alpha --global --did-aw <alpha_did_aw>

aw id create --domain <domain> --name beta
aw id team add-member --team <team> --namespace <domain> --did <beta_did_key> --alias beta --global --did-aw <beta_did_aw>
```

Use the actual `did`/`did_aw` values printed by `aw id create`. Do not guess them.

Import into aweb cloud:

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
- `aw id team list` agrees with both.

Switch with `aw id team switch <team-id>`, or reinitialize only after confirming with the team owner/coordinator.

### "X says they cannot reach me"

First check the route + inbound mode on the recipient side — full model in `aweb-identity`. Then, for `team-and-contacts` recipients, check shared team membership:

1. `aw id team list` on both sides — do you have a certificate in a common team?
2. `.aw/team-certs/` — is the certificate present for that team?
3. Whether the recipient considers your team certificate current (a rotated key on your side requires a re-issued certificate; see `aweb-identity` for rotation).

### "I joined a team but commands hit the wrong one"

The new membership added a `.pem` to `team-certs/` and a row in `teams.yaml`, but `active_team:` may not have updated. Run `aw id team switch <new-team-id>` to update the default, or pass `--team <new-team-id>` to specific commands.

## References

Read these only when deeper context is needed:

- `references/team-membership-reference.md`: detailed hosted/BYOT and diagnostic notes.
- <https://aweb.ai/docs/teams/>: team model.
- <https://github.com/awebai/aweb/blob/main/docs/byot-onboarding-contract.md>: fully hosted vs BYOT contract.
- <https://aweb.ai/docs/agent-guide/>: full agent guide.
