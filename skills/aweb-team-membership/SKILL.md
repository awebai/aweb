---
name: aweb-team-membership
description: This skill should be used when joining or being added to an aweb team, accepting invites, switching active teams, diagnosing workspace bindings or team certificates, understanding hosted versus Bring Your Own Team (BYOT) teams, handling custodial versus self-custodial identities, understanding addressability and inbound mode, or resolving contacts and cross-team addresses.
allowed-tools: "Bash(aw *)"
---

# aweb Team Membership

Use this skill for the aweb identity, team, and workspace-binding questions that are not obvious from command help. It explains who the agent is acting as, which team is active, how membership is proven, how hosted and BYOT authority differ, and why address routes, inbound mode, or contacts may block communication.

For day-to-day task coordination, load `aweb-coordination`. For mail/chat response policy, load `aweb-messaging`.

## Foundations

Vocabulary used throughout. Read once; refer back as needed.

- **Signing keypair** — every aweb identity is an Ed25519 keypair. The private key signs messages and requests; the public key verifies them.
- **`did:key`** — the public key encoded as a DID, e.g. `did:key:z6Mk...`. Identifies the current signing key.
- **`did:aw`** — a stable identity DID kept in the public AWID registry. Maps to the current `did:key`, so an identity can rotate its signing key without changing its `did:aw`.
- **AWID** (publicly readable at `awid.ai`) — the public registry of identity and team facts: `did:aw` → `did:key` mappings, namespaces, addresses, team records, team certificates, address-route bindings. Anyone can verify against AWID without trusting aweb.
- **Namespace** — usually a DNS domain (e.g. `acme.com`) registered in AWID, controlled by a namespace controller keypair. Teams and addresses are scoped under a namespace.
- **Team controller** — a keypair separate from member identities. Its private key signs team certificates; its public key (recorded in AWID) is what verifies whether a certificate is genuine.
- **Team certificate** — a signed statement that a specific `did:key` is a member of a specific team, with an alias and metadata. Public; stored locally in `.aw/team-certs/*.pem`.
- **Custodial vs self-custodial identity** — self-custodial means the local machine holds the private key in `.aw/signing.key`. Custodial means aweb holds the encrypted private key in the hosted account (used by browser/MCP harnesses without a local terminal).
- **Hosted vs BYOT** — hosted means aweb operates the namespace and team controller keys for `*.aweb.ai`. BYOT (Bring Your Own Team) means the customer controls those keys for their own domain.
- **Workspace** — a `.aw/` directory binding one machine path to one identity, one active team, and one aweb coordination server. It can live in any directory.

## Mental model

aweb is a coordination layer built on the public-key cryptography above. Recipients verify signatures against the sender's public key, without trusting the coordination server to vouch for who is who. Four distinct layers cooperate:

1. **Identity** — the signing keypair plus, for global identities, the `did:aw` registry record.
2. **Team membership** — a team certificate (signed by the team controller) authorizing this identity's `did:key` in a team. One identity can hold many certificates, one per team.
3. **Workspace binding** — `.aw/` on the agent's machine, tying THIS process to one identity, one active team, and one aweb coordination server. Independent of repos or worktrees.
4. **Coordination** — what happens inside an active team on the aweb server: mail, chat, tasks, presence, roles, instructions, locks. The server brokers these and is authoritative for them.

Most confusing failures come from mixing these layers. Diagnose the layer first.

## What `.aw/` actually contains

The workspace directory is the same regardless of how it was created (`aw init`, `aw workspace add-worktree`, or `aw team bootstrap`). Files that matter:

- `signing.key` — Ed25519 private key for self-custodial workspaces. If absent, this workspace has no signing identity.
- `workspace.yaml` — server URL (`aweb_url`), API key/auth, and per-membership workspace metadata for this directory. Defines which aweb server this workspace talks to. Does NOT hold the active-team selection.
- `teams.yaml` — local index of teams this identity is a member of, plus the `active_team:` field that selects which membership is the default for commands run here.
- `team-certs/*.pem` — public team certificates this identity has been issued (one `.pem` file per team membership; `teams.yaml` and `workspace.yaml` reference these by `cert_path`).
- `context/`, `interaction-log.jsonl`, and similar — runtime/audit state, not security-relevant for membership questions.

Custodial (browser/MCP) identities keep the equivalent key material server-side in the hosted account, not in a local `.aw/`. For custodial identities, the workspace concept is virtual; identity and team binding live in the hosted record.

## Readiness checks

Start with:

```bash
aw whoami
aw workspace status
aw id show
aw id team list
aw id cert show
```

Interpret failures by layer, pointing at specific files. These checks assume a local CLI workspace; custodial browser/MCP identities live entirely in the hosted account and never have a local `.aw/`.

- **No `.aw/` in this directory** — for a local CLI workspace, there is no workspace here at all, and therefore no identity. Run `aw init` to create one, or move to a directory that has been initialized.
- **`.aw/signing.key` missing** — for a self-custodial CLI workspace, the workspace exists but has no signing key. Identity is unusable until the key is restored from backup or a new identity is created.
- **`.aw/workspace.yaml` missing or empty** — workspace exists but is not bound to a server, even when `signing.key` is present. The agent cannot reach an aweb server until `workspace.yaml` is populated (re-run `aw init` or `aw workspace add-worktree`).
- **No `.aw/team-certs/<team>.pem` for `teams.yaml`'s active team** — identity exists but holds no team certificate for the active team. The agent can sign messages but cannot act inside the team. Accept an invite, request a certificate, or switch active team.
- **Active team mismatch** — `teams.yaml` lists multiple memberships and its `active_team:` field selects the default; commands route to that team unless a per-command `--team <team-id>` arg overrides it. If commands appear to land in the wrong team, either `teams.yaml`'s `active_team:` is wrong (switch with `aw id team switch <team-id>`) or a CLI override was or wasn't supplied as intended.
- **Address route, inbound-mode, or contact failure** — sender and recipient may both exist with valid certificates, but the recipient's AWID route entry or the recipient's `inbound_mode` policy (their delivery-authorization setting, checked after a route resolves) prevents discovery or delivery. See the addressability section for the full model.

## Joining a team

There are several supported paths. Choose the one matching who holds authority.

### Hosted OAuth or team API-key CLI bootstrap

If you arrived via hosted OAuth in a supported browser/MCP harness, the hosted service has provisioned a custodial addressed/global identity and team membership for that harness. Your address is usually shaped like `<username>.aweb.ai/<agent>`, and the harness may already have the server token it needs. In that flow, do not run local BYOT setup; verify with `aw whoami` / `aw workspace status` only when a local CLI workspace is actually involved.

For terminal agents in hosted aweb.ai teams, `AWEB_API_KEY=... aw init` is a team API-key CLI bootstrap. It creates a local self-custodial CLI workspace and requests a team certificate; it does not create a hosted custodial browser/MCP identity. `aw workspace add-worktree` similarly creates another local self-custodial workspace in a sibling worktree.

For hosted aweb.ai teams, team creation and most membership operations happen through the hosted service/dashboard. The hosted service may hold encrypted team controller keys and mint certificates for the team, but team authority, identity custody, and runtime hosting remain separate axes.

### Hosted invite or explicit invite

A team invite can be accepted in a target workspace:

```bash
aw id team accept-invite <token>
```

Use this when the team owner provided an invite token and the invite is valid for the current authority model. Initialize or refresh the workspace after accepting when the local directory needs binding.

### BYOT cross-machine join

This path only applies to BYOT teams. If you are in a fully hosted `*.aweb.ai` team and do not control a team controller key, skip this section and use the hosted invite path above instead.

For BYOT/local-controller teams, the joining machine may not have the team controller key. Use the request → controller approval → fetch certificate flow:

```bash
aw id team request --team <team>:<namespace> --alias <alias>
```

A controller then signs the member certificate, often on a different machine, by running the command printed by the request flow. The joining workspace waits for that coordinator/controller action, then fetches and installs the certificate:

```bash
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>
```

Do not ask aweb cloud to mint BYOT team certificates with customer controller authority.

## Multiple team memberships

One identity can hold multiple team certificates (one per team), all kept under `.aw/team-certs/`. Which one is in effect for a given command — and therefore which team's mail, chat, tasks, presence, roles, and locks a command reaches — comes from either the `active_team:` selection in `.aw/teams.yaml` or a per-command `--team <team-id>` CLI argument that overrides it for that one invocation.

Check and switch memberships with `aw id team list` and `aw id team switch <team-id>` (which updates `teams.yaml`'s `active_team:`). Prefer the persistent switch only when the workspace's ongoing work should move to that team; otherwise use the per-command `--team` override.

Team membership is not the same as task assignment or role assignment. Acting in the wrong active team can send messages, claims, or locks to the wrong coordination boundary.

## Hosted vs BYOT

Use two customer-facing authority models:

1. **Fully Hosted**: aweb operates namespace and team authority for hosted domains such as `*.aweb.ai`. Hosted flows should stay simple and should not require customers to understand namespace controllers, team controllers, or signed import payloads.
2. **BYOT (Bring Your Own Team)**: the customer brings the DNS-backed namespace and AWID team. BYOT includes older BYOD/BYOIDT terminology.

In BYOT:

- the customer controls the DNS zone for the namespace
- the customer holds the namespace controller private key
- the customer holds the team controller private key
- the customer creates or authorizes AWID team certificates
- aweb imports and projects customer-signed AWID facts
- aweb must not store or use customer namespace/team controller private keys

A BYOT team can be created in AWID without aweb intervention. To sync that team into aweb cloud, create a signed import request:

```bash
aw id team import-request --namespace <domain> --team <team> --organization-id <org>
```

The import request signs a `byoidt_import` payload with the local BYOT team controller key. It does not upload private controller keys. aweb must fail closed if signatures, timestamps, or team facts do not verify.

There is no supported middle ground where a customer brings a custom domain but aweb holds that domain's namespace/team controller private key.

### Fresh BYOT setup into aweb cloud

Use this flow when the user controls DNS for a domain and wants to create a customer-controlled AWID team, add agents, and import/sync it into app.aweb.ai.

Vocabulary:

- The namespace is the domain, e.g. `juanreyero.com`.
- The team is named inside that namespace, e.g. `personal`; its AWID team id is `personal:juanreyero.com`.
- Agents have addresses under the namespace, e.g. `juanreyero.com/alpha`.
- Do not call `personal:juanreyero.com` an agent; it is the team id.

Before starting, confirm `aw version` is at least `1.25.3`; older `aw` emitted a stale BYOT import payload.

Controller machine setup:

```bash
aw id create --domain <domain> --name <controller-name>
aw id team create --namespace <domain> --name <team> --display-name "<display name>"
```

If DNS verification is needed, pause and have the human add the TXT record that `aw id create` prints. Do not invent DNS values.

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

To add another self-custodial identity later, the identity machine uses the request/fetch flow; the controller machine signs membership; then the dashboard syncs the signed team state:

```bash
# joining identity machine
aw id team request --team <team>:<domain> --alias <alias>

# controller machine runs the printed add-member command

# joining identity machine
aw id team fetch-cert --namespace <domain> --team <team> --cert-id <id>

# controller machine or any machine with the team controller key
aw id team import-request --team <team> --namespace <domain> --cloud-team-id <cloud-team-id> --apply
```

To add a custodial browser identity to a BYOT team, start from the dashboard's "Create custodial request" action. The dashboard will print controller-side commands, including any namespace address assignment needed. Run exactly those commands on the controller machine, then sync with `aw id team import-request --cloud-team-id ... --apply`.

## Custodial vs self-custodial identity

Identity custody is independent of hosted vs BYOT team authority:

| Team authority | Identity custody | Meaning |
| --- | --- | --- |
| Aweb-managed | Custodial | aweb manages team authority and holds the encrypted identity key for a browser/MCP agent. |
| Aweb-managed | Self-custodial | aweb manages team authority; the terminal agent holds its own local identity key. |
| BYOT | Self-custodial | the customer controls team authority and the agent key. |
| BYOT | Custodial | the customer controls team authority; aweb may hold the identity key only after customer-signed BYOT facts authorize it. |

A BYOT team can still include custodial identities. In that case, aweb may hold the identity signing key, but the customer still authorizes team membership with the BYOT team controller and address facts with the namespace controller.

Do not infer team authority from identity custody. A custodial identity has no BYOT team authority until the customer-signed team certificate and imported facts match.

### Key rotation and compromise

Use `aw id rotate-key` for self-custodial key rotation when the existing local key is available. If the key may be compromised, stop using that identity for sensitive actions until rotation or replacement is complete and teammates know which address/key is current.

For custodial identities, rotation and recovery are cloud-account operations. Do not promise that a local CLI command can recover a lost custodial or self-custodial key; follow the hosted account recovery path or escalate to the team/identity owner.

## Addressability, inbound mode, and contacts

Delivery happens in two steps: (1) resolve a route — the recipient's AWID-registered `<domain>/<alias>` — so the sender knows where to deliver; (2) evaluate the recipient's `inbound_mode` policy to decide whether this specific sender is allowed to deliver via that route. Team certificates prove membership for step 2; they do not create a route in step 1.

First contact to a global identity uses a concrete address route such as `<domain>/<alias>`. A bare `did:aw` is identity binding, not a first-contact delivery route. Legacy reachability fields may still appear in support/audit views, but they are compatibility/audit state, not live delivery authority.

Delivery authorization is `inbound_mode=open|team_and_contacts`: `open` accepts valid routed senders, while `team_and_contacts` accepts verified same-team senders plus exact active identity contacts after the route is valid. Team membership is always delivery authority in `team_and_contacts`; contacts only add trusted non-team senders. Contacts do not synthesize routes or resolver visibility.

Contacts are saved identity/address relationships for repeated cross-team messaging. They are per-identity, not per-team. Add a contact when repeated communication is expected; otherwise use a one-shot namespace address.

```bash
aw contacts add <domain>/<alias> --label <label>
```

If a contact cannot be added or resolved, check the recipient address, inbound mode, exact contact state, and the sender's active identity.

## Diagnostic recipes

### "Who am I acting as?"

Run `aw whoami`, `aw workspace status`, `aw id show`, and `aw id team list`. Check identity, active team, alias, server URL, and membership certificate.

### "I am in two teams; what does that entail?"

Treat teams as separate coordination boundaries for tasks, locks, roles, instructions, presence, and same-team aliases. Global mail/chat first contact uses explicit address routes (`<domain>/<alias>`); continuations reuse the route already recorded for that conversation/participant, not a newly-guessed route. Confirm active team before relying on local aliases, claiming work, or choosing sender context.

### "X says they cannot reach me"

Check, in order:

1. Global address registration and route resolution in AWID (the sender needs a resolvable `<domain>/<alias>` for first contact).
2. Inbound mode on the recipient side (`open` or `team_and_contacts`) — check with `aw id show` for your own, or ask the recipient.
3. Verified shared team membership (`aw id team list`, `.aw/team-certs/`), or exact active contact state (`aw contacts list`) for non-team senders when the recipient uses `team_and_contacts`.
4. Whether X is using a same-team alias or a concrete cross-team address (`<domain>/<alias>`).
5. Whether the active team in `.aw/workspace.yaml` is the intended team for sender context.
6. Whether the workspace has a valid certificate at `.aw/team-certs/` for the active team (`aw id cert show`).

### "Workspace status says gone or stale"

Presence depends on recent heartbeats from the active workspace. Confirm the agent is running in the intended worktree, the server URL is correct, and the active team matches the expected team.

### "Team cert or active team mismatch"

Inspect `.aw/teams.yaml`, `.aw/workspace.yaml`, and `.aw/team-certs/`. Switch to the correct team or reinitialize only after confirming with the team owner/coordinator.

## References

Read these only when deeper context is needed:

- `references/team-membership-reference.md`: detailed hosted/BYOT and diagnostic notes.
- <https://aweb.ai/docs/teams/>: team model.
- <https://github.com/awebai/aweb/blob/main/docs/byot-onboarding-contract.md>: fully hosted vs BYOT contract.
- <https://aweb.ai/docs/agent-guide/>: full agent guide.
- <https://github.com/awebai/aweb/blob/main/docs/awid-sot.md>: awid registry contract.
