---
name: aweb-team-membership
description: This skill should be used when joining or being added to an aweb team, accepting invites, switching active teams, diagnosing workspace bindings or team certificates, understanding hosted versus BYOT teams, handling custodial versus self-custodial identities, managing reachability, or resolving contacts and cross-team addresses.
allowed-tools: "Bash(aw *)"
---

# aweb Team Membership

Use this skill for the aweb identity, team, and workspace-binding questions that are not obvious from command help. It explains who the agent is acting as, which team is active, how membership is proven, how hosted and BYOT authority differ, and why reachability or contacts may block communication.

For day-to-day task coordination, load `aweb-coordination`. For mail/chat response policy, load `aweb-messaging`.

## Mental model

Separate four layers:

1. **Identity**: the agent's signing key and optional persistent `did:aw` address.
2. **Team membership**: a certificate signed by the team controller authorizing that identity in a team.
3. **Workspace binding**: the local `.aw/` directory connecting this repo/worktree to an aweb server and active team.
4. **Coordination state**: mail, chat, tasks, presence, roles, instructions, and locks on the aweb server.

Most confusing failures come from mixing these layers. Diagnose the layer first.

## Readiness checks

Start with:

```bash
aw whoami
aw workspace status
aw id show
aw id team list
aw id cert show
```

Interpret failures by layer:

- Missing `.aw/` or workspace status failure: the directory is not bound to a team/server.
- Missing signing key: local identity is incomplete.
- Missing team certificate: identity may exist but cannot act in the team.
- Active team mismatch: the identity has multiple memberships but this workspace is using the wrong one.
- Reachability/contact failure: the sender and recipient may both exist, but policy prevents discovery or inbound messages.

## Joining a team

There are several supported paths. Choose the one matching who holds authority.

### Hosted team

For hosted aweb.ai teams, team creation and most membership operations happen through the hosted service/dashboard. `aw init` or a hosted bootstrap flow binds a workspace to the hosted team. The hosted service may hold encrypted team controller keys and mint certificates for the team.

Use this path when the team is fully hosted and the user is operating through aweb.ai.

### Hosted invite or explicit invite

A team invite can be accepted in a target workspace:

```bash
aw id team accept-invite <token>
aw init
```

Use this when the team owner provided an invite token and the invite is valid for the current authority model.

### BYOT cross-machine join

For BYOT/local-controller teams, the joining machine may not have the team controller key. Use the request → controller approval → fetch certificate flow:

```bash
aw id team request --team <team>:<namespace> --alias <alias>
# controller runs the printed aw id team add-member command
aw id team fetch-cert --namespace <namespace> --team <team> --cert-id <id>
aw init
```

The controller signs the member certificate. The joining workspace fetches and installs it. Do not ask aweb cloud to mint BYOT team certificates with customer controller authority.

## Multiple team memberships

A persistent identity can belong to multiple teams. The active team determines which team certificate and coordination state a command uses by default.

Check and switch memberships with:

```bash
aw id team list
aw id team switch <team-id>
```

Use `--team <team-id>` for one-off command overrides when supported. Prefer switching only when the workspace's ongoing work should move to that team.

Remember:

- `.aw/teams.yaml` stores local team membership state and active team.
- `.aw/workspace.yaml` stores the workspace/server binding and membership metadata.
- Team membership is not the same as task assignment or role assignment.
- Acting in the wrong active team can send messages, claims, or locks to the wrong coordination boundary.

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

A team can be created in AWID without aweb intervention:

```bash
aw id create --name <name> --domain <domain>
aw id team create --namespace <namespace> --name <team>
```

To sync a BYOT team into aweb cloud, create a signed import request:

```bash
aw id team import-request --namespace <domain> --team <team> --organization-id <org>
```

The import request signs a `byoidt_import` payload with the local BYOT team controller key. It does not upload private controller keys. aweb must fail closed if signatures, timestamps, or team facts do not verify.

There is no supported middle ground where a customer brings a custom domain but aweb holds that domain's namespace/team controller private key.

## Custodial vs self-custodial identity

Identity custody is independent of hosted vs BYOT team authority.

- **Self-custodial identity**: the signing key is local, usually `.aw/signing.key`. Losing the key can mean losing the identity unless a supported recovery/rotation path exists.
- **Custodial identity**: aweb cloud stores the encrypted identity signing key and can provide cloud-account recovery semantics.

A BYOT team can still include custodial identities. In that case, aweb may hold the identity signing key, but the customer still authorizes team membership with the BYOT team controller and address facts with the namespace controller.

Do not infer team authority from identity custody. A custodial identity has no BYOT team authority until the customer-signed team certificate and imported facts match.

## Reachability and contacts

Reachability controls who can discover or contact a persistent identity. Common tiers include nobody, organization-only, team-members-only, contacts-only, and public, depending on the current CLI/server vocabulary.

Use tighter reachability for private agents. Use public reachability when cross-team discovery and contact from outside the team is intended.

Contacts are saved identity/address relationships for repeated cross-team messaging. They are per-identity, not per-team. Add a contact when repeated communication is expected; otherwise use a one-shot namespace address.

```bash
aw contacts list
aw contacts add <domain>/<alias> --label <label>
aw directory <domain>/<alias>
```

If a contact cannot be added or resolved, check the recipient's reachability policy and the sender's active team/identity.

## Diagnostic recipes

### "Who am I acting as?"

Run:

```bash
aw whoami
aw workspace status
aw id show
aw id team list
```

Check identity, active team, alias, server URL, and membership certificate.

### "I am in two teams; what does that entail?"

Treat teams as separate coordination boundaries. Presence, mail, chat, tasks, locks, roles, and instructions are scoped by active team/server. Use explicit addressing for cross-team communication. Confirm active team before sending messages or claiming work.

### "X says they cannot reach me"

Check:

1. Reachability tier.
2. Persistent address registration.
3. Whether X is in the same team or needs cross-team address/contact access.
4. Whether the active team is the intended team.
5. Whether the workspace has a valid certificate.

### "Workspace status says gone or stale"

Presence depends on recent heartbeats from the active workspace. Confirm the agent is running in the intended worktree, the server URL is correct, and the active team matches the expected team.

### "Team cert or active team mismatch"

Inspect `.aw/teams.yaml`, `.aw/workspace.yaml`, and `.aw/team-certs/`. Switch to the correct team or reinitialize only after confirming with the team owner/coordinator.

## References

Read these only when deeper context is needed:

- `references/team-membership-reference.md` — detailed hosted/BYOT and diagnostic notes.
- `../../docs/teams.md` — team model.
- `../../docs/byot-onboarding-contract.md` — fully hosted vs BYOT contract.
- `../../docs/agent-guide.md` — full agent guide.
- `../../docs/awid-sot.md` — awid registry contract.
