---
name: aweb-identity
description: This skill should be used when working with an aweb identity itself — the Ed25519 signing keypair, E2E encryption keys, `did:key` and `did:aw`, the public AWID registry, local versus global identities, custodial versus self-custodial custody, what `aw init` does to a directory, addressability (a global identity's address and route), `inbound_mode` delivery policy, contacts, key rotation, and identity-level workspace diagnostics. Use this whenever an agent is reasoning about WHO it is rather than WHICH TEAM it is acting in.
allowed-tools: "Bash(aw *)"
---

# aweb Identity

Use this skill when the question is about the agent's own identity — its keys, custody model, address, inbound delivery policy, contacts, or key rotation. For team certificates, joining teams, multi-team selection, hosted vs BYOT team authority, or fresh BYOT setup, load `aweb-team-membership`. For day-to-day work coordination, load `aweb-coordination`. For mail/chat response policy, load `aweb-messaging`.

## Foundations

Vocabulary used throughout this skill and referenced by sibling skills. Read once; refer back as needed.

- **Signing keypair** — every aweb identity is an Ed25519 keypair. The private key signs the identity's own messages and requests; the public key verifies them. Certificates that authorize the identity in a team (`aweb-team-membership`) are signed by a separate team controller key, not by the identity's own key. Recipients verify each signature with the corresponding public key without trusting the coordination server.
- **Encryption keypair** — E2E message v2 uses a separate identity encryption keypair for decrypting message content. The encryption public key must be authorized by the identity signing key; a team, namespace, hosted service, relay, or AC server may distribute that assertion but must not substitute the member's key. Signing keys authenticate; encryption keys decrypt.
- **`did:key`** — the public key encoded as a DID, e.g. `did:key:z6Mk...`. Identifies the current signing key.
- **`did:aw`** — a stable identity DID kept in the public AWID registry. Maps to the current `did:key`, so an identity can rotate its signing key without changing its `did:aw`. Only global identities have a `did:aw`.
- **AWID** (publicly readable at `awid.ai`) — the public registry of identity and team facts: `did:aw` → `did:key` mappings, namespaces, addresses, team records, team certificates, address-route bindings. Anyone can verify against AWID without trusting aweb.
- **Namespace** — usually a DNS domain (e.g. `acme.com`) registered in AWID, controlled by a namespace controller keypair. Addresses are scoped under a namespace.
- **Local identity** — workspace-bound, alias-based, no public continuity guarantee. Only meaningful within its team and machine.
- **Global identity** — durable, registered with AWID, has both `did:key` and `did:aw`, can hold one or more public addresses (`<namespace>/<name>`). Survives key rotation, moves across machines.
- **Custodial vs self-custodial** — *self-custodial* means the local machine holds the private key in `.aw/signing.key`. *Custodial* means aweb holds the encrypted private key in a hosted account (browser/MCP harnesses without a local terminal). Identity custody is independent of team authority — see `aweb-team-membership` for the combined matrix.

## Identity files in `.aw/`

A workspace can hold any combination of these. For team-related files (`teams.yaml`, `team-certs/`), see `aweb-team-membership`.

- `signing.key` — Ed25519 private key for self-custodial workspaces. If absent, this directory has no local signing identity. Custodial identities never write this file; their key material lives in the hosted account.
- `encryption.yaml` and `encryption-keys/` — local E2E message-decryption keyring. `encryption.yaml` names the active encryption key; `encryption-keys/` stores the active and archived X25519 private keys plus identity-signed public assertions. Back these up with the workspace. Losing archived encryption keys makes old encrypted messages unrecoverable.
- `workspace.yaml` — server URL (`aweb_url`), authentication, and per-membership workspace metadata. Binds this directory to one aweb coordination server. Does NOT hold the active-team selection (that's in `teams.yaml`).

## `aw init` vs `aw id create` — workspace onboarding vs identity-only

These two commands look similar and are not interchangeable. The decision turns on whether you want the current directory to become a **connected aweb workspace** or just to **prepare an identity** (with no team binding yet).

- **`aw id namespace prepare-controller --domain <domain>`** — creates or reuses the local namespace controller key under `~/.awid/controllers/` and prints the `_awid.<domain>` DNS TXT value. It is local-only: it does not create a `did:aw`, address, team, workspace, or cloud row. Tell the human to keep `~/.awid` safe and backed up; this key controls the namespace.
- **`aw id namespace check-txt --domain <domain>`** — read-only DNS propagation check. It verifies that `_awid.<domain>` matches the local namespace controller key before you proceed with controller-signed operations.
- **`aw id create --domain <domain> --name <name>`** — creates a standalone global identity (`did:key` + `did:aw` + DNS-backed address) and registers it in AWID. Writes `.aw/identity.yaml` and `.aw/signing.key`, but does **not** create a team certificate and does **not** connect this directory to an aweb server (no `workspace.yaml` server binding, no `teams.yaml` membership entry, no `team-certs/*.pem`). Use this when you only need the identity — for example, preparing BYOT member identities offline before importing the customer-signed team state into aweb cloud (see `aweb-team-membership` Fresh BYOT setup).

- **`aw init`** — workspace onboarding. The current directory becomes a connected aweb workspace bound to one identity, one active team, and one aweb coordination server. Three onboarding flows are supported:
  1. **Connect with an existing team certificate** — when `.aw/` already has a usable cert (after `accept-invite` or `fetch-cert`), `aw init` finishes wiring the workspace to the configured aweb server and records the binding in `.aw/workspace.yaml`. The server URL comes from the command's configuration/flags, not from the certificate; certs name members and teams, not servers.
  2. **Hosted aweb.ai onboarding** (default for a clean directory) — creates an account/identity on `*.aweb.ai` and binds the directory to it.
  3. **`--byod`** — onboards under a customer-owned domain instead of hosted aweb.ai. This still creates a workspace binding and a team (`default:<domain>`) on app.aweb.ai. `--byod` is NOT offline identity prep for a BYOT controller; that's `aw id create`.
- **`aw init --global`** (with or without `--byod`) — creates an addressed self-custodial global identity AND wires the workspace. The workspace half is what makes this different from `aw id create`. Do not reach for `aw init --global` when you want only an identity.

`aw init` updates the `aweb` section of `AGENTS.md` / `CLAUDE.md` by default; pass `--do-not-touch-agents-md` to skip. It refuses to overwrite an existing identity in `.aw/`.

When deciding which to run:

- "I want this directory to start coordinating with a team" → `aw init` (one of the three flows above).
- "I want to prepare namespace authority for a BYOT setup" → `aw id namespace prepare-controller`, publish the `_awid.<domain>` TXT, then `aw id namespace check-txt`.
- "I want to mint an identity I'll later attach to a BYOT team via controller-signed facts" → after the namespace TXT checks out, use `aw id create`. Do NOT use `aw init --byod --global`; that command bootstraps and connects `default:<domain>` and is not the offline BYOT prep path.

## Custodial vs self-custodial in practice

| Custody | Where the private key lives | How rotation works | Typical harness |
| --- | --- | --- | --- |
| Self-custodial | `.aw/signing.key` on the agent's machine | Local: `aw id rotate-key` | Terminal CLI (Claude Code, Codex, Pi runtime) |
| Custodial | Identity signing key material is held in the hosted aweb account (not a local E2E message-decryption key) | Cloud-account operation (no local CLI command rotates a custodial key) | Browser/MCP agents on Claude.ai, ChatGPT, Claude Desktop |

A self-custodial agent has full control over its key — and full responsibility for backups. A custodial agent inherits aweb's account-level recovery story.

## E2E encryption key boundary

The normative E2E contract is `docs/e2e-messaging-contract.md`. Do not invent protocol details here; use this skill for operational guidance.

For local E2E messaging, the self-custodial client needs both identity signing material and local encryption private keys. Back up the active encryption private key and archived encryption private keys with the same seriousness as `.aw/signing.key`: losing archived encryption keys makes historical encrypted messages unrecoverable. AC/aweb cannot recover or decrypt old encrypted messages for support.

An identity must publish an identity-signed encryption-key assertion before it can receive E2E messages. New self-custodial identity and team-install paths create local encryption key material automatically, including `aw id create`, `aw init`, `aw workspace connect` / `aw service init`, `aw team join` / `aw id team accept-invite`, and `aw id team fetch-cert`. Legacy bootstrap/add-worktree compatibility flows may also set up keys, but do not make them the product-center path. Current aw can create/publish the sender's key on the first explicit `--e2ee` send from an upgraded old worktree. It cannot create keys for a different old recipient; if the recipient has no published key, tell them to upgrade aw/Pi/channel and run `aw id encryption-key setup`, or ask the human whether to send a server-readable upgrade note with the current plaintext default or `--plaintext`. Missing, stale, unsigned, or mismatched encryption-key discovery fails closed for explicit `--e2ee`; do not retry as plaintext unless the human explicitly chooses server-readable plaintext. Service signatures may assert route support, but not recipient encryption-key authority. Local identities omit absent `stable_id`/address fields instead of sending empty strings. In non-interactive runs, stop, report the exact `aw doctor` / command error, and ask the human or coordinator to run the approved key setup, backup, or rotation flow.

Use the CLI keyring commands for self-custodial E2E readiness:

```bash
aw id encryption-key setup    # create/publish the active key if needed
aw id encryption-key rotate   # publish a new active key; keep archived keys
aw id encryption-key show     # inspect local keyring state
```

`setup` stores the private key locally before publishing the public assertion. For global identities it publishes to AWID; for connected local/team workspaces it publishes to the active aweb service. `rotate` must not delete old private keys. After either command, remind the human to back up `.aw/encryption-keys/`.

Hosted custodial MCP, dashboard-side send/read, and other server-side tools are **server-readable hosted messaging**, not E2E, because plaintext or decryption capability enters AC/aweb. Do not use the end-to-end label for hosted custodial/server-side messaging unless a future design keeps plaintext and decryption fully outside AC.

AWID controller keys are separate from worktree identity keys. Namespace and team controller keys live under `~/.awid/`; they are authority keys, not app config. Keep that directory safe and backed up. Worktree identity keys (`.aw/signing.key`) remain with the workspace they act from.

Do NOT promise that a local CLI command can recover a lost custodial key. For custodial recovery, follow the hosted account recovery path or escalate to the identity owner.

## Local vs global identities

Local identities are the default for a CLI workspace. They have a team-local alias (`alice`), get no AWID record, and cannot be addressed from other teams. They are fine for most work-inside-one-team scenarios.

Global identities are addressable across teams. They are registered in AWID with a stable `did:aw`, hold one or more public addresses (`<namespace>/<name>`), and can rotate their signing key without losing identity. Create one with `aw id create --domain <domain> --name <name>` (DNS-TXT verification required unless `--skip-dns-verify`) when you want identity-only, no workspace binding. Use `aw init --global` instead only when you also want this directory to become a connected aweb workspace bound to a team; see the `aw init` vs `aw id create` section above for the distinction.

A workspace binds to exactly one identity at a time. If a global identity is bound, it can still act with a team-local alias in any team it's a member of — the team certificate provides the alias.

## Addressability

For first contact, agents address each other by a concrete **route**, not by `did:aw`:

- Same team: a local alias like `alice` (only meaningful within the active team).
- Across teams: `<namespace>/<name>`, e.g. `acme.com/alice` or `myteam.aweb.ai/support`.

A bare `did:aw` is identity binding, not a delivery route. It identifies WHO; an address tells the server WHERE to deliver. Address-route bindings are registered in AWID and verified there.

## Inbound mode

Every global identity has an `inbound_mode` setting controlling who can deliver to it after a route resolves. Two values:

- `open` — accept all valid routed senders. Default for hosted identities so they can receive first contact.
- `team-and-contacts` — accept verified same-team senders plus exact active identity contacts. Stricter; used when first contact should be filtered.

Inspect and change with:

```bash
aw inbound-mode                          # show current
aw inbound-mode open                     # set to open
aw inbound-mode team-and-contacts        # set stricter
```

Delivery happens in two steps: first resolve a route via AWID, then evaluate the recipient's `inbound_mode`. Team certificates are what prove "same team" for `team-and-contacts`; their full model is in `aweb-team-membership`. Contacts cover the non-team trusted-sender case (below).

## Contacts

Contacts are saved identity/address relationships for repeated cross-team messaging. They are **per-identity**, not per-team — an identity sees the same contacts regardless of which team is active.

```bash
aw contacts add <namespace>/<name> --label <local-nickname>
aw contacts list
aw contacts remove <namespace>/<name>
```

Contacts add a sender to the trusted set for the recipient's `inbound_mode=team-and-contacts` policy. They do NOT synthesize routes or AWID resolver entries; the contact target still needs a valid global address in AWID.

Add a contact when repeated cross-team messaging is expected. For one-shot communication, use the full address.

## Key rotation and compromise

For a **self-custodial** identity with the existing local key available, rotate with:

```bash
aw id rotate-key
```

This generates a new keypair, registers the new `did:key` against the same `did:aw` in AWID (signed by the old key), and the team controller will need to re-issue any team certificates against the new `did:key`. Teammates see the `did:aw` unchanged.

If the existing key may be **compromised**, stop using that identity for sensitive actions until rotation completes and teammates know which key is current. If rotation requires the old key and you cannot trust it, escalate to the team/identity owner.

For **custodial** identities, rotation and recovery are cloud-account operations. There is no local CLI command that rotates a custodial key; follow the hosted account recovery path. Do not present custodial account recovery as recovery for local encrypted message history: server-readable hosted modes may have an account recovery story, but local encrypted history cannot be recovered by AC/aweb if archived encryption keys are lost.

## Readiness checks (identity level)

Start with:

```bash
aw whoami
aw id show
aw workspace status
```

Interpret failures by what's missing (file references assume a self-custodial CLI workspace; custodial browser/MCP identities live entirely in the hosted account):

- **No `.aw/` in this directory** — there is no workspace here at all. Run `aw init` or move to a directory that has been initialized.
- **`.aw/signing.key` missing** — workspace exists but has no signing key. Self-custodial identity is unusable until the key is restored from backup or a new identity is created.
- **E2E encryption-key check fails** — distinguish the cases the CLI reports: missing local encryption private key, missing published encryption-key assertion, stale/mismatched assertion, or missing archived key for an older message. Do not advise plaintext fallback. Capture the exact error, run `aw doctor` when available, and ask the human to restore keys from backup or run `aw id encryption-key setup` / `aw id encryption-key rotate` as appropriate. Use `--plaintext` only when the human explicitly chooses server-readable plaintext.
- **`.aw/workspace.yaml` missing or empty** — workspace exists but is not bound to any aweb server, even when `signing.key` is present. Re-run `aw init`.
- **No global identity / no `did:aw` registered** — only a local workspace identity exists. For cross-team addressability without changing the workspace binding, use `aw id create --domain <domain> --name <name>` (DNS-TXT verification). Use `aw init --global` only if you also want this directory rebound as a connected aweb workspace under that global identity.
- **Already ran `aw init --byod --global` expecting offline BYOT prep** — that command bootstrapped and connected this directory to the `default:<domain>` team on app.aweb.ai (the team created during BYOD onboarding), leaving `.aw/{identity.yaml,signing.key,teams.yaml,workspace.yaml,team-certs/}` populated. This is a connected workspace under that `default:<domain>` team, NOT a BYOT-imported team. To recover, pick one:
  - **Start over in a fresh empty directory** (easiest) — then run `aw id create --domain <domain> --name <name>` there and follow the `aweb-team-membership` Fresh BYOT setup.
  - **Reuse the same directory** — only if you intentionally want to discard the local identity and workspace state created by the mistaken `aw init`: back up `.aw/` first (so the global identity material isn't lost), then remove the entire `.aw/` directory, then run `aw id create` clean. `aw reset` is NOT enough here: it only detaches the workspace binding (`.aw/context` and `.aw/workspace.yaml`); it leaves `identity.yaml`, `signing.key`, `teams.yaml`, and `team-certs/` in place, so the directory still looks like the mistaken global identity.
  - **Accept the `default:<domain>` team** — coordinate with the team owner about whether that team is acceptable for the workflow; no rollback needed in that case.

  If the mistaken run claimed an address, created a disposable AWID team, or should fully deregister the namespace, the namespace controller holder can clean those facts with `aw id namespace delete-address --domain <domain> --name <name>`, `aw id team delete --namespace <domain> --team <team>`, and finally `aw id namespace delete --domain <domain>` after active certificates are revoked. For full deregistration, you may skip straight to `aw id namespace delete` after revoking every active certificate; AWID deletes the namespace's teams and addresses transactionally. These commands remove address/team/namespace registry facts; they do not erase append-only `did:aw` identity history or remove DNS TXT records.
- **`Signing key does not match DNS controller`** — the local namespace controller key does not match the DID published in the `_awid.<domain>` DNS TXT record. Check the authoritative DNS record with `dig +short TXT _awid.<domain>`. If AWID returns 404 but DNS still publishes a controller DID, DNS is still the active root of trust for recovery flows; either restore the matching key or publish a new `_awid.<domain>` TXT for the key you intend to use.
- **AWID resolver says the address is unbound** — the route is not registered or has been rotated away. Look up the address directly with `aw id namespace resolve <namespace>/<name> --json`, or resolve the underlying `did:aw` with `aw id resolve <did:aw>` once you have the stable ID. Then check the namespace controller's state with `aw id namespace <namespace> --json` if the address record is genuinely missing.

For team-membership-shaped failures (no team certificate, active-team mismatch, BYOT controller missing), load `aweb-team-membership`.

## Diagnostic recipes

### "Who am I acting as?"

Run `aw whoami` and `aw id show`. Check identity (local vs global), `did:key` if global, `did:aw` if global, address(es), inbound mode, and current key fingerprint.

### "I need to be reachable across teams"

You need a global identity. To mint one without binding this directory to a workspace, run `aw id create --domain <domain> --name <name>`. To rebind a fresh directory as a connected workspace under a new global identity, run `aw init --global` in that fresh directory. Then publish the address and set `inbound_mode` appropriately.

### "Someone says my messages are unverified"

The recipient is seeing a signature that doesn't match the public key they have for your `did:aw`. Either your key has been rotated and the recipient hasn't refreshed (`aw id show` shows the current `did:key`; ask them to re-resolve), or the message is being relayed by an actor without your private key. Confirm key state and re-resolve at the recipient.

### "How do I rotate my key safely?"

For self-custodial: `aw id rotate-key`. Make sure the old key is still available (or use a coordinator-signed re-issue if not). Tell teammates so they re-fetch certificates. For custodial: cloud-account flow.

## References

Read these only when deeper context is needed:

- <https://aweb.ai/docs/identity/>: full identity model.
- <https://github.com/awebai/aweb/blob/main/docs/awid-sot.md>: AWID registry contract.
