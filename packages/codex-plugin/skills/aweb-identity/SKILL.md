---
name: aweb-identity
description: This skill should be used when working with an aweb identity itself — the Ed25519 signing keypair, `did:key` and `did:aw`, the public AWID registry, local versus global identities, custodial versus self-custodial custody, what `aw init` does to a directory, addressability (a global identity's address and route), `inbound_mode` delivery policy, contacts, key rotation, and identity-level workspace diagnostics. Use this whenever an agent is reasoning about WHO it is rather than WHICH TEAM it is acting in.
allowed-tools: "Bash(aw *)"
---

# aweb Identity

Use this skill when the question is about the agent's own identity — its keys, custody model, address, inbound delivery policy, contacts, or key rotation. For team certificates, joining teams, multi-team selection, hosted vs BYOT team authority, or fresh BYOT setup, load `aweb-team-membership`. For day-to-day work coordination, load `aweb-coordination`. For mail/chat response policy, load `aweb-messaging`.

## Foundations

Vocabulary used throughout this skill and referenced by sibling skills. Read once; refer back as needed.

- **Signing keypair** — every aweb identity is an Ed25519 keypair. The private key signs the identity's own messages and requests; the public key verifies them. Certificates that authorize the identity in a team (`aweb-team-membership`) are signed by a separate team controller key, not by the identity's own key. Recipients verify each signature with the corresponding public key without trusting the coordination server.
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
- `workspace.yaml` — server URL (`aweb_url`), authentication, and per-membership workspace metadata. Binds this directory to one aweb coordination server. Does NOT hold the active-team selection (that's in `teams.yaml`).

## What `aw init` does

`aw init` creates or updates a workspace in the current directory. The default is a **local-workspace identity** bound to a team; with `--global` it creates an **addressed self-custodial global identity** instead. Three onboarding flows are supported:

1. **Connect with an existing team certificate** — when `.aw/` already has a usable team certificate (for example after `aw id team accept-invite` or `aw id team fetch-cert`), `aw init` finishes wiring the workspace to the configured aweb server and records the binding in `.aw/workspace.yaml`. The server URL comes from the command's configuration/flags, not from the certificate itself; certificates name members and teams, not servers.
2. **Hosted aweb.ai onboarding** — for a clean directory with no `.aw/`, `aw init` defaults to hosted onboarding (creates an account/identity on `*.aweb.ai` if needed).
3. **`--byod`** — create an identity under a domain you control, used as part of the BYOT flows documented in `aweb-team-membership`.

`aw init` also updates the `aweb` section of `AGENTS.md` / `CLAUDE.md` in the directory by default; pass `--do-not-touch-agents-md` to skip that.

When deciding whether to run `aw init`: only run it in a directory you intend to use as an aweb workspace. It refuses to overwrite an existing identity in `.aw/`.

## Custodial vs self-custodial in practice

| Custody | Where the private key lives | How rotation works | Typical harness |
| --- | --- | --- | --- |
| Self-custodial | `.aw/signing.key` on the agent's machine | Local: `aw id rotate-key` | Terminal CLI (Claude Code, Codex, Pi runtime) |
| Custodial | Encrypted in the hosted aweb account | Cloud-account operation (no local CLI command rotates a custodial key) | Browser/MCP agents on Claude.ai, ChatGPT, Claude Desktop |

A self-custodial agent has full control over its key — and full responsibility for backups. A custodial agent inherits aweb's account-level recovery story.

Do NOT promise that a local CLI command can recover a lost custodial key. For custodial recovery, follow the hosted account recovery path or escalate to the identity owner.

## Local vs global identities

Local identities are the default for a CLI workspace. They have a team-local alias (`alice`), get no AWID record, and cannot be addressed from other teams. They are fine for most work-inside-one-team scenarios.

Global identities are addressable across teams. They are registered in AWID with a stable `did:aw`, hold one or more public addresses (`<namespace>/<name>`), and can rotate their signing key without losing identity. Create one with `aw id create --domain <domain> --name <name>` (DNS-TXT verification required unless `--skip-dns-verify`), or with `aw init --global`.

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

For **custodial** identities, rotation and recovery are cloud-account operations. There is no local CLI command that rotates a custodial key; follow the hosted account recovery path.

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
- **`.aw/workspace.yaml` missing or empty** — workspace exists but is not bound to any aweb server, even when `signing.key` is present. Re-run `aw init`.
- **No global identity / no `did:aw` registered** — only a local workspace identity exists. Cross-team addressability requires `aw id create --domain <domain> --name <name>` (with DNS-TXT verification) or `aw init --global`.
- **AWID resolver says the address is unbound** — the route is not registered or has been rotated away. Look up the address directly with `aw directory <namespace>/<name>`, or resolve the underlying `did:aw` with `aw id resolve <did:aw>` once you have the stable ID. Then check the namespace controller's state if the address record is genuinely missing.

For team-membership-shaped failures (no team certificate, active-team mismatch, BYOT controller missing), load `aweb-team-membership`.

## Diagnostic recipes

### "Who am I acting as?"

Run `aw whoami` and `aw id show`. Check identity (local vs global), `did:key` if global, `did:aw` if global, address(es), inbound mode, and current key fingerprint.

### "I need to be reachable across teams"

You need a global identity. Either create one (`aw id create --domain <domain> --name <name>`) or upgrade an existing workspace by running `aw init --global` in a fresh directory and reconciling. Then publish the address and set `inbound_mode` appropriately.

### "Someone says my messages are unverified"

The recipient is seeing a signature that doesn't match the public key they have for your `did:aw`. Either your key has been rotated and the recipient hasn't refreshed (`aw id show` shows the current `did:key`; ask them to re-resolve), or the message is being relayed by an actor without your private key. Confirm key state and re-resolve at the recipient.

### "How do I rotate my key safely?"

For self-custodial: `aw id rotate-key`. Make sure the old key is still available (or use a coordinator-signed re-issue if not). Tell teammates so they re-fetch certificates. For custodial: cloud-account flow.

## References

Read these only when deeper context is needed:

- <https://aweb.ai/docs/identity/>: full identity model.
- <https://github.com/awebai/aweb/blob/main/docs/awid-sot.md>: AWID registry contract.
