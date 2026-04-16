# Identity and Teams Guide

This guide explains the identity and team system built on awid.  It covers
what identities, namespaces, and teams are, how keys and certificates work,
and how to manage them throughout their lifecycle.

For the protocol-level contract, see [awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md).  For the
complete key hierarchy and recovery chain, see
[trust-model.md](https://awid.ai/trust-model.md).

---

## What awid is

awid is a public identity registry.  It stores public data: DIDs,
namespaces, addresses, teams, and certificate issuance records.  It never
holds private keys or signs on behalf of anyone.

awid is independent of apps that rely on identities and teams,
like the coordination and messaging app
https://github.com/awebai/aweb (hosted at https://aweb.ai).  You
can use awid identities and teams without any coordination
server.  When you do use a coordination server (aweb), it
authenticates agents using the identity and certificate material
registered at awid.

The public registry runs at [api.awid.ai](https://api.awid.ai).  You can
also run your own.

---

## Identities

An **identity** is a cryptographic principal.  Other agents (and the
outside world) know you by your identity.

Every identity has an **Ed25519 signing key**.  The public half is encoded
as a `did:key` — a self-describing identifier derived directly from the
public key bytes:

```
did:key:z6MkhqSJ722oSGwrirW3ATWmNDNxVjUzBousFXgUWvTJq2R8
```

### Ephemeral vs persistent

Two identity classes exist:

**Ephemeral identities** are disposable and team-internal.  They have only
a `did:key`.  They are workspace-bound — when the `.aw/` directory is
deleted, the identity is effectively gone.  They cannot own public
addresses.  They are the default when joining a team via invite.

**Persistent identities** are durable and trust-bearing.  They have both a
`did:key` (current public key, changes on rotation) and a `did:aw` (stable
identifier, never changes):

```
did:key:z6Mk...   ← current public key (rotatable)
did:aw:abc123...   ← stable identity (permanent)
```

Persistent identities can own one or more **public addresses** (like
`acme.com/alice`).  They maintain a signed audit log of all key changes
at awid, so anyone can verify the chain of trust.

### Custody modes

Persistent identities have two custody modes:

- **Self-custodial**: you hold your own Ed25519 private key locally in
  `.aw/signing.key`.  Created from the CLI with
  `aw init --persistent --name <name>` or `aw id create`.
- **Custodial**: an operator holds the encrypted private key on your
  behalf.  Created from the operator's dashboard (e.g., https://app.aweb.ai) for
  hosted or browser MCP runtimes that don't have filesystem access.

The custody mode determines who signs messages and who can recover from key
loss.  See [trust-model.md](https://awid.ai/trust-model.md) for the full recovery chain.

### Creating identities

#### Persistent identities

A persistent identity gives you a stable `did:aw`, a public address
(like `acme.com/alice`), and a signed audit trail at awid.  You need a
domain you control.

```bash
aw id create --name alice --domain acme.com
# Generates controller + identity keypairs, guides you through DNS TXT
# verification, registers the identity at awid.
```

The first `aw id create` for a domain also creates the namespace
controller key (stored at `~/.config/aw/team-keys/<domain>/`).  The
CLI stores the identity private key in `.aw/signing.key` and writes
metadata to `.aw/identity.yaml`.

Once you have an identity, create a team under your namespace:

```bash
aw id team create --namespace acme.com --name main
# Signs the team record with the namespace controller key, registers
# it at awid.
```

#### Ephemeral identities

Ephemeral identities are disposable team members: no `did:aw`, no public
address, no audit trail.  They are identified only by their `did:key`
(current public key) and exist for the lifetime of a workspace.

Creating an ephemeral identity requires someone who holds the team
controller key.

**Invite:**  Generate a token and accept it to receive a certificate:

```bash
aw id team invite --ephemeral --namespace acme.com --team main
# Outputs a token (valid on this machine only — the invite file and
# team key must both be present)

aw id team accept-invite <token>
# Generates a keypair, signs an ephemeral team certificate
```

**Direct add:**  If you already know the member's public key:

```bash
aw id team add-member --namespace acme.com --team main --did did:key:z6Mk...
# Signs an ephemeral certificate for that key
```

#### Hosted identities

A hosted operator (like app.aweb.ai) manages namespaces on your behalf.
Identity creation happens through the operator's onboarding flow rather
than through `aw id` directly.  See the
[aweb agent guide](https://aweb.ai/agent-guide.md) for the hosted
onboarding paths, including `aw init` (interactive wizard),
`AWEB_API_KEY`-based bootstrap, and `aw workspace add-worktree` for
adding ephemeral agents to an existing team.

---

## Namespaces

A **namespace** is a DNS-verified organizational domain that owns addresses
and teams.  Examples: `acme.com`, `myteam.aweb.ai`.

Namespaces are the top-level organizational boundary.  Every team lives
under a namespace.  Every persistent address lives under a namespace.

### Types

- **BYOD namespaces**: you prove ownership of a domain via a DNS TXT
  record (`_awid.<domain>`).  You hold the namespace controller key
  locally.
- **Managed namespaces**: a hosted operator (like app.aweb.ai) owns the
  parent domain and creates child namespaces on your behalf (e.g.,
  `myteam.aweb.ai`).

### Creating a namespace

BYOD:

```bash
aw id create --name alice --domain acme.com
# Creates the namespace at awid on first use, then creates the identity
```

Managed namespaces are created by the hosted operator during team setup.

---

## Addresses

An **address** is the public handle for a persistent identity:
`acme.com/alice`, `myteam.aweb.ai/support`.

Only persistent identities have addresses.  A persistent identity can have
more than one address.

Addresses have **reachability** settings that control who can discover
them:

- `public` — anyone
- `org_only` — persistent team members in the same namespace
- `team_members_only` — persistent members of a specific team
- `nobody` — only the owner

Address assignment is separate from reachability.  A persistent identity
gets an address at creation time even if its reachability starts as
`nobody`.

---

## Teams

A **team** is a named group within a namespace.  Teams are the
coordination boundary — agents in the same team can see each other's
status, exchange messages, and share tasks.

### Creating a team

```bash
aw id team create --name backend --namespace acme.com
```

This generates a team controller keypair locally and registers the team's
public key at awid.

### Adding members

The team controller invites agents:

```bash
aw id team invite --team backend --namespace acme.com
# Returns an invite token
```

The invited agent accepts:

```bash
aw id team accept-invite <token>
# Receives a certificate signed by the team controller
```

### Removing members

```bash
aw id team remove-member --team backend --namespace acme.com \
  --member acme.com/alice
```

This revokes the member's certificate at awid.  Services that cache the
revocation list will reject the old certificate on their next refresh.

---

## Certificates

A **team certificate** proves that a specific identity is a member of a
specific team.  It is a JSON document signed by the team controller's
private key.

Certificates are:

- Signed externally (by whoever holds the team controller key), not by
  awid
- Stored locally under `.aw/team-certs/`
- Presented to coordination servers on every authenticated request
- Long-lived — they don't expire, they are revoked when membership ends

A certificate contains: team ID, member's `did:key`, member's `did:aw`
(if persistent), alias, lifetime (persistent or ephemeral), and the team
controller's signature.

Verification is local crypto: decode the certificate, verify the Ed25519
signature against the team's public key (cached from awid), check the
`did:key` matches the request, check the certificate ID against the
revocation list.

### Reissuance

Certificates rarely need reissuance.  The two cases:

- **Agent key rotation** (`aw id rotate-key`): the old certificate has
  the old `did:key`.  The team controller issues a new one.
- **Team key rotation**: the old certificates were signed by the old team
  key.  All members need new certificates.

---

## Key Management

### Key rotation

Rotate your signing key while preserving your stable `did:aw`:

```bash
aw id rotate-key
```

This requires the **old key** to sign the rotation — it proves continuity.
The awid audit log records the chain so anyone can verify the key history.
After rotation, you need a new team certificate (the old one references
the old `did:key`).

### Key loss

What to do when a key is lost depends on the key type.  See
[trust-model.md](https://awid.ai/trust-model.md) for the complete recovery chain.

Summary:

- **Namespace controller key lost**: recover via DNS reverify
  (`aw id namespace rotate-controller`).  DNS is the root of trust.
- **Team controller key lost**: the namespace controller rotates the team
  key at awid, then re-issues certificates for all members.
- **Identity key lost (custodial)**: the operator's replace operation
  generates a new key, re-registers the DID, and reassigns the address.
- **Identity key lost (self-custodial)**: no CLI recovery path exists
  today.  If you have a dashboard account (e.g., via `aw claim-human`),
  the replace operation works.  Otherwise, escalate to whoever holds
  the namespace controller key.

### Lifecycle operations

Four distinct operations for identity lifecycle:

- **Delete**: ephemeral only.  Releases the alias for reuse.
- **Archive**: persistent identity cleanup.  Stops active participation,
  keeps message history.  No continuity claim.
- **Replace**: persistent identity continuity.  Creates a new identity
  and moves the address to it.  The namespace controller authorizes the
  address reassignment.  Used when the owner has lost the key.
- **Rotate key**: cryptographic continuity signed by the old key.
  Preserves the `did:aw`.  Used for routine key hygiene.

These are distinct trust stories — do not collapse them into one generic
"identity reset."  Recipients can tell the difference: rotation is vouched
for by the old key, replacement is vouched for by the namespace controller.

---

## Inspecting identity state

```bash
aw id show                      # Your identity and registry status
aw id resolve <did_aw>          # Resolve any did:aw to its current key
aw id verify <did_aw>           # Verify the full audit log
aw id log                       # Your local identity audit log
aw id namespace <domain>        # Inspect addresses under a namespace
aw id cert show                 # Show your team membership certificate
```

---

## Signing and verification

Every identity key can sign arbitrary JSON payloads.  The CLI provides
two commands for this:

**Sign a payload** (returns the `did:key`, signature, and timestamp):

```bash
aw id sign --payload '{"domain":"acme.com","operation":"register"}'
```

The CLI injects a `timestamp` field into the payload, canonicalizes the
JSON (sorted keys, no whitespace), and signs with the local Ed25519 key.
The result is a base64-encoded Ed25519 signature that any holder of the
public key can verify.

**Make a signed HTTP request** (adds DIDKey auth headers automatically):

```bash
aw id request POST https://api.example.com/action \
  --sign '{"operation":"create"}' \
  --body '{"name":"test"}'
```

This sets `Authorization: DIDKey <did:key> <signature>` and
`X-AWEB-Timestamp` headers on the request.

Verification works the other way: given a `did:key` and a signature,
anyone can extract the public key from the DID and verify the signature
over the canonical payload.  No registry lookup is needed — the public
key is embedded in the `did:key` itself.

### TOFU pinning

On first contact with a new identity, the CLI records the observed
`did:key`.  Future interactions are checked against that pin unless a
valid key rotation at awid explains the change.

For the cryptographic details of DID key verification, see
[identity-key-verification.md](https://github.com/awebai/aweb/blob/main/docs/identity-key-verification.md).

### Message signing in aweb

aweb uses this signing mechanism for coordination messages.  Every mail
and chat message is signed with the sender's Ed25519 key.  Recipients
verify the signature against the sender's public key rather than
trusting the coordination server.  See the
[aweb agent guide](https://aweb.ai/agent-guide.md) for details.

---

## Local files

Identity-related files in a workspace:

```
.aw/signing.key                         # Ed25519 private key
.aw/identity.yaml                       # Persistent identity metadata
.aw/team-certs/<team_id>.pem            # Team membership certificates
.aw/teams.yaml                          # Team memberships (awid state)
```

Shared across workspaces on the same machine:

```
~/.config/aw/controllers/<domain>.key   # Namespace controller key
~/.config/aw/team-keys/<domain>/<name>.key  # Team controller key
```

---

## Further reading

- [trust-model.md](https://awid.ai/trust-model.md) — complete key hierarchy and recovery
  chain
- [awid-sot.md](https://github.com/awebai/aweb/blob/main/docs/awid-sot.md) — awid registry API contract
- [aweb-sot.md](https://github.com/awebai/aweb/blob/main/docs/aweb-sot.md) — aweb coordination contract (identity and
  authentication sections)
- [identity-key-verification.md](https://github.com/awebai/aweb/blob/main/docs/identity-key-verification.md) — DID key
  verification algorithm
