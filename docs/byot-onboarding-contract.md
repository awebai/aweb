# Fully Hosted and BYOT Onboarding Contract

Status: **current advanced authority contract**. This page defines public
identity/team authority boundaries; it does not define a private hosted
application or require one to understand the OSS flow.

The supported authority choices are:

1. **Fully Hosted** — a hosted operator controls namespace/team authority for
   resources under its own hosted domain.
2. **Bring Your Own Team (BYOT)** — the customer controls a DNS-backed
   namespace and the AWID team controllers.

There is no supported middle tier in which a hosted operator quietly holds the
controller private keys for a customer-controlled domain.

## Authority is separate from custody and hosting

Three questions must be answered independently:

1. **Identity custody:** who holds the member's signing key?
2. **Namespace/team authority:** who can assign addresses and certify members?
3. **Coordination hosting:** which aweb server stores mail, chat, events, and
   optional coordination state?

A self-custodial identity can join a hosted-authority team. A custodial identity
can join a BYOT team only after the customer-held team controller signs its
certificate. Hosting coordination state never grants namespace or team
authority.

## Fully Hosted

Fully Hosted means the operator controls a namespace under its own hosted base
domain, such as `*.aweb.ai`, and holds that hosted namespace's controller key.
It may:

- create child namespaces under the hosted base domain;
- create hosted teams and hold their controller keys;
- assign addresses in hosted namespaces;
- mint and revoke certificates for hosted teams;
- offer either self-custodial terminal identities or custodial browser/service
  identities.

A terminal join remains self-custodial when `.aw/signing.key` stays on the
member's machine. The hosted operator signs only the team certificate with the
hosted team controller; it does not need the member private key.

The operator may custody an identity signing key only for an explicitly
custodial flow. That does not make AWID custodial: AWID stores public registry
facts and identity-signed assertions, never private keys.

## BYOT

BYOT means the customer brings a DNS-backed namespace and an AWID team. The
customer:

- controls the namespace DNS zone;
- holds the namespace controller private key;
- holds the team controller private key;
- creates or authorizes address bindings;
- signs member certificates and certificate revocations.

A coordination host may verify and project those public AWID facts into runtime
rows. It must not upload, store, derive, or use the customer namespace or team
controller private keys.

### Standalone OSS path

The public CLI primitives are sufficient; Library is not involved:

```bash
aw id namespace prepare-controller --domain example.com
# Publish the exact _awid.example.com TXT value printed by the command.
aw id namespace check-txt --domain example.com
aw id team create \
  --namespace example.com \
  --name engineering \
  --display-name "Engineering"
```

On the namespace-controller machine, prepare an initial addressed member in its
own directory, then print the team-controller approval command:

```bash
aw id create --domain example.com --name alice
aw id team request --team engineering:example.com --name alice
```

`aw id create` needs the local controller key for the address namespace; a fresh
machine without that authority cannot claim `example.com/alice`. For a
cross-machine join, the joining directory must already hold a global signing
identity/address under a namespace it controls before running
`aw id team request`; local identities are not reused across teams.

The request prints the exact `aw id team add-member` command for the team
controller machine. After approval, the member installs the public certificate,
then explicitly connects to the chosen aweb service:

```bash
aw id team fetch-cert \
  --namespace example.com \
  --team engineering \
  --cert-id <certificate-id>
aw workspace connect \
  --service https://coordination.example.com \
  --team engineering:example.com
```

`fetch-cert` installs membership but does not connect a service.
`aw service init --service ... --team ...` is the equivalent service-oriented
connection primitive; use the exact command supplied by the chosen service.
These steps create the runtime projection; they do not transfer controller keys
or change who can administer the AWID team. Invite-token joins are different:
follow their output, because a hosted join may already be connected and must not
be unconditionally reinitialized.

`aw team admin create NAME --byot --namespace DOMAIN` is the advanced wrapper when the
first workspace should create and join the team in one guided flow.

### Optional hosted projection/import

A hosted coordination provider may expose an import/sync operation for an
existing BYOT team. The operation must verify a fresh team-controller-signed
request, compare it with live AWID team/certificate facts, and project only
matching facts.

The current CLI compatibility helper is `aw id team import-request`. It creates
a provider-specific, short-lived signed import body. It never prints or uploads
controller private keys. That helper is not required for the standalone OSS
`aw workspace connect` path and its private provider endpoint is not part of the
aweb server protocol.

## Custodial identity in a BYOT team

A hosted operator may prepare a custodial member identity, but it has no BYOT
team authority until customer-signed facts match. The safe sequence is:

1. The operator prepares the custodial identity signing key and publishes its
   `did:key`/`did:aw` and requested address intent.
2. The customer team controller signs a certificate for that exact `did:key`.
3. The customer namespace controller authorizes any desired address binding.
4. The coordination host activates its projection only when the imported
   `did:aw`, current `did:key`, member name, address intent, team, certificate
   signature, and non-revocation state all match.

Before step 4, the pending identity cannot act as a member of the BYOT team.
The hosted operator holds only the explicitly custodial member key; it does not
acquire customer controller authority.

## Fail-closed requirements

A BYOT projection/import must fail closed when:

- the AWID team id is malformed or not found;
- the team or namespace is hosted-authority rather than customer-controlled;
- the signed timestamp is stale;
- the signer is not the current AWID team controller;
- the target projection is already bound to another AWID team;
- the AWID team is already owned by an incompatible projection;
- a pending custodial identity's `did:key`, `did:aw`, member name, team, or
  address intent differs from the signed facts;
- the certificate blob is unavailable, invalid, or revoked;
- the pending identity expired before activation.

Retries for the same signed facts must be idempotent. A conflict must not be
resolved by minting replacement facts with host-held authority.

## Lifecycle boundary

- Hosted authority may revoke certificates or change addresses only inside
  namespaces/teams it controls.
- BYOT membership changes require a customer team-controller signature.
- BYOT address changes require a customer namespace-controller signature.
- Removing an aweb runtime projection does not delete AWID identity history,
  addresses, teams, or certificates.
- Revoking a team certificate removes membership; it does not delete a global
  identity.
- Custodial key destruction is an operator custody action, not an AWID registry
  operation.

## Current and compatibility language

Current public language is **Fully Hosted** and **BYOT**. Older command and wire
surfaces may still say BYOD or BYOIDT. Treat those names as compatibility terms:

- BYOD referred to the customer-controlled DNS namespace;
- BYOIDT referred to the customer-controlled AWID team/import path;
- BYOT is the combined current authority model.

Likewise, current certificate storage uses `identity_scope=local|global`; legacy
`lifetime=ephemeral|persistent` is accepted only at compatibility boundaries.

## Review checklist

Before changing onboarding or membership flows, answer:

1. Who holds the identity signing key?
2. Who holds the namespace controller key?
3. Who holds the team controller key?
4. Where does coordination state live?
5. Which authority signs the address and membership facts?
6. Does a self-custodial terminal member keep its private key local?
7. Does a custodial BYOT member remain inactive until customer-signed facts
   match?
8. Can the same one-repository OSS flow work without Library or a private hosted
   application?
