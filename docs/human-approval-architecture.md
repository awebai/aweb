# Human approval and key custody

This document describes how the system establishes that a person approved an
act, how an identity is shown to belong to a person, and where an
organisation's keys are kept. It is the reference for the registry, the
approval service, the key holder, the servers and the applications.

The implemented core is the approval service for hardware keys and passkeys,
the Python and Go receipt and evidence verifiers, the key holder, and
`aw id human register|enroll|add`, `aw id proof` and `aw verify`. Approval is
optional and off by default. Lost-key replacement is not implemented.

[Human verification: planned target](#human-verification-planned-target),
decided 2026-11-16, describes the four pieces still to build. It is a plan,
not a claim that those pieces are running. Shipping without them is supported.

## The rule everything rests on

An organisation is a domain. The domain's controller key decides which teams
exist and what each team's key is. A member of a team is whoever holds a valid
certificate signed by that team's current key. A person or an agent is whoever
holds an ID certificate that chains to the domain. Anyone can check both with
DNS and the public registry, without an account.

Above the controller key is the domain's DNS record. Whoever controls the DNS
record controls the organisation. For an organisation registered under a parent
domain, the parent's controller key can also replace its controller.

## The parts

| Part | What it does | What it holds |
|---|---|---|
| Registry | Publishes organisations, teams, certificates and the tree from organisation to person to agents | Public records only |
| Approval service | Enrols a person's key and obtains that person's approval of one exact act | No person signing key. It cannot forge a hardware-key or passkey approval |
| Key holder | Holds an organisation's keys and signs with them only by its rules | The organisation's controller key and team keys |
| Servers and applications | Do their work, and enforce the rules for what they own | Their own state |

The key holder is optional. An organisation may keep its keys with its owner;
it then has no enforcement on the use of those keys.

Nothing in the registry or on a server records whether an organisation uses a
key holder. The registry cannot know where a key lives. A key holder is an
organisation's own protection, not a public claim.

## Creation, enrolment and approval

Creating a person's ID, enrolling an approval key and approving an act are
separate, optional operations. ID creation needs no approval service. The same
enrolment operation serves a new or an existing person; approving an act uses
the receipt flow below when the enforcer's rule requires it.

An agent's creator signs its parent certificate. Team membership is separate;
an invite admits agents answering to its specified human, without changing
parentage. [Invitations and adoption](id-certificates.md#6-invitations-adoption-and-migration)
defines creation and the first adoption under a person.

## Approving an act

1. Each server and application declares the operations it can require a person
   for. Each operation has a fixed, structured description. The requester does
   not write the text the person reads.
2. The enforcer, which is whoever owns the thing being changed, issues a
   request. It states the complete act, who is asking, the enforcer it is for,
   the resource and the rights, the state the enforcer expects, a one-time
   value chosen by the enforcer, and a deadline. It gives the request to the
   party that asked for the act.
3. That party, the requester, carries the request to the approval service and
   later brings the receipt back to the enforcer. The approval service accepts
   a request only from a requester that belongs to the person's own
   organisation: a current member of one of its teams, an identity in its
   tree, or its controller. An enforcer needs no standing with the approval
   service and never contacts it.
4. The person opens the approval service themselves. It shows who is asking
   and the exact act. The person approves with an enrolled key. A notice may
   tell a person that an approval is waiting; it carries no link and no detail
   of the act.
5. The enrolled key signs over a challenge that is the hash of the request,
   together with the address of the approval service. The receipt is the
   request, the key's signed data, and the approver's ID chain and binding
   (see "Evidence"). Without them an enforcer cannot find the enrolled key or
   its grade.
6. The enforcer checks the receipt before acting:
   - the challenge is the hash of this request, and the request is for this
     enforcer and this exact act;
   - the signed address is the approval service named in the approver's
     evidence, and user verification was performed;
   - it is inside the deadline, and the one-time value is the enforcer's own;
   - it is presented by the requester the request names, and that requester is
     allowed to ask under the enforcer's own rules;
   - the person is allowed to approve under the enforcer's rule;
   - the enrolled key is of at least the grade the rule demands;
   - the evidence is current: the person's key is the one the evidence names,
     and the person's team certificate is valid, from status reads no older
     than 60 seconds.

A receipt cannot be used at another enforcer. An act names its exact effect, so
presenting the same receipt twice changes nothing. The one-time value is a code
the enforcer computes from the act and the deadline with a secret of its own,
so the enforcer keeps no list of issued values. Where an act cannot be repeated
harmlessly, the enforcer records the value as used in the same transaction as
the effect.

User verification is required for hardware-key and passkey approvals. A touch
alone is not accepted. The planned email level has no user-verification ceremony
and a different, service-signed receipt.

## Current rules

Each enforcer currently enforces its own rules. The key holder's private
`human_issuance` setting defaults to `operator`: issuing a person needs no
approval service. Its `approved` mode requires an enrolled person's approval
through awsign. No operation inherently requires human verification merely
because it exists.

The planned track below replaces that setting with one configuration per
organisation, shared by all enforcers. Enforcement remains with the component
that owns the effect; the registry does not acquire an approval policy.

## Showing that an ID belongs to a person

### Creation

Enrolment accompanying ID creation is bound to the same pending certificate,
subject and key, and can establish creation evidence. An ID created without
enrolment is valid and reports "no evidence". Later enrolment enables approval
and reports "can approve since T, grade G"; it never adds a creation claim.
For an existing person, the person's current identity key authorises enrolment
and the issuer checks the registration before signing the binding.

### Current key grades

| Grade | Meaning |
|---|---|
| Certified hardware | The key proved, with a certificate chain checked against a pinned and dated list of certified models, that it is a hardware key that requires the person |
| Passkey with user verification | The person was verified by the device. Nothing is proved about the kind of key |

A weaker grade never satisfies a rule that asks for a stronger one. The
statement "a physical act accompanied the creation of this ID" is made only
for certified hardware.

### Evidence

Two signed statements travel beside the chain a sender presents. The issuer of
the person's ID signs both.

- The binding names the person's certificate and key, each enrolled key with
  its own grade, and the approval service they were enrolled at. A receipt
  carries the binding of the person who approved.
- The evidence records how the ID was created and each later change, and
  refers to the receipts that prove them.

Two keys are involved. The person's key is the identity key that the person's
certificate names. An enrolled key is a key the person approves with.

Today evidence is presented in an `aw id proof` file. Ordinary mail and chat
carry the ID chain without this evidence.

The following key-transition semantics are planned; they do not provide an
implemented lost-key replacement command today.

- Evidence belongs to the person's current key. A change of the person's key
  carries a receipt from an enrolled key that was current before it, so a
  verifier follows the changes from creation.
- A change of the person's key without a receipt ends the evidence. The
  verifier reports since when.
- Replacing or withdrawing an enrolled key changes the person's key. Statements
  and receipts tied to the earlier person's key stop being current, so a lost
  enrolled key cannot go on approving.
- Enrolling a key later never changes how an ID was created.
- Where an approval service is used, the link from a person to an agent they
  issue or adopt can carry a receipt; without one the link is reported as
  without a receipt and is not refused. Agents issued by agents carry none;
  they are attributed to the person through the chain. A verifier reports the
  evidence for each link of the chain.
- Evidence is seen only where a sender presents it. A bare ID cannot be looked
  up for its grade. An absent statement proves nothing.

### Lost keys

Replacing a lost enrolled key is not implemented; today a person who loses their only enrolled key is issued a new ID by the operator and enrols again, and the old ID is revoked. Enrol two keys.

A person who approves has at least one enrolled key and is advised to enrol a
second. In the planned recovery model, a lost enrolled key is replaced with another
person's approval, and the verifier reports the evidence from then on as
continued on that person's approval, not as an unbroken chain. A person who is
alone in an organisation and loses every key is
created again on the organisation's authority; this is recovery and is visible
as such. Mail recovery cannot produce a hardware-key or passkey approval. The
planned email level can produce only its distinct email approval.

## The key holder

The key holder is a separate process. Keys are created inside it and leave it
only as a backup encrypted to a key the operator keeps offline. The key of a
parent domain is kept in a key holder as well. It offers a closed list of operations. Each is either routine, signed
without a person under a fixed rule, or requires a receipt.

Issuing a person without an approval service is supported and yields an ID
without evidence. The issuing setting is `operator` by default: a private
operator command issues the ID. With awsign configured, an organisation may
select `approved`, requiring an enrolled person's approval. Agents cannot issue
people unattended in either mode. Any activated, currently valid person of the
organisation, enrolled at creation or later, may approve `human.add` in approved mode.
The shared gate will move this rule to `organisation.human.add`; it has not yet
replaced this setting.

The process that asks it to sign cannot read its memory or storage, cannot
sign directly, and cannot change its rules. Its database permissions and
backups are its own. Every signature is written to an append-only record of
what was signed, for whom, on whose approval, and when.

An organisation whose keys existed before moves in by importing them and then
rotating each to a key created inside: the controller keys first, with a
rotation signed by both the old key and the new one, which keeps everything
issued before valid; team keys afterwards, once members' clients can fetch a
new certificate.

Recovery from a lost key holder is, first, its encrypted backup. The last
resort is publishing a new controller key in the domain's DNS record, which
invalidates every ID issued under the organisation. The reserved `local`
namespace has no DNS record above it and depends on the backup alone.

## Membership and key changes

A server does not take a team's key on the registry's word. It holds the key it
admitted the team with, and moves to a different key only on the controller's
signed act for that change, checked against the controller the domain's DNS
record names, and newer than the act it last accepted. The registry stores and
serves these acts; it has no authority over them. The key a server holds in
this way is what "the team's current key" means on that server.

A server records, for each member, the team key under which it last accepted
that member's certificate. A member is refused when that key is not the team's
current key. The same comparison applies wherever a member is looked up,
including delivery between servers and resolving the participants of a
conversation.

Changing a team's key therefore removes every member until each holds a
certificate under the new key.

- The command that changes a key issues and records a new certificate for
  every member the owner keeps.
- A client that is refused for a certificate under a superseded key fetches
  the certificate now recorded for it, verifies it, installs it and continues.
- Credentials issued from the superseded certificate do not return. The member
  issues them again.

How quickly a change takes effect:

| What | Within |
|---|---|
| A server learns the new key | 60 seconds; up to 15 minutes if it cannot reach the registry |
| Chat connections and grants | 30 seconds after that |
| Room content | 60 seconds after that |
| Event and status streams | 5 minutes after that |

## What is and is not established

Established:

- A registered person approved this exact act, with a key of a stated grade,
  at an approval service whose address cannot be impersonated.
- An ID was created with a certified hardware key that requires the person.
- Each step from a person to an agent was approved in the same way, or is
  reported as not.

Not established:

- Who holds the key.
- That the person understood the act.
- That the approval service displayed the act it asked the key to sign. A
  hardware key has no display, so the approval service is trusted for this.
- That the person's computer did not alter what was displayed.
- That the approval service itself was not compromised. Its address cannot be
  impersonated; that does not protect against the real service being taken
  over.
- That the person was not persuaded to approve a genuine request.
- For a person whose key is held by a hosted service, that a message signed
  with the person's key was sent by the person. The service signs on the
  person's behalf.

## Keeping approvals resistant to phishing

- Only a requester from the person's own organisation can put a request in
  front of that person.
- Acts are fixed and structured.
- The person opens the approval service. A notice carries no link and no
  detail of the act.
- One receipt per act and per enforcer.
- No method weaker than the configured requirement is accepted; email will
  never satisfy a hardware-key or passkey requirement.
- The approval page loads no third-party scripts.

A key is bound to the address of the approval service it was enrolled at.
Moving to an approval service at another address means enrolling again.

## Privacy

Published evidence contains only what the statement needs: no certificate that
identifies an individual device, nothing that links a person's separate IDs,
and no application receipts or resource names. The raw attestation of a key
stays private; its grade is published.

## Human verification: planned target

Decided 2026-11-16. This section is the plan for the optional human
verification track, for both Cloud and self-hosted organisations. It supersedes
any earlier requirement that an operation must always need a person. Nothing
in this track is required before the rest of the product can ship.

### Optional, action by action

An organisation that has not enabled human verification never meets it: no
server demands approval, nothing contacts the approval service, and no command,
signup or deployment step mentions it. Each organisation chooses which actions
need a person and the verification level for each. When an action requires a
person, awsign is where that person approves it.

### Three levels

A weaker level never satisfies a stronger requirement. Level names are
provisional; their wire values must have one shared definition so a rename is
one change. These are the planned configuration levels, not a change to the
existing signed key-grade values.
The existing `certified_hardware` grade satisfies `hardware` and `passkey`,
`passkey_uv` satisfies `passkey`, and `email` corresponds to no key grade.

| Level | Wire value | What the person does | What it establishes |
|---|---|---|---|
| Hardware key | `hardware` | Touches a certified security key and gives its PIN or fingerprint | A person was physically present; the only level supporting the statement "a human did this" |
| Passkey | `passkey` | Unlocks a passkey on their device with a fingerprint, face or PIN | The device verified its user; nothing is proven about the device |
| Email | `email` | Confirms from a mailbox the organisation registered for them | Someone with access to that mailbox confirmed; not evidence of a human |

At `hardware` and `passkey`, the person's own enrolled key signs the approval;
the approval service cannot forge it. At `email`, there is no such key: the
approval service signs the receipt itself, and its operator can forge an email
approval. This limitation is stated wherever email is offered. An email receipt
is a distinct receipt kind and is never accepted for either stronger level.

The organisation gives the mailbox address privately to the approval service
when the person enrols at that level. It never appears in a receipt, the
registry or anything a verifier sees. Only `hardware` and `passkey` produce
identity evidence such as "created with a hardware key" or "can approve since
T". Email produces none.

### Declared actions

Each server or application declares the actions it can require a person for.
An action has a fixed name and structured description; the requester never
writes the text the person reads. Declaring an action does not enable a
requirement.

| Action | Declared by |
|---|---|
| `organisation.human.add` | Key holder; Cloud |
| `team.human.add` | Cloud; aweb server |
| `secrets.key.read_write` | Secrets application |
| `agent.root.authorize` | Key holder; Cloud |

The existing holder approval for adding a person moves onto the first action.
The other declarations do not claim those enforcers or their effects are
implemented today.

### One configuration per organisation

The default is empty: no action requires a person. For example, an organisation
may opt in with:

```yaml
human_approval:
  service: https://awsign.com
  require:
    organisation.human.add: hardware
    secrets.key.read_write: passkey
```

- Self-hosted: a section of the one deployment file, rendered to each
  component. The operator who edits that file is the authority; each component
  records changes in its audit record.
- Cloud: one per-organisation setting, edited on one dashboard page listing
  every available action and its level: none, email, passkey or hardware.
- Adding or raising a requirement needs no approval. On Cloud, lowering or
  removing one requires approval at that action's current level.
- A server that cannot read its configuration refuses the actions it declares.
  An unreadable configuration never means an empty one.
- Any current person of the organisation enrolled at the required level or
  above may approve. Naming particular approvers per action is a later
  extension of this same configuration.
- Permission to approve an action does not grant a role in the application.

There are no per-server switches, second configuration or additional levels.
The key holder's `human_issuance` setting is replaced by
`organisation.human.add` in this configuration.

### One shared gate

Every enforcer uses the gate in the approval-service library:

1. The server asks the gate about the action it is about to perform.
2. If the action is unconfigured, it proceeds. Nothing else happens.
3. If configured, it answers HTTP 428 with a request for that exact act. The
   requester, `aw` or the dashboard, carries the request to awsign and presents
   the receipt after the person approves.
4. The gate checks this act, this server, the deadline, the named requester,
   the entitled person, a level at least as strong as configured, and current
   evidence. Only then does the server proceed.

The server never contacts the approval service. Adding a gated action is a
declaration of its name and description and one call to this gate. Every
enforcer must prove that an unconfigured action proceeds with no approval
service reachable. This does not remove the action's ordinary authorisation.

### Responsibilities

| Responsibility | Self-hosted | Cloud |
|---|---|---|
| Holds organisation keys and countersigns a person's enrolment | Key holder | Cloud |
| Enforces actions | Key holder, aweb server, applications | Cloud, applications |
| Stores configuration | Deployment file | Per-organisation setting and dashboard |
| Approval service | awsign.com or the organisation's own instance | awsign.com |

Enrolment is one command for a new or existing person: `aw id human enroll`.
The dashboard offers the same operation for a hosted person.

### Four pieces, in order

These pieces are planned, not implemented by this document. Build one at a
time; each is complete only when its stated result works on a real stack with
product commands.

1. **Shared gate and configuration (aweb-adfa).** Move
   `organisation.human.add` onto the gate and add `secrets.key.read_write` as
   the second action. Done when an operator edits the deployment file, an
   agent's request for a read-write key receives an approval request, a person
   approves at awsign, and the request succeeds; and when removing the section
   lets the same request succeed with no approval service reachable. If only
   one piece is built before the track is parked, it is this one.
2. **Cloud enrolment and enforcement (aweb-adfb).** Cloud countersigns hosted
   people's enrolment, enforces declared actions with the same gate, and
   provides the configuration dashboard page. Done when a hosted person enrols
   with `aw id human enroll` and a hosted organisation gates one action from
   the dashboard.
3. **Email level (aweb-adfc).** Add private mailbox enrolment, the distinct
   service-signed email receipt and its verification in the gate.
4. **awsign.com hosted (aweb-adfd).** Host the approval service. This is
   production work and is decided separately.

Shipping before these pieces exist is supported. Existing identity, membership
and messaging operations remain usable without human verification configured.
