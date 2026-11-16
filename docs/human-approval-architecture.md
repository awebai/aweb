# Human approval and key custody

This document describes how the system establishes that a person approved an
act, how an identity is shown to belong to a person, and where an
organisation's keys are kept. It is the reference for the registry, the
approval service, the key holder, the servers and the applications.

It describes the target design, which is being built. Where the code does not
yet do what is written here, this document is the intent.

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
| Approval service | Enrols a person's key and obtains that person's approval of one exact act | No secrets. It cannot forge an approval |
| Key holder | Holds an organisation's keys and signs with them only by its rules | The organisation's controller key and team keys |
| Servers and applications | Do their work, and enforce the rules for what they own | Their own state |

The key holder is optional. An organisation may keep its keys with its owner;
it then has no enforcement on the use of those keys.

Nothing in the registry or on a server records whether an organisation uses a
key holder. The registry cannot know where a key lives. A key holder is an
organisation's own protection, not a public claim.

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

User verification is always required. A touch alone is not accepted.

## Rules

Each enforcer holds its own rules: which operations need a person, which
people may approve, and which grade of key is needed.

- Adding a requirement, or raising one, needs no approval.
- Lowering or removing the requirement on an operation needs an approval that
  satisfies that operation's current requirement.
- Some operations always need a person. That minimum is fixed and cannot be
  lowered.
- There is no unsigned override.
- A rule that cannot be read never means that no approval is needed.
- A rule that lets a team's people approve does not give those people roles in
  an application.

## Showing that an ID belongs to a person

### Creation

A person's ID is created together with the enrolment of a key. Both are one
act, bound to the same pending certificate, subject and key, and authorised by
the organisation. An organisation may require an existing person's approval
for each later person.

An ID created without enrolling a key carries no evidence. It is not refused. A
verifier reports it as without evidence.

### Grades

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

- Evidence belongs to the person's current key. A change of the person's key
  carries a receipt from an enrolled key that was current before it, so a
  verifier follows the changes from creation.
- A change of the person's key without a receipt ends the evidence. The
  verifier reports since when.
- Replacing or withdrawing an enrolled key changes the person's key. Statements
  and receipts tied to the earlier person's key stop being current, so a lost
  enrolled key cannot go on approving.
- Enrolling a key later never changes how an ID was created.
- Each agent issued or adopted under a person carries its own receipt. A
  verifier reports the evidence for each link of the chain. A link without a
  receipt is reported as such and is not refused.
- Evidence is seen only where a sender presents it. A bare ID cannot be looked
  up for its grade. An absent statement proves nothing.

### Lost keys

A person enrols at least one key, and is advised to enrol a second. A lost
enrolled key is replaced with another
person's approval, and the verifier reports the evidence from then on as
continued on that person's approval, not as an unbroken chain. A person who is
alone in an organisation and loses every key is
created again on the organisation's authority; this is recovery and is visible
as such. An account recovered by mail cannot produce an approval.

## The key holder

The key holder is a separate process. Keys are created inside it and leave it
only as a backup encrypted to a key the operator keeps offline. The key of a
parent domain is kept in a key holder as well. It offers a closed list of operations. Each is either routine, signed
without a person under a fixed rule, or requires a receipt.

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
- No weaker method is offered, and none for recovery.
- The approval page loads no third-party scripts.

A key is bound to the address of the approval service it was enrolled at.
Moving to an approval service at another address means enrolling again.

## Privacy

Published evidence contains only what the statement needs: no certificate that
identifies an individual device, nothing that links a person's separate IDs,
and no application receipts or resource names. The raw attestation of a key
stays private; its grade is published.
