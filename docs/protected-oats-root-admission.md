# Protected root endorsement and bounded agent admission

This implementation slice serves the three OATS operations from the unchanged
[human-assurance contract](human-assurance-contract.md). It adds no identity,
certificate, signature or generic signing format. The runtime table enables
`identity.root.endorse/default`, `team.agent.admit/default`, and the existing
`human-role.revoke/default`; the rest of the catalog remains a separate source
assignment. `team.admission-policy.read` is an authenticated read, never a signer
approval or admission grant.

## Authority and custody

The independent protected host owns the actual H and team-controller key files.
The public profile pins the registry, namespace authorities, request origin,
human origin/RP, complete authority/H scope and generation, and each signing
key. A profile reference supplies no authority on its own. Runtime registry
observations, held SQL authorizer/requester associations, current B3 credentials
and the applicable action/admission policy must agree. Workers receive neither
private keys nor the signer's database credentials. Ordinary member files
provide private-registry reads and cannot substitute a protected authority key.

[HOST.md](../server/src/aweb/protected_signing/HOST.md) describes matching-key
installation, once-only operator bootstrap, the existing enrollment page and
initial bounded policy provisioning. The optional controller-key manifest
permits the explicit H and team bindings to share one HTTP/B3 surface. It does
not select arbitrary keys or import a worker key. Each seed retains the same
real-file ownership, mode, symlink and worker-exclusion checks. Existing teams
and identity keys are preserved; automatic conversion or rotation is absent.

## Exact requests and results

Both signing operations use the existing `POST /protected-operations` envelope:
`{operation_id,operation,variant,scope,audience,subject,redirect_uri?}`. The client
persists its UUID and exact request before sending. The scope is the complete
profile binding, including its controlling human; bounded execution does not
invent `human:null`. The artifact consumer audience is the pinned registry;
covering request authentication still names the pinned request origin.

| Operation | Exact subject | Server-added request members beyond `requester`, `policy_ref`, `policy_version`, `artifact` | Result/effect |
| --- | --- | --- | --- |
| `identity.root.endorse/default` | `domain,root_id,root_key,teams,deployment_label` | `registry,expected_head,responsibility_statement,admission_policy` | Existing prefixed v1 ID-certificate signing bytes and padded standard-base64 signature. This is signing; aw separately registers with the root's proof and verifies read-back. |
| `team.agent.admit/default` | `team_id,root_id,root_key,child_id,child_key,member_alias,admission_policy_digest,expected_policy_version` | `request_id` (the operation UUID), `admission_policy_version` | Existing unprefixed canonical v1 membership-certificate bytes and padded standard-base64 signature, committed only after registry admission confirmation. |

Preparation retains B2's existing covered-request digest over the full frozen
request and action-policy reference/version. It answers exactly
`operation_id,handoff_id,digest,payload,expires_at`, with no URL. The optional
loopback callback is frozen too. An owned UUID with changed inputs conflicts
before new target observations; an exact retry returns its original artifact,
digest and expiry. Other requesters cannot recover that preparation. A missing
policy refuses before any pending operation, B2 link or approval exists.

For endorsement the existing eight-field ID certificate names H as its identity
parent and the registered root as an agent in H's namespace. The root needs no
address, team membership or Cloud login. The real B3 LOGIN is followed by a
separate UV approval of the exact B2 digest. The page checks the typed artifact,
policy digest and target, and displays the fixed responsibility statement and
finite admission bounds. Its selected H/issuer and full request remain covered.
A changed policy cannot consume the old approval into an effect. The service
retains that exact endorsement with its original effect/receipt/audit transaction.

aw obtains H's public supporting chain from the existing registry status read,
verifies it against the pinned namespace authority, registers the root's signed
certificate using the root's own subject proof, and verifies the exact current
head. A locally signed but unregistered root is not eligible for admission.
An ordinary `identity.agent.issue/human_parent` result is not this service's
retained root endorsement. Existing ancestry is not silently replaced.

Admission requires the explicitly named root's own current key, its current
valid agent ancestry under the selected H, and this service's retained
endorsement with that exact current certificate head. A descendant is not the
root. Registered child IDs bind their current keys and eligible agent kind;
local certificates keep local fields and acquire no invented did:aw/address.
Neither accepts admin/role/resource-right inputs or a protected private key as
a worker member key.

The default admission executes at
`POST /protected-operations/{id}/execute`, with truly empty bytes, covering label
`protected_operation_execute` and the original scope hash. It uses no browser,
LOGIN, UV decision or fake B2 approval. Request-side execution of a live-floor
operation returns `live_approval_required` without killing its pending approval.
Authorized execution outcomes use the closed HTTP-200 receipt; ingress,
authentication, scope/conflict and availability errors retain section 5 statuses.

## Policy read and bounds

`GET /protected-admission-policies?team_id=T` uses label
`protected_admission_policy_read`, T's namespace domain, and exactly
`{service_id,team_id}` as its signed scope. A named prospective requester proves
its current registered key under the operator's explicit binding. A random
registered key is insufficient. The response is exactly
`{service_id,team_id,mode,policy}`; no optional operational snapshot is emitted.
Known bound teams without an applicable policy answer null. Malformed stored
policy, unknown authority or unavailable evidence never means absence.

The policy has exactly `version,digest,teams,root_selector,subject_kinds,
member_role,bounds`. Teams and subject kinds are nonempty sorted distinct lists;
only local/registered agents and literal ordinary `member` are permitted.
The selector is `{kind:"service_endorsed_root",service_id:S}`. The bounds are
positive portable integers `max_active,rate_window_seconds,max_per_window`.
The digest is `sha256:` plus lowercase SHA-256 over
`aweb.admission-policy/1`, LF, and canonical policy JSON without `digest`.

The local `operator policy-init --file` admits one initial unsigned policy under
real current custody for every listed controller. An exact repeated file is
recovery; any replacement refuses. Later widening needs its own protected
policy-change operation. Reading, endorsement and admission never provision a
policy. The policy's value is configuration, not proof of controller authority.

Quota locks and rows are keyed by service, team and stable root ID. Root key
rotation does not reset the bucket. Active and uncertain reserved admissions
count toward the active bound; admitted timestamps enforce the finite rate
window. There is no implicit aggregate team ceiling or role escalation.

## Commit and recovery

Bounded execution atomically retains one certificate/signature, quota
reservation and signing audit before the registry mutation. A durable claim
admits at most one mutation attempt. The existing registry receiver verifies the
signed blob; fresh ordinary-member reads then confirm its immutable certificate
ID and complete registration fields. Only that confirmation makes the receipt
committed. A dropped response is reconciled by reads of the retained registration,
without new bytes, signature, certificate ID, quota charge or blind write replay.

An unresolved signed registration at its original expiry remains
`unknown/external_effect_unresolved`, not a claim that no effect occurred.
Definite policy/eligibility/limit/expiry refusals before signing become retained
refused receipts and local audit. Availability and authentication failures do
not become success or permanent policy absence. Original gesture, operation,
policy and registry-observation deadlines are checked after the last awaited
step; no poll, retry or lock wait renews them.

The component native selection is
`server/tests/test_protected_admission_native.py`. Collection is not execution;
its exact source/runtime receipts are supplied separately at handoff. The CLI
commands and release pin are owned by acxy.5, and browser/deployment acceptance
remains separately attributed. Backup restore fences, provider-move rotation,
hosted adaptation and existing-deployment migration are separate assignments.
