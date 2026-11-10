# secrets grants for inheritance-admitted members

Status: **proposal** (aweb-acwd.16). It is the resource-policy half of one
decision whose membership half is
[selective membership inheritance](selective-membership-inheritance.md)
(aweb-acwd.13). Juan sees both as one decision. This document commissions no
implementation and changes nothing in [secrets](secrets.md) until it is
accepted.

Goal 2: let unattended workers use a human-governed team's secrets without
a human action per worker and without giving workers that team's governance.

## The gap

Juan's direction, 2026-11-10: no cross-team grant. A human-controlled resource
team H owns the shared secrets, and workers join H through membership
inheritance. A worker that needs H's secrets holds its own local key B_H with
an inherited H certificate, alongside whatever it uses elsewhere
([local evidence](selective-membership-inheritance.md#local-evidence-and-the-protected-resource-flow)).

Inheritance gives B_H membership and nothing else: no principal grant, no role
and no owner authority. Today a secrets grant names one of three subjects
([§4.3](secrets.md#43-grants)): a principal, `secrets.owner`, or a
`secrets.role.<name>`. A grant to a principal does not name a child that does
not exist yet. A role reaches B_H only after an owner assigns it, and that
assignment is a widening change that needs the owner's passkey
([§6.3](secrets.md#63-widening-changes-need-owner-passkey-confirmation)). So
every spawned worker would need an owner act before it could use anything.

The fix is a grant subject that names a set of inherited members by the
signed membership path that admitted them. The owner authorizes the set once,
with a passkey. Each member admitted into that set afterwards is covered
without another owner act.

## The model

- **H's controller** decides who may join H and through which parents, by the
  inheritance policy (acwd.13). It remains the root of trust for who the
  owners are ([§14, T11](secrets.md#141-trust-boundaries);
  [owner acts](../owner-act.md#who-signs)). Under the recommendation below,
  its inheritance policy does not by itself extend secret use.
- **A secrets owner** decides which members may use which secrets, by grants.
  A grant to an inherited set is a widening change and needs the owner's
  passkey, like every grant.
- **The shared verifier** (`aweb_naapp`, B1) establishes membership and its
  currentness, including the inherited path. secrets reads the path only from
  that verified result, never from a request field.
- **Nothing passes from the parent.** A grant to A_H's principal, a role
  assigned to A_H, and A_H's owner or approver standing do not cover B_H. The
  only way B_H gets use is a grant whose subject covers it. Admission into H
  never assigns a secrets role.
- **Placement is not evidence.** One team can mix workers on a customer's
  server with workers on a person's own computer. A subject is defined by the
  verified membership path alone. No soul, host or placement claim widens or
  gates it.

## The subjects

For a request from an inherited member, the shared verifier returns, from
verified evidence:

- `team_id`;
- the inheritance `policy_id`, stable across the policy's revisions;
- the **root**: the eligible direct member that started the path, as a
  principal DID. That is its `member_did_aw` when its certificate carries one,
  and its `member_did_key` otherwise, keyed with `team_id` as in
  [§4.1](secrets.md#41-admission-of-a-member-request) step 3;
- the ordered **path** of parent principals, root first, in the same form;
- the leaf's **depth**: 1 for the root's direct child.

A direct member has no inherited output, so no inherited subject ever covers
it. The grant's team is the installation's team, from the installation
record, as for every grant.

Two inherited subjects are defined:

| Subject | Covers | Logical fields |
| --- | --- | --- |
| **Root-scoped** | Every current inherited member of the installation's team admitted under `policy_id` whose root is `root` and whose depth is at most `max_depth`. | `policy_id`, `root`, `max_depth` |
| **Policy-scoped** | Every current inherited member admitted under `policy_id`, through any root, whose depth is at most `max_depth`. | `policy_id`, `max_depth` |

Both subjects follow the same rules:

- **The root itself is never covered.** It is a direct member, and its own use
  needs its own grant.
- **Only the root can be named.** No subject names an intermediate parent.
  Intermediate parents are inherited members themselves, often short-lived,
  and naming one is a per-worker owner act again.
- **`max_depth` is the owner's bound.** It is an integer of at least 1.
  Raising the policy's depth admits deeper members into H. It does not extend
  a grant to them unless the grant's `max_depth` already reaches them.
- **The `policy_id` is exact.** A member admitted under any other policy of the
  team is not covered. A policy with a different ID is a separate controller
  authorization, and no existing grant follows it.
- **The other `grant/1` fields stay as they are**: `capability`,
  `operations`, `open_request`, `jobs` and `policy_digest`. Sensitive secrets
  still admit only named operations ([§8](secrets.md#8-operation-bounding)).

Exact field names and encodings are frozen with the grant vectors. The
subject joins the existing three; it replaces none of them.

### The choice for Juan

| Option | Result and cost |
| --- | --- |
| **Recommend: root-scoped only.** | The owner names each eligible root once, for example a deployment member A_H, and every worker A_H's line admits within `max_depth` is covered. Only the owner's passkey can extend use to another root's line. Cost: one owner act per root, never per worker. |
| Also offer policy-scoped. | One owner act covers every root's line. H's controller then extends secret use by making more members eligible (a named-parent eligibility grant, or all-direct-members mode, which covers every direct member it later admits), with no secrets owner passkey. That moves a widening change outside [§6.3](secrets.md#63-widening-changes-need-owner-passkey-confirmation). |

Under the recommendation, a grant covers another root's line only through an
owner's passkey-confirmed grant. That bounds the normal grant path, not the
trust base. The controller's existing powers are unchanged
([§14, T10 and T11](secrets.md#141-trust-boundaries)): it binds the owners, so
it can change who confirms grants. Re-certification alone does not take over a
root's line. Every request is signed by the member's own key, and for a global
root, B1b also requires the certificate's key to be the `did:aw`'s current
registry key ([§4.1](secrets.md#41-admission-of-a-member-request)). T10 is a
limit of the trust base, not an exemption from that check. Policy-scoped would
add a path on which ordinary eligibility changes extend secret use, with no
owner act at all. Where the owner and the controller are
the same human, the cost is small; the recommendation still does not depend on
that.

A root-scoped grant is the owner preauthorizing a root's future line. It
authorizes a line, not a count. Within `root` and
`max_depth`, how many workers are covered, and when, is set by the root, which
spawns them, and by the controller, through the policy's allowance and its
widening revisions. The rate buckets below bound their use; nothing in the
grant bounds their number.

## Admission order

[Decision 46](secrets.md#43-grants) tries grants to the principal, then grants
to its roles, each in `grant_id` order, and uses the first that admits.
Inherited subjects come last, root-scoped before policy-scoped, each in
`grant_id` order. Only the admitting grant's policy buckets are charged. No
match refuses with the existing `grant_missing`. A member that matches no
inherited grant cannot tell whether one exists for another root.

The dispatch fence ([§11.3](secrets.md#113-the-dispatch-fence)) re-reads the
admitting grant as today, and re-evaluates its inherited match against the
verified path retained with the intent. A revoked or narrowed grant therefore
stops admitted, not-yet-sent uses at once, as removing a role member does
([§12](secrets.md#12-containment-from-day-one)).

**The membership deadline is checked after the last wait.** Admission retains
the shared verifier's original membership dependency deadline: the earliest
`fresh_until` across the verified evidence, which a cache hit never refreshes
([acwd.13 currentness](selective-membership-inheritance.md#withdrawal-reissue-and-currentness)).
The verifier's proof keeps that deadline on a process-local monotonic clock
(`naapp-lib/src/aweb_naapp/runtime/team_auth.py`), which must not be persisted
or read by another worker. So the admission transaction samples the database's
`clock_timestamp()` first, adds the smallest remaining original budget,
rounded down, and persists that absolute deadline; a non-positive budget
refuses. It is never rebased after a wait; adding an earlier budget to a later timestamp would extend authority.
The final fence transaction compares it with the same database clock, read
after its last effect-lock wait. That transaction covers approval consumption, credential
opening and release, and the dispatch or assignment commit. The rule applies to
direct and inherited members alike and makes no network call, so §11.3 gains
"membership evidence deadline" in its list of re-checks. An expired deadline
refuses with the shared `503 current_membership_unavailable`, a fixed
unavailable refusal and not a claim that membership was withdrawn. The refusal
happens inside the transaction, which rolls back: no approval is consumed, no
credential is released, no assignment is persisted and no bytes are sent. The
requester recovers by a fresh authenticated re-submission, through the normal
grant, approval and idempotency checks. Dequeueing, cache hits, retries and
lock acquisition never restart the old window. Grant revocation remains an
independent stop.

The consequences:

- **Runner jobs.** A job admitted while no runner is connected, and claimed
  after its deadline, refuses at the claim fence
  ([§9.3](secrets.md#93-transport)) with `current_membership_unavailable`.
  The refusal is final for that dispatch, and only re-submission recovers it.
  Because a cache hit keeps the original expiry, the deadline can fall under
  60 seconds after admission. That is the availability cost: a queued job
  needs a connected runner, or a re-submit.
- **Brokered requests** are admitted and dispatched in one flow, so in practice
  they are unaffected.
- **Exposure to a withdrawn path** is the verifier's observation window, with
  no added queue delay.
- Whether a re-submission reuses its `request_id` and the unconsumed approval
  is fixed with the vectors, under the idempotency rules of
  [§11.2](secrets.md#112-idempotency).

## Currentness, withdrawal and policy revisions

Membership currentness is decided by the shared verifier before any grant is
read. A grant to an inherited subject never makes a withdrawn path usable.

| Event | Effect on use |
| --- | --- |
| Controller revokes the root's membership, or a parent on the path | The verifier denies every member depending on it. No grant is read. Members of other roots are unaffected. |
| Policy withdrawn or expired | Every dependant is denied at membership. |
| Narrowing revision (same `policy_id`), including any edit that reduces a limit or removes eligibility | Per acwd.13, dependants are withdrawn and denied at membership. A member re-admitted under the revision matches the same grant with no owner act. |
| Widening revision (same `policy_id`): raising allowance or rate, or extending expiry ([acwd.13 continuity](selective-membership-inheritance.md#policy-continuity)) | Dependants keep membership, and the grant keeps covering them. Members admitted afterwards are covered only within the grant's `root` and `max_depth`. Eligibility-mode changes, added eligibility and increased depth are classified in acwd.13's wire freeze; until then they refuse publication. |
| Policy replaced by another `policy_id` | Existing grants cover nothing under it. The owner grants again, if wanted. |
| Owner revokes the grant | Admission refuses at once, the fence refuses `grant_revoked`, and derived secrets issued under the grant are disabled ([§8.4](secrets.md#84-derived-secret-creation-and-use)), as for every grant. Any change to the grant is a `grant.changed`, which is widening and needs the passkey. |
| Global root rotates its key and is re-admitted under the same `member_did_aw` | The root principal is unchanged, so a root-scoped grant still names it. Old child paths do not transfer; re-admitted children match again. |
| Local root replaces its key | Another principal. The grant does not cover the replacement root's line until the owner grants it. |
| Local child's key replaced | Another principal with a fresh certificate. If it is admitted under the same root, policy and depth, it is covered. |
| Global child re-admitted under the same `member_did_aw` with another key | The same principal, with fresh membership evidence. Old paths do not transfer. Re-admitted under the same root, policy and depth, it is covered. |

An approved `per_use` request is consumed only when the same request is
re-submitted ([§10.3](secrets.md#103-flow)), and that re-submission is
verified as a member request again. A withdrawn path therefore cannot consume
an approval granted before the withdrawal.

## Derived secrets

A `store_as_secret` result ([§8.4](secrets.md#84-derived-secret-creation-and-use))
creates a child secret with a grant from pinned template terms. When the
requester is an inherited member, that grant names the requester's own
principal, never the inherited subject that admitted it. A credential one
worker created is therefore not usable by the rest of its line unless an owner
grants it. Today `store_as_secret` is refused (`store_as_secret_unavailable`),
so the rule takes effect when derived-secret creation is enabled.

## Approvals and four eyes

Approval policy is unchanged. For an inherited requester,
`distinct_approver: required` excludes an approver linked to the requester
**or to any principal on its path**. The root and the intermediate parents
are the side that spawned the requester, so letting them approve would defeat
the four-eyes rule. The exclusion uses the verified path, not names or
placement.

## Rate scopes and custody limits

The existing rate scopes ([§4.4](secrets.md#44-policy)) keep their names and
their keying by installation, policy digest and secret. For an inherited
admission, the principal part of the key is the member's **line**, so spawning
neither resets nor multiplies a budget:

- **`principal_secret`** counts per line: `(team_id, policy_id, root)`, from
  the verified output, never per leaf. Every worker in one root's line shares
  one bucket, however many are spawned or re-admitted. The line key is
  distinct from the root's own principal key, so the root's own use under its
  own grant is counted separately. One busy worker can spend the line's
  budget; per-worker fairness inside a line is not provided.
- **`secret`** counts across every principal and line, as today.
- **acwd.13's issuance allowance** bounds how many members a policy admits.
  It counts admissions, not use, and does not reset.

A direct member's buckets are unchanged.

The custody limits:

- **A grant gives use, never the value.** Brokered use, sensitivity, named
  operations, destinations and approval rules are unchanged
  ([§14.2](secrets.md#142-the-defensible-claim)).
- **Use follows the key.** Whoever holds a covered leaf's key, on a server or a
  laptop, can use what the grant allows until the path is withdrawn or the
  grant revoked.
- **No predicate can distinguish placement.** Attestation predicates prove
  only positive custodial facts and never self-custody
  ([§4.6](secrets.md#46-custody-and-principal-attestation-contract)). An owner
  can still require them.
- **A compromised eligible root** can admit attacker-held keys up to the
  policy's allowance. Together they share the line's bucket, so more keys do
  not buy more use. Two containment acts each cut the whole line, with a
  difference. The owner revoking the grant also stops admitted intents at the
  fence. The controller revoking the root's membership stops admissions, but
  intents already admitted still dispatch unless the grant is revoked too.
- **Several keys under one worker UID** remain one compromise boundary, as
  acwd.13 states.

## Worked flow and refusals

Setup is all owner and controller acts, done once:

1. H's controller publishes an inheritance policy P, with A_H as an eligible
   root (acwd.13).
2. A secrets owner of H's installation grants `use` of secret S to the
   root-scoped subject `{policy_id: P, root: A_H, max_depth: 2}`, and confirms
   it with a passkey.

Then, for each worker, with no human act:

3. A spawns B and admits B_H into H under P (acwd.13). B_H is a local
   `did:key`; it can run on the customer's server or on a person's own
   computer.
4. B_H signs a request for S. The verifier returns team H, policy P, root A_H
   and depth 1. The grant matches, and use proceeds under its policy.

| Case | Result |
| --- | --- |
| B_H, admitted under P through A_H, depth 1 | Allowed under the grant's policy. |
| B_H's child, depth 2 | Allowed (`max_depth: 2`). |
| Depth 3, after H's controller raises the policy depth | Membership valid; `grant_missing`. |
| B_D presents its deployment-team certificate to H's installation | Refused by team-auth before any grant is read (wrong team). |
| B admitted under P through another root A2_H | `grant_missing` under the recommendation. |
| B admitted under another policy P2 | `grant_missing`. |
| A_H uses S | Covered only by its own principal or role grant; the inherited subject never covers the root. |
| B_H relies on A_H's principal grant, role or owner standing | `grant_missing`; nothing transfers. |
| Controller revokes A_H's membership | B_H and its children are denied at membership. |
| Narrowing revision of P | Dependants are denied at membership; re-admitted members are allowed again with no owner act. |
| Widening revision of P | B_H stays allowed with no owner act. |
| Owner revokes the grant | `grant_missing` at admission; `grant_revoked` at the fence for admitted intents. |
| Approver linked to A_H, `distinct_approver: required`, B_H requests | A_H's approver is excluded. |
| Ten workers of A_H's line request S together | They share one `principal_secret` bucket; spawning more does not raise it. |
| A request's membership deadline passes during a proven final-fence lock wait | `503 current_membership_unavailable` in that transaction: no approval consumed, no credential released, nothing sent. |
| The deadline passes while the admission transaction persists it | Refused: no approval consumed, no credential released, nothing sent. |
| Another worker claims a queued job after the requester's deadline | `current_membership_unavailable`: no approval consumed, no credential released, no assignment row; re-submission recovers. |
| Membership evidence unavailable | The verifier's 503; no grant is read and no fallback applies. |

## Work this creates, after acceptance

- **acwd.13 verifier output**: the inherited fields above, from verified
  evidence only, retained with the intent for the fence.
- **secrets**: the `grant/1` subject, the admission order, the fence
  re-evaluation, the membership deadline in the final fence for every member,
  the line-keyed `principal_secret` bucket, the
  `distinct_approver` path exclusion and the console
  rendering. The console shows the policy, the root, `max_depth` and the
  policy's current terms as read at draft time, labelled as such.
  [§4.3](secrets.md#43-grants), [§4.4](secrets.md#44-policy),
  [§12](secrets.md#12-containment-from-day-one) and
  [§16](secrets.md#16-tests) change with it.
- **Vectors**: the grant subject encoding, and the refusals above for both
  local and global roots. That includes expiry during a proven effect-lock
  wait, expiry while the deadline is persisted, and a queued job claimed by
  another worker after the deadline. Each asserts that no approval was
  consumed, no credential was released and nothing was sent.

The hook catalog's `post-secret-use-hook` refusal codes gain
`current_membership_unavailable`, through a reviewed catalog revision. No payload field changes:
`grant.created`, `grant.changed` and `grant.revoked` keep their fields, and a
`post-secret-use-hook` event keeps its fields, with its admitting `grant_id`
identifying the subject.
