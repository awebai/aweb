# Disposable provisioning execution contract

This capability executes `provision-disposable` only through declared
`local-controller` authority in this release.

- `provision-durable` is refused because no production mint-and-handoff path
  exists (`aaaa.39`).
- hosted `provision-disposable` is refused before authority resolution or any
  create call. The current cleanup API requires a team owner/admin API key;
  putting that key in the same-UID hook would also give it to the model. A
  separate investigation owns finding scoped, non-ambient hosted cleanup
  authority.
- local-controller provisioning is explicitly an **accident and
  confused-deputy control**, not a boundary against an intentional same-UID
  model. The controller key and every local record are readable or replaceable
  by that UID.

The opaque 128-bit operation id is allocated by the decision layer and written
to the journal before the first remote call. It is also the explicit member
alias and the native `TeamInvite.operation_id`; an instance name, purpose, or
user alias is never used as operation identity.

## Cleanup authority and order

The local path proves these authorities before grant creation:

1. the reviewed external principal still selects the declared active team;
2. its certificate and signing key agree with the declared address and
   `did:aw`;
3. the machine-wide controller key still has the declared controller DID;
4. the authority carries both registry and aweb service routes.

Cleanup runs in this order and persists each completed step in the external
operation record:

1. remove every local grant carrying the operation id;
2. soft-delete the stale workspace and local identity using the persistent
   declared authority, not the disposable principal;
3. revoke the AWID certificate with the controller key;
4. remove the owned credential tree, retaining only the non-secret operation
   audit record.

Reversing steps 2 and 3 would strand self-authenticated workspace cleanup and is
forbidden.

## Artifact terminal-state matrix

| Artifact | Owning authority / observation | Successful terminal state |
|---|---|---|
| Local `TeamInvite` and bearer secret | machine user-state enumeration by exact operation id | **physically absent** |
| Provisioned signing/public/encryption material | external operation-specific identity home | **physically absent at the owned tree** |
| AWID team certificate | AWID registry list under exact team, then controller-authorized revoke | **revoked** (or authoritatively absent) |
| aweb workspace row | exact-team persistent authority calling workspace delete | **soft-deleted** |
| aweb local agent/identity row | local-workspace lifecycle cascade | **soft-deleted** |
| Task claims, presence, API grants, delivery state | aweb local-workspace lifecycle cascade | **soft-deleted/revoked by the same cascade** |
| Hosted organization membership | not created on the local-controller path | **physically absent / not applicable** |
| Target `workspace.yaml`, `teams.yaml`, certificate files, context | owned credential tree | **physically absent** |
| `provision-operation.json` | external target audit record | **intentionally retained audit** |
| External intent journal | capability scanner/operator | **intentionally retained audit** as `complete`, or **quarantined** |

“Physically absent” is bounded to the owned tree; it does not claim that a
same-UID process did not intentionally copy or hard-link material elsewhere.
A 404 is accepted as workspace absence only under the exact persistent team
authority. A 404 under an unrelated credential is not evidence.

## Crash/reconciliation matrix

| Independent boundary | Durable observation after process kill / host restart | Recovery |
|---|---|---|
| journal allocated, before any create | `allocated`, no target/grant | close without side effects |
| local grant file committed, response not observed | operation-tagged grant with bearer retained only in user state | encode that exact grant and continue |
| signing key committed | operation target key | reuse; never overwrite |
| registry certificate committed, response lost | alias + target DID resolve to active certificate | fetch and verify the existing certificate |
| certificate fetched/saved | target certificate and team state | continue membership finalization |
| aweb connect committed, response lost | operation target plus idempotent certificate connect | reconcile the same target and continue |
| resource tuple journaled, before hook output | `prepared` | never auto-adopt into another instance; retire/operator cleanup |
| binding bytes handed to OAS | `bound` | ordinary matching retire owns cleanup |
| grant removal committed | local enumeration has no matching usable grant | continue cleanup |
| workspace delete committed, response lost | exact-team delete returns authoritative absence | record soft deletion and continue |
| certificate revoke committed, response lost | registry lists the certificate revoked | continue without a second destructive assumption |
| credential removal interrupted | operation audit record plus remaining owned entries | remove remaining entries and re-read |
| scanner killed | journal state and per-operation target record | next trigger resumes the same operation |

Recovery never transfers a disposable identity to a differently named retry.
If the original spawn did not receive a binding, its reconciled identity is
cleaned; a later spawn allocates its own operation and principal.

## Scanner and quarantine contract

- Triggers: a later local provisioning spawn, every retire hook, and the
  operator-visible `aweb-identity-attach.mjs reconcile` command. After fixing
  the reported authority/service problem, an operator retries a quarantined
  operation with `reconcile --retry-quarantine <operation-id>`.
- Automatic stale threshold: five minutes. The explicit command ignores the
  threshold.
- Ownership: one `O_EXCL` lock per operation, with a five-minute stale-lock
  threshold. A scanner never cleans another scanner's live operation.
- Automatic states: stale `allocated`, `provisioning`, and `cleanup-pending`.
  `prepared` and `bound` are not inferred to mean launched and are not silently
  transferred to another spawn.
- A cleanup still failing on the third persisted attempt moves to visible
  `quarantined`. Quarantine is a remediable non-success and is never reported as
  completed cleanup.

The in-scope failure model is process kill and host restart. Power loss with
unflushed writes, disk loss, and Byzantine remote behavior are out of scope.
