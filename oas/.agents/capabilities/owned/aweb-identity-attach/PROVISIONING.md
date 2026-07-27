# Disposable provisioning execution contract

> **EXPERIMENTAL / INTERNAL.** Run
> `oas aweb-identity status --soul <name> --json` before spawn. The native,
> active/trust-gated command asks `oas doctor --json` for the same soul-resolved
> settings that spawn consumes, then runs spawn's non-mutating identity and
> authority preflight. Its result is `ready`, `needs_setup` with one
> `next_action`, or `experimental` with no identity/instance/session creation.
> This verdict is advisory: OAS 0.18 hooks are not required and can still launch
> after hook failure. Only `aaaa.2` can provide fail-closed admission/rollback.
When the command runs in a bound instance, that same result includes a public
`identity` projection: attached/durable identities show their registered
address and DID; disposable local identities honestly show `address: null`,
their actionable team member name, and `did:key`. It also labels the identity
type and cleanup owner. Receipt fields, operations, and principal-store paths
are never projected. A disposable local identity has no global address by
design; the command never synthesizes one from its team and alias.

This capability executes `provision-disposable` only through declared
`local-controller` authority in this release.

- Durable resident provisioning is not in the exposed configurable-mode list
  and is refused because no production mint-and-handoff path exists (`aaaa.39`).
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
to the journal before the first remote call. The native
`TeamInvite.operation_id` carries it unchanged. The member alias is a separate,
deterministic lowercase 128-bit SHA-256 projection of the operation, because
aliases are normalized while operation identity is not. An instance name,
purpose, or user alias is never used as operation identity.

Local same-UID cleanup corroboration is also keyed by that operation id, never
by the locally chosen OAS instance name. The immutable first-writer record still
contains and checks the exact instance id and receipt, preserving accidental
cross-developer cleanup refusal even when two roots choose the same name.
Cleanup removes only that operation's corroboration record immediately before
persisting terminal `complete`; failed/pending cleanup retains it for retry, and
exact reconciliation releases records left beside older complete journals. The
bounded instance-key → operation-key cutover adopts a valid merged-main legacy
record on read and deletes its old name; this dual-read exists only for that
transition and is not a general versioned loader. Thus neither other operations
nor the local-name namespace are permanently allocated.

## Cleanup authority and order

The local path proves these authorities before grant creation:

1. the reviewed external principal still selects the declared active team;
2. its certificate and signing key agree with the declared address and
   `did:aw`;
3. the machine-wide controller key still has the declared controller DID;
4. the authority carries both registry and aweb service routes.

The cleanup graph therefore requires the declared external principal to remain
active until workspace/identity soft deletion, and the controller key to remain
available until certificate revocation. No universal retirement choke point
exists, so this is declarative rather than enforced against intentional
same-UID retirement; loss of either authority produces visible quarantine. A
controller key alone cannot prove or perform aweb workspace deletion.

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
| Task claims and reservations created during runtime | aweb PostgreSQL lifecycle cascade; proof seeds positive rows | **physically absent** |
| Workspace and agent-heartbeat presence created during runtime | aweb Redis reverse-coordinate hashes accumulate every global/team/repo/branch/alias key and remain durable until explicit cleanup; lifecycle clears both workspace and local-agent IDs; pre-coordinate entries use a complete fallback scan | **physically absent** |
| aweb API keys | local certificate connect creates none; AWID certificate above is the authorization grant | **not created** |
| Messages/delivery records | no model session or message is created by this no-launch provisioning proof; historical messages are audit, not member authorization | **not created / not applicable to the provision operation** |
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
| workspace SQL delete committed, Redis cleanup failed / response lost | server returns retryable failure; the surviving exact-team provisioning authority re-enters the tombstone; one Redis Lua commit removes every accumulated set/alias entry before deleting coordinates | record soft deletion only after the server confirms post-commit cleanup |
| certificate revoke committed, response lost | registry lists the certificate revoked | continue without a second destructive assumption |
| credential removal interrupted | operation audit record plus remaining owned entries | remove remaining entries and re-read |
| scanner killed | journal state and per-operation target record | next trigger resumes the same operation |

Recovery never transfers a disposable identity to a differently named retry.
If the original spawn did not receive a binding, its reconciled identity is
cleaned; a later spawn allocates its own operation and principal.

## Scanner and quarantine contract

- Triggers: a later local provisioning spawn, every retire hook, and the native
  operator command `oas aweb-identity reconcile --operation <operation-id>`.
  The operator surface always requires exactly one operation; only hook scanners
  enumerate stale scanner-owned states. The OAS dispatcher requires this
  capability to be active and executable-trusted; direct bin invocation is not
  the operator contract. After fixing the reported authority/service problem,
  an operator retries exactly one quarantined operation with
  `oas aweb-identity reconcile --retry-quarantine <operation-id>`.
- Automatic stale threshold: five minutes. The explicit command ignores the
  threshold only for scanner-owned states.
- Ownership: one SQLite lock row per operation. Acquisition and stale takeover
  run under `BEGIN IMMEDIATE`; takeover compare-and-swaps the observed random
  token and refuses only the same host-boot/process-birth identity, not a reused
  PID. No lock pathname is unlinked/recreated, so a concurrent scanner cannot
  replace or remove a fresh holder. macOS boot time is parsed numerically and
  process birth is read under forced UTC/C locale, so caller timezone cannot
  change ownership. Legacy lock-schema migration uses the same serialized
  transaction. Process-kill, prior-boot PID-reuse, cross-timezone live-holder,
  two-reclaimer, and 24-process concurrent migration controls prove the path.
- Automatic states: stale `allocated`, `provisioning`, and `cleanup-pending`.
  `prepared` and `bound` are not inferred to mean launched and are never globally
  selected. Only
  `oas aweb-identity reconcile --cleanup-unacknowledged <operation-id>` can clean
  one such identity, after the operator confirms that exact original instance is
  quiescent and its metadata did not retain the receipt. The journal can observe
  writing hook stdout, not OAS accepting it. A `bound` identity with retained
  metadata still requires its matching retire judgement.
- A malformed, unreadable, symlink, non-regular, or unknown-version intent first commits
  a visible no-cleanup-authority report, then moves the original entry unchanged
  to the external quarantine directory. If the process dies between those
  commits, the next scan completes the report-directed move, surfaces the
  quarantine warning, and continues other valid stale work.
- Exactly one attempt is persisted per real cleanup-command execution, including
  recovered provisioning and prepared/bound operator entry. A cleanup still
  failing on its third execution moves to visible `quarantined`. Quarantine is a
  remediable non-success and is never reported as completed cleanup.

## Real lifecycle proof

`scripts/e2e-oas-attached-principal-retire.sh` uses the repository's guarded,
no-tmux loopback Docker stack. In addition to attached-principal preservation,
it provisions two throwaway local identities through real OAS hooks, AWID, aweb,
PostgreSQL, and Redis. It seeds real task-claim/reservation rows and Redis
reverse cleanup coordinates/indices for both workspace and production agent-
heartbeat IDs, proves coordinates have no expiry, exercises one pre-coordinate
fallback, expires the shorter-lived primaries, asserts every
secondary remains as a positive control, asserts both
external journals terminal `complete`, and
snapshots each provisioned credential tree before scanning both instance homes
and the controlled repository by names, digests, symlink target, and device/inode
for copies or hardlinks. It retargets one instance-side receipt at the other operation,
proves the exact corroboration refusal leaves both real rows and certificates
active, then proves ordinary authorized retire and the native exact-operation
command produce AWID revocation, aweb agent/workspace soft deletion, local grant
absence, and credential-tree absence at their owning authorities. This is
explicitly local same-UID accident/confused-deputy evidence, not hostile-model
resistance. Removing the operation comparison in the target audit makes the
forged execution cleanup reach real deletion and turns the owning-authority
post-forgery active assertion red.

The in-scope failure model is process kill and host restart. Power loss with
unflushed writes, disk loss, and Byzantine remote behavior are out of scope.
