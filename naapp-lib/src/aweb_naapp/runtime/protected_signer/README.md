# Protected signer: first executable slice

Import the shared service and trusted adapter ports from
`aweb_naapp.runtime.protected_signer`:

```python
from aweb_naapp.runtime.protected_signer import (
    ProtectedSigner, ProtectedKeyContext, RevokeHumanRole,
    RestrictedRequester, AdmittedHuman, ReceiptReader,
    AuthorityProvider, CurrentAuthority, ControllerCustody,
)

signer = ProtectedSigner(
    db, passkeys=passkeys, policies=policies, delivery=delivery,
    audit=local_transactional_audit, authority=current_authority,
    custody=protected_local_controller,
)
await signer.migrate()
prepared = await signer.prepare(operation, requester=requester)
options = await signer.approval_options(prepared.operation_id, human=human)
# The shared browser performs navigator.credentials.get(options).
receipt = await signer.execute(prepared.operation_id, assertion, human=human)
receipt = await signer.receipt(prepared.operation_id, reader=requester_reader)
```

This slice accepts only `RevokeHumanRole`, the `human-role.revoke` owner act.
The operation ID is a canonical UUID selected before prepare. Repeating the
same ID and intent returns the frozen preparation; a changed intent refuses.
The signature and its exact signing bytes are base64 in the committed result.
It does not deliver or apply the act remotely. HTTP/page mounts and the other
catalog operations are subsequent slices; embeddings must refuse those until
the shared implementation supports them. `handoff_id` is an association ID,
not a URL or a currently mounted page.

`ProtectedKeyContext` names the service, authority kind/ID/domain, selected
human ID/domain, and current generation. It is B3's explicit preinstallation
proof context; no app installation is invented. Existing app proof shapes and
commitments remain unchanged. The B3 proof resolver returns this context for
the provisioned authorizer's scope. Provisioning and custody import are operator
operations outside this request API; these calls never bootstrap an authorizer
or create/rotate/import a controller key on a miss.

The server builds the three actor types after authenticating its actual caller.
They are not JSON evidence or authorization by themselves. `.4` owns the
covering-v2 possession parser; the service has no competing parser. The
`AuthorityProvider.observe(context, purpose=...)` adapter obtains remote evidence
before locks. Its `CurrentAuthority.prepare(tx, actor)` holds current
requester/human association, authorizer, key generation and policy authority;
`check(tx, actor)` is SQL-only and uses those existing holds, with no later
lock acquisition. `require_fresh()` checks original evidence deadlines
synchronously. Missing or unavailable authority refuses, never defaults.
All writers/readers touching an operation take its operation lock before their
authority/B3 locks; an adapter must not acquire the operation lock from a later
callback. For an app adapter, preserve F6/retirement/roles/B3/S4 ordering.

Prepare and receipt authenticate restricted requester scope; cookies and tokens
cannot approve an act. A human receipt read may pass `AdmittedHuman`, independently
checked by the authority adapter for that exact current human/authority scope.
The operation ID alone reveals no result. Receipt lookup can survive generation
changes when the adapter still authorizes the same stable scope. It never
re-signs or renews the nonce.

B3 verifies actual UV and retains its original challenge/context/proof. B2
freezes the request and policy and consumes its approval exactly once in the
effect transaction. The final deadline is the earlier of original challenge
issuance + 300 seconds, original challenge expiry and operation expiry; the
owner act itself has a separate maximum of 600 seconds. The final authority
check is the last await, followed by synchronous authority/UV deadline checks.
A wait crossing a deadline rolls back consume, outcome, receipt and audit.
The local audit sink writes on the supplied transaction. No remote Logs service
is needed, and no audit delivery happens under these locks.

`ControllerCustody.sign_owner_act(operation, fields)` is a synchronous, local,
deterministic adapter for an existing protected controller key. It has no
export or general signing route, performs no network call and discloses no
artifact before SQL commit. External custody needs a separate specified
idempotent protocol; it cannot claim this transaction guarantee. The signed
bytes are built and verified by the existing owner-act implementation.

Run `tests/runtime/test_protected_signer.py` against private PostgreSQL for the
focused positive, wrong-authority/payload, original-deadline, concurrent execute
and audit rollback/retry cases. B3 migration 006 follows the holder stack's 004;
coordinate the credential-change branch's 005 before the combined release.
No deployment, key import or production migration is authorized by this seam.
