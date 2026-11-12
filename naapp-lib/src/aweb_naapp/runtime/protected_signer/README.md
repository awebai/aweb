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
It does not deliver or apply the act remotely. Request-origin and human-origin
JSON mounts are below; console supplies the existing page's governance mode.
Other catalog operations remain unsupported. `handoff_id` is an association ID,
not a URL or authority.

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


## Shared request-origin HTTP mount

```python
from aweb_naapp.runtime.protected_signer import ProtectedOperationsHTTP

http = ProtectedOperationsHTTP(
    signer, request_origin=configured_request_origin,
    requester=authenticate_prepare, reader=authenticate_receipt,
    limiter=shared_login_limiter,
)
# Either include http.api_router() on the configured request-origin server,
# or pass protected_operations=http into the one ConsoleHandoffs factory.
```

`authenticate_prepare(request, operation)` returns an authenticated
`RestrictedRequester` for the exact proposed context.
`authenticate_receipt(request, operation_id)` returns a `ReceiptReader` for the
original authorized scope. Before authenticating, it may call
`await signer.lookup_context(operation_id)` to obtain the exact retained
`ProtectedKeyContext` (or None). This is internal routing metadata only: no
result/credential/link, no current authority, and no actor-free HTTP endpoint.
It must never reconstruct scope from an account default. After authentication,
`receipt()` reads again and authorizes under operation/authority locks.
The callback resolves trusted current profile/scope,
uses `.4`'s `awid.protected_request.verify_protected_request` for possession
proofs (or the explicitly supported team-auth/hosted restricted lane), and
checks current key/association. It never derives authority merely from the
operation ID, a cookie or JSON scope. The service independently enforces
current authority and original requester binding after authentication.
Do not mount it on an unconfigured origin; forwarded headers do not select it.
The factory rejects a protected mount with a different database or B3 instance.
A standalone composition applies `apply_console_migrations(db)` before serving
the existing LoginLimiter; no installation or app holding is fabricated.
Protected requests always use bucket `protected.operations.client`, independent
of `console.login.client` even when they share a limiter and client identity.
Polling cannot spend the human login budget.

POST `/protected-operations` takes the operation's `intent()` fields and an
optional `redirect_uri`. The callback is validated by the existing literal
loopback parser and frozen in the covered request. The response is exactly
`operation_id`, `handoff_id`, `digest`, `payload`, `expires_at`, with no URL.
For HTTP, `payload` is the existing B2 covered object
`{"policy":{"ref":POLICY_REF,"version":VERSION},"request":REQUEST}`;
the digest is SHA-256 of `aweb.approval-request/1` plus LF plus that canonical
object. This wraps the library's `PreparedOperation.payload` (REQUEST).
REQUEST retains the input fields unchanged. Its only server additions are
`requester`, `policy_ref`, `policy_version`, `artifact`; the owner-act nonce,
issued/expiry, team key and signed subject live inside `artifact`.
Clients must verify both this digest and their exact intent before displaying
the comparison link.

GET `/protected-operations/{operation_id}` returns HTTP 200 with a closed
receipt: `pending` has `reason` and `expires_at`; `committed` has `result`;
`refused` and `unknown` have `code`. Authentication errors are 401
`requester_invalid`, scope denial 403 `scope_refused`, absent record 404
`operation_not_found`, changed intent 409 `operation_conflict`, and availability
503 `receipt_unavailable`, all with fixed `detail` and no private exception
text. Every response is no-store. Unknown/duplicate input fields, noninteger
numbers and malformed callbacks refuse. Cookies and console session headers
cannot substitute for a restricted request proof.

The request and human JSON mounts are shared here; console's existing page mode
is composed separately. Until that page and the trusted sessions are mounted,
a returned association is not a working browser ceremony. No request-origin
execute route permits this live-floor operation.


## Human-origin governance mode

`ProtectedOperationsHTTP(..., human_sessions=sessions,
human_csrf_key="configured-tab-storage-key")` adds `human_router()` with the
frozen `/handoff/{id}/governance` state, `/options` and `/execute` JSON mounts.
`ConsoleHandoffs(..., protected_operations=mount).human_router()` includes them.
The sessions must use the exact signer's database and B3 instance. The embedding
admits its exact provisioned protected B3 scope through `sessions.scopes`; it
mounts the existing `console_login_router` once at `/login/options` and `/login`
on the human origin. A fresh tab performs that real LOGIN in place, retaining
the handoff, then performs the separate B3 approval UV. Account/CLI tokens and
key-bound CLI sessions cannot stand in for the browser LOGIN.

Console owns the single HTML page and its existing JS module. It calls
`await mount.page_context(handoff_id)` only after no app handoff matches; this
returns only `{b3_scope, csrf_key}` or `None`, before login. That routing read
never exposes a payload or grants admission. The configured CSRF key names the
actual console login token in tab storage; the page never guesses/scans keys.
This module mounts no competing `GET /handoff/{id}` and no second page.

The authenticated state returns `{mode:"governance", operation_id, handoff_id,
digest, payload, expires_at, state}` plus the receipt's `reason`/`code`/`result`
where applicable. `payload` is the exact covered `{policy,request}` object also
returned to aw. Options accepts `{}` and returns existing B3 required-UV JSON.
Execute accepts only `{assertion:...}` and returns the ordinary receipt JSON.
Only committed execute adds the frozen loopback `redirect_uri` with `handoff_id`
as its sole query member. It carries no code or authority; aw still authenticates
and reads its exact immutable receipt. With no frozen callback it is omitted.

Human routes require the pinned human Host; POST also requires its exact Origin,
JSON and the real console session's `X-CSRF-Token`. The actor is built from the
stored context and that authenticated session, then rechecked against current
provisioned authority. It never comes from browser JSON. The original session
is held after the ordered B3 preparation and checked with the same SQL effect
transaction. Its original deadline and the retained approval challenge deadlines
are sampled synchronously after the last authority await. No receipt/audit work
follows those samples. Existing library calls may omit a session; this HTTP
mount always supplies the authenticated frame.
