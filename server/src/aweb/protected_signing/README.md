# Independent protected signing: first composition

`IndependentProtectedSigner` composes the shared
`aweb_naapp.runtime.protected_signer.ProtectedSigner` with current independent
authority, protected local controller custody, B3, B2 and transactional local
audit. The embedding process installs `aweb-naapp[runtime]` from the compatible
release. The ordinary aweb server imports none of this module by default.

This slice supports `human-role.revoke` only. It produces a signed owner-act
receipt; it does not deliver or apply that act at the target app. Shared HTTP
mounts, browser pages, bootstrap and the other catalog operations remain with
their shared implementations. No alternative parser, ceremony or receipt
store is provided here. In-process actor objects are trusted adapter ports,
never request JSON credentials.

```python
from aweb.protected_signing.composition import IndependentProtectedSigner
from aweb.protected_signing.custody import ProtectedControllerCustody
from aweb.protected_signing.registry import CustomerRegistry

# All values below come from explicit protected-host provisioning.
registry = CustomerRegistry(
    registry_origin=registry_origin,
    namespace_keys=namespace_controller_public_keys,
    member_signing_keys={team_id: member_agent_seed},
)
custody = ProtectedControllerCustody(
    service_id=context.service_id,
    team_id=context.authority_id,
    domain=context.authority_domain,
    key_file=protected_controller_key_file,
    worker_uids=worker_os_uids,
)
composition = IndependentProtectedSigner(
    db, context=context, registry=registry, custody=custody,
    human_origin=human_origin, request_origin=request_origin,
    delivery=existing_approval_and_passkey_delivery,
)
await composition.migrate()
# No authority binding or key is created when one is absent.
requester = await composition.requester(
    request, principal=registered_requester_id,
    operation="protected_operation_prepare",
)
prepared = await composition.signer.prepare(operation, requester=requester)
# Shared human mounts independently authenticate the exact H/holding and use
# signer.approval_options / execute with B3's exact-act UV assertion.
```

The provisioned `ProtectedKeyContext` selects one exact service, team-controller
authority, human/domain and association generation. Its authoritative row in
`protected_authorizer_bindings` binds the B3 subject/scope and policy version.
`protected_requester_bindings` grants prepare/receipt scope only. These rows
contain no private keys. This composition exposes no writer for them: changing
an authorizer set or policy must use its separately classified live approval;
missing operations refuse. Initial provisioning and existing-key import require
their separately approved operator procedure. Migration creates empty tables;
it is not enrollment or a production cutover.

The requester must prove the exact covering-v2 request and its registered
identity's current key. Bodies are bounded to 64 KiB before whole-body proof
verification. Tokens, local keys without a current registered mapping and
unprovisioned requester scope cannot authorize preparation. A restricted
requester cannot execute the live-floor operation. Receipt reads use their
separate signed GET proof and return `ReceiptReader`.

The human's own verified kind must be human. An agent whose verified ancestry
contains that human does not qualify. The same configured customer registry
resolves current identities, ID status and the team's current controller.
Namespace controller public keys are explicit protected-host trust references;
an unknown domain, changed pin, unavailable evidence or mismatched controller
refuses. There is no Cloud token, public-registry or controller-as-member
fallback. Private team reads use the configured ordinary member key. Updating
namespace pins is a separately authorized controller/operator transition.
After a legitimate namespace-controller rotation, update the protected host's
pin through that authorized transition before resuming protected operations.
Until then, verification fails closed against the old pin; it never learns
the replacement key from a worker request or an unverified status response.

The operation lock precedes binding locks and B3/B2 locks. Binding checks use
the original effect transaction and keep the rows held through commit. This
composition additionally limits its uncached remote observation to 60 seconds
from acquisition start, checking the same deadline after the final SQL wait.
Policy changes, authority retirement and generation changes refuse signing;
an authorized same-stable-scope receipt can survive a generation change.
The shared signer alone owns UV freshness, consumption and exact-result replay.
`protected_local_audit` is written in that same transaction without depending
on a remote Logs installation.

Custody requires a signer OS principal distinct from every declared worker;
UID 0 workers refuse. The key directory must belong to the signer with mode
0700; the regular key file must belong to it with mode 0400 or 0600. Symlink
keys/directories refuse. The seed uses the shared 64-hex-character format,
optionally newline-terminated. The adapter compares the concrete operation's
act, service, team, domain, audience and complete subject before supplying its
signature. It exposes no export or general signing method.

UID/mode checks reject known unsafe configurations. The operator must also
exclude worker ACL access, mounts, backups, debugging access and unlock
material. These checks are not a deployment inventory or proof that every
worker was declared. A process under the worker's own OS user is refused.

The real composition tests are
`server/tests/test_independent_protected_signer.py` and the file/crypto checks
are `server/tests/test_protected_controller_custody.py`. The reviewed shared
dependency and its AWID baseline must be present together. B3 migration 006
must compose with package .3's 005 in the release; this slice does not authorize
deployment or migration of an existing installation.
