# Retained protected effects

The operation definition owns its consumer delivery builder as well as its
artifact codec. The optional custody port is
`RetainedEffectCustody` in `aweb_naapp.runtime.protected_signer.retention`.
This port integrates explicitly protected consumers; custody without it keeps
its existing signed-result and delivery behavior.

`retain_authorized_effect` is synchronous and runs inside the existing local
signature transaction. It receives the normalized `CatalogOperation`, frozen
request and artifact, verified signature bytes, current authority observation
and original effect deadline. It must perform no network I/O or expose a proof.
A `None` result means an authoritatively unmarked legacy consumer; an unavailable
or protected binding cannot use that fallback. `RetainedEffect` contains the
same signed artifact, the exact final request and its authentication, service
attestation, artifact reference and a deadline no later than the supplied bound.
The engine persists these together in the new private `retained_effect` column
and `signed_result`; it does not yet publish a committed result.

The definition's `effect.delivery_plan` builds only its exact consumer:

- Team certificate registration includes the complete signed certificate and
  the existing registry body. Its covering-v2 request authentication is a
  separate controller signature over the exact route and body.
- Certificate removal reuses the artifact's original covering-v2 envelope and
  signature, including its original timestamp.
- An owner act uses its existing signed-artifact body at the existing app route.
- Human root endorsement has no team-controller delivery builder. The root
  retains possession of its own key and performs subject-proof registration.

Custody can authenticate a `DeliveryPlan` only with a signature over its exact
controller envelope. It then adds the detached service proof to the frozen
headers. Custody uses the shared protected-effect codec's artifact digest and
consumer encoding; the engine does not define another proof format.

After signature retention commits, the engine independently rechecks current
requester, authority, action policy, effect policy and any original live UV.
It commits a single delivery claim before calling `deliver_retained`. It checks
the original deadline again after that commit. The adapter sends only the
retained bytes and never generates a fresh timestamp, signature or request on
retry. An uncertain response keeps the signed result and claim.

`confirm_retained` is a read-only exact-consumer check returning
`EffectConfirmation(operation_id, artifact_sha256, valid_until)` or `None`.
A signed artifact, conflict response or matching certificate UUID alone is not
confirmation. The engine caps the observation at sixty seconds from the start
of that read and rechecks it after the final awaited authority check. Confirmed
application, any definition-owned capacity change, the public result and the
application audit commit atomically. Audit failure rolls back those local
changes; recovery reads the same owned operation without another mutation.
Historical confirmation may settle an already-applied effect after its original
execution deadline; it never authorizes a fresh release.

The safe public committed result is:

```json
{"v":2,"type":"aweb.protected-delivery","artifact":{"signing":"<padded standard base64>","signature":"<padded standard base64>"},"delivery":{"mode":"service_owned","state":"applied","reference":{"operation_id":"<uuid>","artifact_sha256":"<lowercase hex>"}}}
```

Clients verify the retained artifact and exact reference and do not perform a
local POST for this result. Pending or uncertain application keeps its existing
pending/unknown receipt state. Private headers, body and attestation are never
part of public receipts, approval views, mail or diagnostic representations.
The legacy public result remains exactly `signing` and `signature`.

The component native controls in `test_protected_retention_native.py` use real
local transactions and passkey approval with a remote transport double. They
exercise commit-before-release, lost-answer recovery, audit rollback, current
policy and original deadline fences. They do not establish acceptance by a real
protected verifier; that requires composition with the protected-effect custody
adapter and actual consumer.
