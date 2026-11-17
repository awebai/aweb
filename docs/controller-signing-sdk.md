# Typed controller signing

The `awid.controller_signing` SDK supplies one interface for an organisation's
key holder. The holder retains custody, selects its keys from trusted state
and authorizes the caller under its own rules. A public descriptor, operation
name or working service credential grants no controller authority.

Clear distinction between signed-object operations and authenticated registry
requests. The existing registry remains unchanged; legacy under-bound auth
envelopes stay inside the holder's owned transport. No protected-effect
header, service key, registry lock, custody flag or new registry receipt.

`ControllerDescriptor(scope, domain, did_key, key_reference, generation,
team=None)` contains public information only. `key_reference` and `generation`
are holder-local selectors, never a registry compare-and-swap condition.

`parse_controller_request` accepts a closed object with `operation`, `domain`
and that operation's fields. Nested inputs are snapshotted. The signer receives
an immutable `ControllerSigningContext` containing that typed operation, the
selected descriptor/role and the SDK's timestamp and registry pin. It returns
`(did_key, raw_signature)`, synchronously or asynchronously. The holder checks
the operation and its own policy before signing `context.signing_bytes()`.
An RPC adapter must parse the typed operation again; it must not expose a
"sign these bytes" endpoint.

```python
request = parse_controller_request({
    "operation": "team_register",
    "domain": "example.com",
    "name": "engineering",
    "display_name": "Engineering",
    "team_did_key": team_descriptor.did_key,
    "visibility": "private",
})
result = await holder_registry.controller_request(
    request,
    controllers={"controller": namespace_descriptor},
    signer=holder.sign_controller_operation,
)
```

The client belongs inside the holder and uses its configured registry origin.
This path performs no registry discovery or redirect following. It derives
the method, path, query, body and signature roles, checks every returned
signature, submits the request itself and returns the registry's public result.
It never returns reusable authentication headers. The configured destination
is not a cryptographically signed audience in legacy formats that omit it.

Registry operations are `namespace_register`, `namespace_update`,
`namespace_delete`, `namespace_rotate`, `namespace_reset`, `team_register`,
`team_rotate`, `team_visibility`, `team_delete`, `certificate_register`,
`certificate_revoke`, `address_register`, `address_update`, `address_delete`,
`address_reassign`, `address_claim`, `id_revoke`, `server_publish`, `team_read`,
`certificate_list`, `member_read` and `revocations_read`.
The parser's closed field table is the executable interface. Certificate
registration takes the complete signed `certificate` blob and derives its
registration fields. Address assignment takes the checked target `did_aw`
and `current_did_key`; it does not silently select another identity.
Private reads return a single public route result, with bounded `limit` and
opaque `cursor`; the holder requests each further page through this same
interface, without exporting or reusing a header.

Continuity rotation takes `from_seq`, `previous_did_key`, `new_did_key` and
separate `controller`/`new_controller` descriptors. It uses the existing POST
rotation format. Recovery PUT is the separately named `namespace_reset`, never
a fallback. Delegated registration/reset specifies `parent_domain` and a
separate `parent` descriptor. Namespace authority cannot substitute for a team
key on team-controller operations.

`parse_controller_object` and `sign_controller_object` are separate from HTTP:
`team_certificate_issue`, `namespace_id_issue`, `team_server_sign`,
`address_claim_proof` and `address_replacement` produce only their existing
signed artifacts. ID issuance validates the explicit human/agent kind and
namespace parent. ID registration still requires the subject's separate
signature. An address replacement announcement is an application artifact,
not a registry route. Atomic address claims verify the independent identity
and supplied DID-log proofs before requesting the namespace signature; their
registry origin comes from the holder configuration.

Local malformed inputs, wrong roles and invalid signer answers raise
`ControllerSigningError` before submission. Registry refusals preserve
`RegistryError`'s status/code/detail for registry4xx refusals. Writes send once.
Any other failed write answer, including5xx/gateway errors, lost or unreadable
answers and a2xx arriving after the time budget, raises
`ControllerRequestUncertain`, with `operation` and
`request_digest`: the effect may have committed. Reconcile through current
reads and the holder's durable journal; do not blindly retry or report an
effect as unapplied. Cached clients invalidate affected entries before and
after attempted mutations, including ambiguous answers. This adds no reads
or holder calls to ordinary messaging or valid-certificate authentication.

Existing raw-key client APIs remain supported. `delete_namespace` and
`rotate_team_key` are additive conveniences using this seam. SDK coverage
does not expose recovery, rotation or revocation to every holder caller; the
holder retains its existing eligibility checks. Team rotation deployment still
depends on members' released certificate-fetch workflow.

Team creation obtains two signatures under the same closed `team_register`
operation: its covering request and the compact public creation act, selected
by the immutable context's `public_team_key_act` flag. The holder continues to
check that operation and audit each signature; it never signs arbitrary bytes.
Creation and team-rotation request timestamps accept UTC `Z` with up to six
fractional digits so successive acts can be ordered within one second. Other
signed-object timestamp formats remain unchanged; second-precision requests
remain accepted.
