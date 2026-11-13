# Protected agent membership removal

`team.agent.remove/default` is the frozen catalog's bounded narrowing operation
(`human-assurance-contract.md:257-261`). It uses the same protected operation
UUID, exact-body prepare, B2 digest, execute and receipt path as unattended
admission. It removes one agent certificate, not an identity, human holding or
resource grant. Controller keys stay in the protected host's custody.

The subject has exactly these members:

```json
{
  "team_id": "engineering:example.org",
  "root_id_or_self": "self",
  "member_id": "<member did:aw, or local did:key>",
  "certificate_id": "<lowercase UUID>",
  "expected_membership": {
    "member_did_key": "<did:key>",
    "member_did_aw": null,
    "member_address": null,
    "alias": "worker",
    "identity_scope": "local"
  }
}
```

The CLI can project this snapshot from the admitted certificate without a
registry read. Null values are present, not omitted. The server checks the
snapshot against a fresh record in its pinned customer registry, and checks
the current identity kind for a registered subject. Human and protected-key
targets refuse. A local subject has neither a registered ID nor an address.

A root uses its usual covering-v2 requester proof and names its own stable ID
in `root_id_or_self`. Its active requester grant, current service endorsement,
current registered root key, policy and named team must all match. It may
remove only certificates in its own retained admission bucket. An untracked
legacy certificate or another deployment's bucket does not acquire this root's
authority. Root key rotation does not reset the stable-ID bucket.

## Self request proof

The member uses the existing team-auth v2 envelope and its own private member
key. It supplies `Authorization: DIDKey <did:key> <signature>`,
`X-AWEB-Timestamp`, `X-AWEB-Signed-Payload`, and
`X-AWID-Team-Certificate`. There is no `X-AWEB-DID-AW` selection header on
this route. A cookie or mixed root/member credentials refuse.

The canonical signed payload has exactly ten members:
`v`, `aud`, `method`, `path`, `team_id`, `timestamp`, `body_sha256`,
`operation`, `service_id`, `scope_sha256`.
`v` is integer 2; `aud` is the profile's request origin; `path` covers the
actual raw path and query. The body hash covers the exact bytes. The scope hash
is SHA-256 of the canonical full protected scope, including its H association
and generation. The labels and bodies are:

| Request | Label | Body |
| --- | --- | --- |
| POST `/protected-operations` | `protected_operation_prepare` | Exact prepared request |
| POST `/protected-operations/{UUID}/execute` | `protected_operation_execute` | Empty |
| GET `/protected-operations/{UUID}` | `protected_operation_receipt` | Empty |

The public-only encoding example is
`server/tests/fixtures/protected-self-remove-request.json`. Its fixed timestamp
is illustrative; it supplies no current registry evidence or private key.

Current controller, real certificate signature and exact fresh registration
must match before the in-process self admission is constructed. That admission
binds only this UUID, member key, certificate, full intent and original
observation deadline. It skips no current H/controller checks. It grants no
policy read, root endorsement, agent admission or other membership removal.

After revocation, the same member key and certificate may recover only its
already retained self-removal operation. Fresh timestamp, signature, selected
registry record and current H/controller are still required. This historical
proof is read-only: it cannot create a new operation, sign an unsigned request
or release another registry mutation. Exact retry returns the retained result;
changed inputs under the owned UUID refuse `operation_conflict`.

## Frozen request, registry effect and bounds

Beyond the common `requester`, `policy_ref`, `policy_version` and `artifact`,
the prepared request adds exactly `requester_key`: the actual authenticated
request key. The artifact has exactly `controller_did` and `request`.
`request` is the existing AWID covering-v2 `revoke_certificate` request for
POST `/v1/namespaces/{domain}/teams/{name}/certificates/revoke`, with the exact
certificate UUID, team claim and canonical body `{certificate_id}`. Its
audience is the pinned registry. Only its canonical request bytes are signed;
there is no new prefix, arbitrary signing route or second serializer.

The common result is `{signing,signature}` in padded standard base64. The
original operation expiry is also capped by the registry request timestamp's
300-second freshness window. A retry never refreshes that timestamp or signs
again. Current B2 policy checks remain separate from the admission policy.

One retained signature precedes a durable single mutation claim. A lost
registry answer is reconciled with fresh reads, never a blind mutation retry.
A registry conflict alone is not success. The receipt becomes committed only
after the exact registry record is revoked and the local admission's
`state='removed'`, receipt and local removal audit commit together. Until
confirmation, the reservation still counts against `max_active`. Removal
does not delete its admission time or reset `rate_window_seconds` /
`max_per_window`; those remain the operator's provisioned policy bounds.

Private registry reads retain the host's separate ordinary member credential;
the controller is never substituted for it. Removing that reader credential
can make confirmation unavailable. Capacity and the receipt then stay
unresolved until supported reader recovery restores fresh evidence.
