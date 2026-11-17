# AWID controller request binding

Namespace and team controllers retain their existing authority. Controller
possession does not establish identity custody or permit a member to register or
revoke certificates. This additive HTTP envelope covers every written field in
header-authenticated namespace, team and address mutations.

## Covering wire

`Authorization: DIDKey <controller did:key> <signature>` signs canonical UTF-8
JSON bytes carried in base64url `X-AWEB-Signed-Payload`. Required fields are the
existing operation-specific claims (`domain`, `operation`, and the route's name,
team name, certificate ID or preconditions) and:

```json
{
  "v": 2,
  "type": "aweb.awid-controller-request",
  "aud": "https://registry.example.com",
  "method": "POST",
  "path": "/v1/namespaces/example.com/teams",
  "body_sha256": "<SHA-256 of exact HTTP request body bytes>",
  "timestamp": "<X-AWEB-Timestamp>"
}
```

Every field is required, canonical bytes must match exactly, and extra claims
are refused. `method` is uppercase; `path` is the external raw path plus raw
query, including a mount prefix and percent-encoding. The `aw` and Python
clients address a registry by its origin and refuse a registry URL with a path,
so they do not write to a registry served under a path prefix. Timestamp skew
remains 300 seconds. A covering header, including an empty or malformed one, never
falls back to a legacy signature. Controller requests cannot use the team-auth
v2 purpose, and team-auth refuses the AWID purpose.

`aud` must be a canonical origin from `AWID_PUBLIC_ORIGINS` (comma-separated), or
an embedding's explicit `app.state.awid_public_origins`. It is never derived
from Host or forwarded headers. A covering request fails closed with 503 when
no origins are configured. Configure each registry's public origins before
migrating its clients. Legacy request verification is unaffected by this setting.

Parent authorization has its own `X-AWEB-Parent-Authorization`,
`X-AWEB-Parent-Timestamp`, and `X-AWEB-Parent-Signed-Payload`. It binds the same
HTTP request body, method and path, with its parent authorization operation.
Existing atomic-claim and DID-log proofs are separately versioned signed body
artifacts; they retain their existing canonical bytes and authority checks.

## Certificate records

Every new certificate registration, under either HTTP envelope, requires the
complete team-signed certificate blob. ID, team, team key, member key, optional
stable DID and address, alias and scope must match the verified blob. Missing or
mismatched blobs are refused; historical blob-free records remain readable and
retain the existing explicit reissue-required response when fetching the blob.
The certificate's optional stable DID remains controller-asserted; this change
does not add an independent stable-identity verification claim.

## Rollout and measurement

Deploy the accepting AWID server and configure its origins first. Then publish
and deploy the Python RegistryClient and aw clients that sign covering requests.
Clients must not silently retry a covering refusal using a legacy signature.
Old forms remain accepted until Juan chooses their cutoff from measured use.
Their unsigned-field weaknesses are not repaired by merely deploying an accepting
server; migration and the later cutoff complete that protection.

Each successful request increments `app.state.controller_auth_counts` once per
signed form and operation, including a distinct parent operation where used,
keyed by the sending client's family. Each key's cumulative count is reported
at one and powers of two, following AWID's existing service-exemption metric
convention, as one structured line:

```
event=<event> metric=<event> value=<count> operation=<operation> client=<client> form=<form>
```

| event | form | counts |
|---|---|---|
| `awid_legacy_controller_auth_accepted` | `legacy` | controller writes signed in the legacy form |
| `awid_controller_auth_accepted` | `covering` | controller writes and team reads signed in the covering form |
| `awid_path_signed_read_accepted` | `path` | team reads signed with the path signature |

The covering count shows that requests still arrive, so a silent legacy line
means no legacy sender rather than no traffic. `client` is one of three
families: `aw/<version>` when the User-Agent is exactly aw's
`aw/<version> (<os>/<arch>)`, `python-httpx` for the Python client, and `other`.
Each worker process tracks at most 16 distinct aw versions and counts any later
one as `aw/other`: any key can sign an accepted read, so a claimed version must
not grow the counter or the log without bound. The raw User-Agent is never
emitted. Invalid proofs and refused requests are
not counted. Only these closed values are emitted: no domains, caller
identifiers, bodies or credentials. The counts are per worker process. There is
no public metrics endpoint or new telemetry SDK.

Private-team reads use the same covering envelope with operation `read_team`;
[awid-sot.md](awid-sot.md#signed-team-reads) states the claims and which key
each read admits.

The published aw 1.36.43 always sends the blob. Cloud's production registration
wrapper also supplies a minted or validated persisted blob on every call;
its paired change refuses an empty blob before calling the registry. Historical
test evidence is seeded as old data, rather than creating a new unsigned record.

### Public team creation act

New Python/Go team creation callers additionally send `X-AWEB-Team-Key-Act`.
It carries `{signed_payload,signature}`; the unpadded-base64url payload is the
canonical JSON `{v:1,type:"aweb.team-key-act",operation:"create_team",domain,
name,team_did_key,timestamp,body_sha256}`. The same namespace controller signs
it. The registry checks all three domain/team/key fields against the body,
the exact body hash and timestamp, and stores the act atomically with creation.
Unlike the covering request, this public proof can establish the key without
publishing a private team's display name. Released callers remain accepted;
a missing act is repaired by explicit same-key re-attestation. Old registries
may ignore the additional header. The existing covering request is unchanged.
