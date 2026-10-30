# Non-redeeming invite inspection

`aw team invite inspect --token-stdin --json` reads one token line from stdin
through EOF, up to 65536 bytes. `--token-stdin` is optional: stdin is always the
input. Do not put the token in command arguments, shell history, logs or traces.
For example, an application can write its invite directly to the command's stdin
and close the pipe, or an operator can redirect a protected token file:

```bash
aw team invite inspect --json < protected-invite.txt
```

Inspection never accepts an invite, changes its use count, creates identity or
membership state, or connects a workspace. Existing invite creation and joining
commands retain their behavior. Automatic update checks are suppressed for this
command, including interactive text output.

## Hosted envelopes

The `aw_inv_v1_…` envelope supplies the destination service URL in `a` and the
inner invite token in `t`. Inspection sends exactly one possession-authenticated
`POST /api/v1/spawn/invite-preview` with `{"token":"<exact full input token>"}`,
the same credential supplied to acceptance. The envelope is not unwrapped for
the preview request. It sends no
identity credentials, performs no discovery, retries or redirects, and does not
follow any URL in the response. A base URL ending in `/api` is not double-prefixed.
Older bare hosted tokens have no destination and are refused; obtain a shareable
envelope rather than relying on a selected identity or ambient server setting.

The Cloud service must support this preview endpoint before hosted inspection is
available. An older service may return the same generic 404 as an unknown token;
the CLI cannot distinguish those cases. Source availability alone does not prove
the endpoint is deployed or that an installed CLI supports this command.

Successful JSON contains only:

```json
{
  "kind": "hosted",
  "canonical_team_id": "backend:example.test",
  "identity_scope": "local",
  "server_url": "https://service.example.test/api",
  "expires_at": "2030-01-01T00:00:00Z",
  "status": "active"
}
```

`identity_scope` is `local`, `global`, or `unknown` when the invitation does not
bind the child's scope. Unknown never selects local or global on acceptance;
creation chooses its scope explicitly. `expires_at` may be null. Status is the
service's current report, not a reservation or guarantee that later acceptance
will succeed. The envelope is unsigned: contacting its chosen service does not
independently verify the service or team. The normalized response `server_url`
must match the envelope URL; mismatch fails without a second request.

## Controller tokens

Base64url `TeamInviteToken` values are decoded locally, without network calls or
controller-store reads. Output uses `kind: "controller"`, canonical team ID from
the token's team/domain, its service URL (empty if absent),
`identity_scope: "unknown"`, and `status: "unverified"`. It omits `expires_at`.

The released token format contains no scope, expiry, signature or status. Local
decoding therefore establishes none of these, even when the token looks valid.
Controller acceptance still requires the same-machine invite record and
controller authority; inspection does not expand that boundary.

The command supplies no suggested label. Consumers such as OATS derive and
validate their own labels from `canonical_team_id` and handle collisions.

## Errors and identity selection

Exit 0 means inspection completed. Exit 2 denotes usage errors (such as absent,
multiline or oversized stdin, or a positional token); exit 1 denotes inspection
failure. Inspection errors have static messages and JSON of the form
`{"error":{"code":"malformed_token","message":"..."}}`.

| Code | Meaning |
| --- | --- |
| `malformed_token` | Malformed/incomplete token or invalid input usage |
| `unsupported_version` | Unsupported hosted envelope version |
| `unknown_or_invalid` | Service returned 401 or 404; token unavailable or preview unsupported |
| `expired`, `exhausted`, `revoked` | Known inactive invite; HTTP 200 responses include safe metadata under `invite`; HTTP 409 reports exhaustion |
| `expired_or_revoked` | HTTP 410; invite expired or revoked, without preview metadata |
| `server_unreachable` | Transport, rate-limit, HTTP or malformed-response failure |
| `server_mismatch` | Response service differs from the envelope service |

Inactive hosted results may arrive as HTTP 200 with safe preview metadata, or
as HTTP 409/410 without it; both become typed failures in the CLI. Response fields and values are validated before output. Bodies, headers,
token-derived URLs and underlying errors are never copied into diagnostics;
`--trace` prints only a fixed request description and HTTP status.

Inspection follows the shared identity selector (`--identity-home`, then
`AWEB_IDENTITY_HOME`, then the current directory). A selected folder that is
missing or invalid fails before inspection; it never uses another directory's
identity. Inspection itself creates no identity or membership. Acceptance is a
separate operation; creating a local identity requires an explicit fresh target
when an identity is inherited from the environment.

## Hosted acceptance and responsibility

New CLI hosted spawn acceptance requires a successful possession-only preview.
An old Cloud service without the route refuses; acceptance does not fall back
to an unattributed request. Cloud with preview must deploy before promoting the
new CLI from `@next` to `latest`.

The preview's `invite_id` identifies the spawn invitation. Its separate
`id_tree` is explicitly null for a legacy invitation, or contains the issue-time
selection `{v:1, issuer_id, domain, child_kind:"agent", mode}`. These fields pin
an agent issuer before acceptance; they do not verify ancestry. `mode` is
`host_managed` or `self_custodial`, describing who can sign as that issuer.
It does not select the child's local/global scope or custody. Acceptance signs
the selected domain, identity parent, mode and request UUID in `id_tree`.

The CLI supplies an installed issuer chain when issuing a hosted invitation.
A self-custodial issuer must supply an actual signed child through the existing
ID parent exchange before acceptance; an absent signature stays pending. An
existing global child's chain is reused only with the same selected parent;
joining never reparents it. The shared verifier checks the returned child chain
against the child's own key and the independently pinned selection.

The first successful preview, original child key, request UUID and selection
are retained in the identity home's recovery record. A lost acceptance response
retries that same operation with the retained preview; Cloud rechecks current
invitation and issuer authority. Once a response is durable, registry-only resume
uses the same certificate and registration arguments without another Cloud POST.
The per-child `registration_request.invitation_id` is distinct from the spawn
invitation's `invite_id`. Current public verification precedes chain installation;
local children are never published. Output reports ID registration separately
from membership, which Cloud may have committed before registration completes.
