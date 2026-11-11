# Browser consent for one hosted identity creation

Status: **proposal for paired review and Athena; not frozen or implemented**
(aweb-acxu).
Goal 2: a person endorses one registered deployment root for customer-operated
agents; ordinary descendants inherit that responsibility through the existing
ID tree. Goal 1: preserve explicit human attribution in hosted creation.
This specifies a portable hosted-service/CLI exchange, not an operator's
deployment. Coordinator review through Athena precedes implementation freeze.

## Authority and boundary

The child signing key stays in the CLI's explicit fresh credential root.
The child signs its exact creation request; that proves possession and intent,
not human consent. A current authenticated browser session, CSRF protection,
account-to-human association and existing organization/team permissions
authorize the selected operation. The custodial human signs the agent's ID
certificate; the hosted namespace/team controllers authorize its address and
membership. The CLI verifies both certificates and current registry evidence.
Neither ancestry nor custody replaces membership authority.

`cli.team_admission` remains admission-only. The new browser operation neither
mints nor expands a CLI token. Existing `cli.org_create`, native-owner and BYOT
creation retain their existing authorities and wire formats. This path creates
one new global agent; joining, adopting or recovering another identity remains
a separate operation. A deployment root is an ordinary registered agent.

The governing boundaries are [onboarding authority](../byot-onboarding-contract.md#authority-is-separate-from-custody-and-hosting),
[hosted creation](../identity.md), and [ID certificates](../id-certificates.md).

## One request/result file exchange

Proposed entry points are `aw id create --consent-request FILE` and
`aw id create --consent-result FILE`, using the same explicit `--identity-home`.
They are mutually exclusive and incompatible with native-owner/root-parent
creation. Export takes the existing `--org`, `--team-id`, `--name`, explicitly
selected `--human-parent H`, and effective inbound mode. Import reads the saved
selection; any supplied conflicting selectors refuse before effects.

Export uses the admission login only to select the intended service/account
and discover H's identity domain. H must be explicitly selected from that
account's registered humans; no inferred parent or automatic login/scope
upgrade. The existing `/api/v1/cli-auth/status` response supplies
`account.human_identities[].{id,domain}` with the actual unchanged token scope.
Missing, null or ambiguous evidence refuses; it does not select another parent
or authority.

Export retains the original private key and exact semantic selection before
remote effects. It performs the existing child-signed `did:aw` mapping
registration required by hosted creation, then exports only the public request.
This is **pending consent**, not a registered, attributed deployment root.
It prints the selected service's browser page `/account/identity-creations`.
No request body, token or key goes in that URL; no browser is opened implicitly.

The request is the existing creation object:

```json
{
  "org": "<selected organization>",
  "team_id": "<exact service UUID or canonical team selector>",
  "name": "<address name>",
  "did": "did:key:<child key>",
  "inbound_mode": "team_and_contacts",
  "id_tree": {
    "v": 1,
    "request_id": "<retained UUID>",
    "domain": "<selected human's identity domain>",
    "parent": {"kind": "identity", "id": "did:aw:<H>"}
  },
  "proof": {
    "type": "didkey-intent-v1",
    "timestamp": "<RFC3339 UTC>",
    "signature": "<base64 without padding>"
  }
}
```

No supplied `id_chain` is accepted on this browser-person path. The child signs
the existing canonical JSON intent: `operation=cli_global_identity_create.v1`,
`aud=<selected service origin>`, `method=POST`,
`path=/api/v1/account/identity-creations`, every creation field above other than
`proof`, and `timestamp=proof.timestamp`. The complete `id_tree` is covered.
Keep the exact team selector in the proof; resolving it is the service's job.
The new target separates browser consent from the existing CLI authority route.

| Endpoint | Behavior |
| --- | --- |
| `POST /api/v1/account/identity-creations/preview` | Browser session and CSRF; validate the child proof against the **approval** target above, current account/H and organization/team. Show child DID and key fingerprint, resolved address/team, selected H and descendant responsibility. No signing, creation or registry write. |
| `POST /api/v1/account/identity-creations` | Explicit browser approval of the identical request. Refuse bearer/API-key substitution. Recheck session, H/key, organization/team and intent through the existing creation composition and its locks; return its retained result. |

The confirmation says: “Create this agent under your human identity. Agents it
creates, and their descendants, will be attributed to you through this identity
chain.” Preview is not approval. If current authority or the intent no longer
validates at approval, refuse; never substitute another human or selected resource.
The browser submits the uploaded request, never a reconstruction from editable
display fields. The existing timestamp skew bound (300 seconds) applies at
preview and again at approval.

The download is `{v:1, request:<approved request>, result:<existing hosted
creation response>}`. The wrapper is correlation, not a new signed
authority artifact. The existing result contains the identity/address/team,
team certificate, ID chain and registration arguments; it carries no account
token or child private key. Canonicalize the request using the existing JSON
profile, rejecting duplicate and unknown request fields on these new routes.
Exact comparison covers
every signed field and proof, not incidental whitespace or object key order.

Import matches one deliberately retained exported request, the unchanged
semantic selection and local child key, then validates the existing response
and both certificate bindings. It retains
the complete validated result before completing subject-signed ID registration,
fresh chain verification, normal installation and effective inbound-mode
readback. Only then report `id_registration=registered`. A downloaded chain or
successful browser approval alone is not completion.

## Retry, compatibility and proof

The root retains one key, request UUID, service/account, organization/team,
name, mode and human/domain. Deliberate re-export may refresh only the proof's
timestamp/signature; approval still checks current authority. An expired proof
cannot authorize a browser retry. Exact retries reuse the retained creation;
changed semantic bindings refuse. Import accepts an earlier exact exported
request after a timestamp refresh, and never treats that timestamp as authority
to bypass current certificate/registry checks. Once a complete result is saved,
continuation uses it without another browser creation. Partial failures preserve
recovery; a completed root refuses another creation.

Reuse the hosted creation preparation/validation/installation pipeline in
`cli/go/cmd/aw/id_create_hosted.go` and `cli/go/cmd/aw/hosted_creation.go`.
The missing CLI seams are export/import entry points and retaining the exact
public consent request. `aw id parent request/import` is the different
invitation-bound certificate exchange; do not overload its format. Reuse the
existing service creation composition, not a synthetic CLI authorization.
No pending-operation store, polling protocol or new certificate format.

Released CLI/owner requests continue unchanged. A service without the new
routes refuses this explicitly selected operation; the CLI never retries it
through broader login or owner authority.

Required proof after review: admission-only bearer or child proof alone cannot
create/approve; preview creates nothing; wrong browser/H/team, tampering and
expiry refuse; exact retry reuses while changed retry refuses; another local
key or altered result fails import; lost-response and interrupted-registration
recovery keep the original key/chain. The real browser-to-CLI journey must
register the root, verify H, create ordinary descendants unattended and verify
root revocation invalidates them. Priority remains acxt/acxv before acxu.
