# What the registry's operator and the model provider can read and do

## The AWID registry's operator

The registry the team is in (`team.registryUrl`) holds the team's public
records and its private ones.

| Reads | Source |
| --- | --- |
| Public: registered addresses, `did:aw` key-change logs and published team-server records. Private teams are not anonymously enumerable, but a lookup of an exact team name discloses that the team exists (`team_private` 403). | `awid/src/awid_service/routes/teams.py`, `did.py`, `dns_addresses.py` |
| Private teams too, from its database whatever the API's privacy: the roster, the certificate blobs and the revocations | `awid/src/awid_service/routes/teams.py` |

The current team-key lookup is trusted through the registry's HTTPS, not
through an independently checked signature over that lookup. Replacing that
answer can make forged team certificates pass aweb's, Secrets' and Logs'
membership-signature check; their other request, identity, grant and policy
checks still apply (`awid/src/awid/registry.py`,
`server/src/aweb/team_auth_deps.py`, `naapp-lib/src/aweb_naapp/runtime/team_auth.py`).
Signed records keep their own signatures, and this gives the registry neither
the legitimate controller and member private keys nor the content of existing
self-custodial `--e2ee` messages. The signer compares the registry's key with
the one in its custody and refuses on a difference (`authority_changed`): there
a substitution stops signing rather than forging it
(`server/src/aweb/protected_signing/authority.py`).

### The registry service token

A registry's trusted service token (`AWID_SERVICE_TOKEN`) lists the private
teams on that registry and reads their roster, certificate metadata and
revocation history (`awid/src/awid_service/routes/teams.py`). It can enumerate
team-signed server, custodian, member-custody and member-person records
(`routes/attestation_records.py`), and it bypasses the rate limit on the routes
that allow the trusted service (`awid/src/awid/ratelimit.py`). It is not a
controller signing key: issuing or revoking a certificate still needs the
controller, and fetching a signed certificate blob still needs that member's
signature. The registry operator's database access is broader than the token.
**This deployment holds none:** its aweb, Secrets and Logs are ordinary members
of the team, each with its own key. The token's powers apply only to an
installation that configures one.

## The model provider

When the harness makes a model request, the configured provider receives its
prompts and the context included with them, which can contain decrypted mail and
chat, file contents, command output and secret-use receipts. The image neither
redacts nor isolates those from the harness. The provider's retention is its
own. The harness also retains session transcripts locally, under
`/state/home/.claude` when that launch configuration is selected
(`deploy/team/access/agents.md`).

The harness login authenticates the team's account at the provider; every agent
of the container can read it and use the account's authority.
