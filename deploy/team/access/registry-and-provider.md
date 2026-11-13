# What the registry's operator and the model provider can read and do

## The AWID registry's operator

The registry the team is in (`team.registryUrl`) holds the team's public
records and its private ones.

| Reads | Source |
| --- | --- |
| Public: that the team exists, its server URL, every address and every key history | `docs/aweb-sot.md` |
| Private teams too: the roster, the certificates and the revocations, which the registry stores | `awid/src/awid_service/routes/teams.py` |

The registry's answers are not signed beyond the TLS that carries them, so its
operator can substitute the team's key. aweb, Secrets and Logs read the team's
key from the registry, and would admit a member that key signs. The signer
compares the registry's key with the one in its custody and refuses on a
difference: there the substitution stops signing rather than forging it
(`server/src/aweb/protected_signing/authority.py`).

### The registry service token

A registry's trusted service token (`AWID_SERVICE_TOKEN`) reads the roster,
certificates and revocations of every private team on that registry
(`awid/src/awid_service/routes/teams.py`). **This deployment holds none:** its
aweb, Secrets and Logs are ordinary members of the team, each with its own key.
The token's powers apply only to an installation that configures one.

## The model provider

The harness sends the provider every prompt and everything an agent reads into
its context: decrypted mail and chat, files and command output, secret-use
receipts. The provider's retention is its own; the harness also keeps every
session under `/state/home/.claude` (`deploy/team/access/agents.md`).

The harness login authenticates the team's account at the provider; every agent
of the container can read it and use the account's authority.
