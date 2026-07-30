# Authenticate to library with an AWID team certificate

library has no app accounts. Team-scoped reads and writes authenticate with an
AWID team certificate over the aw-native signed-request path. Public catalog
reads (`/v1/blueprints`, `/v1/blueprints/{id}/profiles/{profile_id}`) need
no auth; the shelf (`/v1/shelf`, `/v1/profiles/{id}`) is private and cert-gated.

## Call a team-scoped endpoint

```bash
export LIBRARY_ORIGIN=https://library.aweb.ai
aw id request GET "$LIBRARY_ORIGIN/v1/agents/<agent_id>/profile-binding" --team-auth --raw
aw id request POST "$LIBRARY_ORIGIN/v1/materialize" --team-auth --raw \
  --body '{"profile_ref":"<ref>","runtime_kind":"claude-code","target":"local"}'
```

`--team-auth` attaches the team certificate plus a signed v2 request envelope.
library verifies the certificate against the AWID registry, checks revocation,
and keys all team state by the verified `team_id`.

## What library verifies

- the `Authorization: DIDKey <did_key> <signature>` header signs a canonical
  request payload (method, path, team_id, body_sha256, audience, timestamp);
- the `X-AWID-Team-Certificate` is signed by the team's `team_did_key` and is
  not revoked;
- the certificate's `member_did_key` matches the signing key;
- the request timestamp is within the allowed clock skew.

A request missing or failing any of these is rejected with HTTP 401. AWID
(https://awid.ai) is the authority for team keys, certificates, and revocation.
