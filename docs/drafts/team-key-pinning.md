# Team-key pinning (V1 design, for review before build)

Status: **proposal**. This changes a stated rule: `trust-model.md` calls the
local `teams.team_did_key` "a hint, not authority". It is an identity-path
change and needs Juan's explicit approval before it is built.

## Problem

Every certificate check takes the team key from an unsigned registry answer:
`awid/src/awid/registry.py` `get_team_public_key`,
`server/src/aweb/team_auth_deps.py` `_resolve_team_key`, and
`naapp-lib/src/aweb_naapp/runtime/team_auth.py` `_refresh_team_facts`.
Whoever runs the registry, or can change what it serves, can name a key it
holds. Its forged certificates then pass the membership check on aweb, Secrets
and Logs. The 2026-08-17 ruling puts partial-service compromise in scope, so
the registry must not be the only source of truth for a team's key.

## Governing model

The **namespace controller** creates a team, sets its key and is the only
party that can rotate it (`POST .../teams/{name}/rotate`, signed
`rotate_team_key`). DNS `_awid.<domain>` is the root of trust for that
controller. A hosted `*.aweb.ai` child inherits `_awid.aweb.ai`, so for hosted
teams the operator is the authority, as the docs already say. The registry
stores and serves these facts but has no authority over them.

## Design

1. **Pin.** A verifying server holds one pinned key per team. On aweb that is
   `teams.team_did_key`, which is already written once when the team is
   admitted (`service_registration.py`, `connect.py`), never silently
   overwritten, and checked on re-registration (`awid_team_controller_mismatch`).
   naapp-lib needs a new runtime table, `team_key_pins`. Its observed-principals
   `teams` row cannot serve as the pin: `record_observed_principal` overwrites
   it on every observation (`team_auth.py:860`). With this change, a registry
   answer is used only when it equals the pin. The first answer for a team sets
   the pin.
2. **Changed key.** If the registry names a different key, the server does not
   use it. It moves the pin only with rotation evidence (step 3). Otherwise it
   fails closed: 401 `team_key_unverified`, distinct from `unknown_team`. It
   logs the team, the pinned key, the served key and the reason the evidence
   failed. The existing signature-failure refresh path goes through the same
   check.
3. **Rotation evidence.** This is the exact `rotate_team_key` act the
   namespace controller already signs. Today awid verifies the act and then
   discards it. With this change awid stores it: a new migration adds
   `team_key_acts`, holding the exact signed bytes, the signer `did:key` and
   the signature. awid serves the latest act at
   `GET .../teams/{name}/key-act`. A server accepts the act only if:
   - the signature verifies over the stored bytes;
   - `operation` is `rotate_team_key`;
   - `domain`, `name` and `new_team_did_key` equal the team and the served key;
   - the signer equals the controller named by **exact DNS** for the domain
     (or the inherited parent record). The signer is not checked against the
     registry's `controller_did`. The lookup uses the SDK's existing
     `_awid.` TXT resolver;
   - the act's timestamp is newer than the timestamp of the act that set the
     current pin. This blocks replaying an older act to roll the key back.

   The server then advances the pin and the act timestamp in one statement,
   guarded by compare-and-swap on the old pin. The verification lives once,
   in the awid SDK. Each server supplies only its pin storage.
4. **Recovery cases that use the same act.** If the namespace controller has
   rotated since a team-key act was signed, or a team was deleted and then
   recreated under the same name, the current controller re-submits `rotate`
   with the key the team already has. awid already accepts that request
   (`key_changed: false`), so no new operation is needed, and it records a
   fresh act.

## Not changed

Certificates, the revocation path, the 60-second key freshness and the
15-minute outage grace stay as they are. Released clients need no change: the
`aw` CLI already sends the act and awid now records it. The cloud signer's
refusal when the registry key differs from custody already follows this rule.

## Accepted residuals (named)

- **First admission is still trust-on-first-use (TOFU).** A substitution
  before a team's first contact with a server is not detected silently,
  though: the team's genuine certificates then fail under the substituted
  key. Binding the first pin to DNS-backed evidence would need a key-binding
  `create_team` act. Today's create act does not sign the key. That is left
  as a later step.
- **The `local` namespace has no DNS.** A local-dev team cannot rotate under
  a pin. The server operator has to remove the pinned row explicitly.
- **Hosted teams:** pinning protects against a registry-only compromise. It
  cannot protect against the operator that also holds the controller key.
- **The registry can withhold acts.** That denies availability. It does not
  grant authority.

## Build plan (TDD, after approval)

The plan has four parts. Each starts from a RED test in which a registry
serving a substituted key makes a forged certificate pass on aweb and on
naapp-lib.

1. awid migration and route.
2. SDK act verifier.
3. aweb and naapp-lib pin checks, plus a migration for the pin act timestamp.
4. Updates to `trust-model.md` and `awid-sot.md`.
