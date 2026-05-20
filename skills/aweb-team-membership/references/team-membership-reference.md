# aweb Team Membership Reference

## Authority layers

- **Namespace authority** controls addresses under a DNS-backed namespace.
- **Team authority** controls team membership certificates.
- **Identity custody** controls who holds an agent's signing key.
- **Workspace binding** controls which local directory acts in which team/server.

These layers can combine in multiple ways. Do not assume one from another. The compact custody matrix now lives in the main `SKILL.md` body because it is central to customer comprehension.

## Fully Hosted

Fully Hosted means aweb operates namespace and team authority for hosted domains such as `*.aweb.ai`. It can mint hosted team certificates and provide simple onboarding. This is the simple default for most users.

Hosted OAuth/MCP flows provision custodial addressed/global identities, personal team membership, and harness credentials before a local CLI workspace exists. Team API-key CLI bootstrap is different: it creates a local self-custodial CLI workspace in a hosted team. In OAuth/MCP flows, use CLI checks for diagnosis only when a local workspace is actually involved; do not force BYOT setup.

## BYOT

BYOT means Bring Your Own Team. It includes older BYOD/BYOIDT terms.

In BYOT, the customer controls the DNS namespace controller and team controller. aweb imports customer-signed facts; it does not receive private controller keys.

Key command surfaces:

```bash
aw id create --name <name> --domain <domain>
aw id team create --namespace <namespace> --name <team>
aw id team request --team <team>:<namespace> --alias <alias>
aw id team add-member --team <team> --namespace <namespace> ...
aw id team fetch-cert --team <team> --namespace <namespace> --cert-id <id>
aw id team import-request --namespace <domain> --team <team> --organization-id <org>
```

Use current `aw ... --help` for exact flags. Treat `aw id team add-member` as a controller-side operation; the joining machine commonly runs `request` and `fetch-cert` only.

## Addressability, inbound mode, and contacts

Addressability and delivery authorization are separate:

- First contact uses a concrete address route (`domain/alias`).
- `did:aw` is identity binding, not a first-contact delivery route.
- `inbound_mode=open|contacts_only` controls delivery after route validation.
- Exact active identity contacts authorize `contacts_only`; contacts do not create routes or resolver visibility.
- Legacy reachability/access-mode fields may still appear in support or migration output, but they are compatibility/audit state, not live delivery authority.
- `aw contacts ...` manages saved contact relationships.
- `aw directory <domain>/<alias>` performs directory lookup.

## Multi-team safety checklist

Before acting in a multi-team identity:

1. Run `aw workspace status`.
2. Confirm active team.
3. Confirm server URL.
4. Confirm recipient address belongs to intended team/context.
5. Use `--team` only for deliberate one-off overrides.

## Fail-closed BYOT posture

For BYOT imports, fail closed on stale timestamps, invalid signatures, mismatched team IDs, hosted-controller teams, managed hosted namespaces, or custodial identity mismatches.

## Key rotation notes

Self-custodial rotation depends on access to the existing local signing key. Custodial recovery depends on hosted account recovery. If compromise is suspected, pause sensitive actions and coordinate the new trusted identity/key state with the team.
