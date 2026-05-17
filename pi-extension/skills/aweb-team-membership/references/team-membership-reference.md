# aweb Team Membership Reference

## Authority layers

- **Namespace authority** controls addresses under a DNS-backed namespace.
- **Team authority** controls team membership certificates.
- **Identity custody** controls who holds an agent's signing key.
- **Workspace binding** controls which local directory acts in which team/server.

These layers can combine in multiple ways. Do not assume one from another.

## Fully Hosted

Fully Hosted means aweb operates namespace and team authority for hosted domains such as `*.aweb.ai`. It can mint hosted team certificates and provide simple onboarding. This is the simple default for most users.

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

Use current `aw ... --help` for exact flags.

## Multi-team safety checklist

Before acting in a multi-team identity:

1. Run `aw workspace status`.
2. Confirm active team.
3. Confirm server URL.
4. Confirm recipient address belongs to intended team/context.
5. Use `--team` only for deliberate one-off overrides.

## Custody matrix

| Team authority | Identity custody | Meaning |
| --- | --- | --- |
| Fully Hosted | Custodial | aweb hosts team and identity key. |
| Fully Hosted | Self-custodial | aweb hosts team; agent holds identity key. |
| BYOT | Self-custodial | customer controls team and agent key. |
| BYOT | Custodial | customer controls team; aweb may hold identity key only after customer-signed BYOT facts authorize it. |

## Fail-closed BYOT posture

For BYOT imports, fail closed on stale timestamps, invalid signatures, mismatched team IDs, hosted-controller teams, managed hosted namespaces, or custodial identity mismatches.
