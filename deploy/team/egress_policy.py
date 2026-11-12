"""The agents' egress policy, derived from one team's deployment.

The egress component (OATS container/agent/egress, README "Derived policy")
reads this file read-only at /etc/egress/policy.json. It is derived, never
written by an operator: the five origins agents use come from deployment.yaml,
their addresses are what each origin's host resolves to on the services
network when the deployment starts, the denied addresses are the protected
backends', and the authority records are the signer profile's namespace
authorities, in AWID's own TXT encoding.
"""

import ipaddress

from awid.dns_verify import _parse_awid_record, awid_txt_name, awid_txt_value

ROLES = ("aweb", "secrets", "logs", "signer", "registry")


class Refused(Exception):
    """The deployment cannot give its agents an egress policy."""


def _origins(config: dict) -> dict[str, str]:
    return {
        "aweb": config["aweb"]["publicOrigin"],
        "secrets": config["secrets"]["publicOrigin"],
        "logs": config["logs"]["publicOrigin"],
        "signer": config["signer"]["requestOrigin"],
        "registry": config["team"].get("registryUrl", "https://api.awid.ai"),
    }


def _pinned(role: str, addresses: list[str]) -> list[str]:
    if not 1 <= len(addresses) <= 8 or len(set(addresses)) != len(addresses):
        raise Refused(f"{role}: needs one to eight distinct addresses, got {len(addresses)}")
    for address in addresses:
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            raise Refused(f"{role}: {address!r} is not an IPv4 address") from None
    return list(addresses)


def derive(config: dict, profile: dict, addresses: dict[str, list[str]], denied: list[str]) -> dict:
    """The policy for this deployment, its signer's profile, the addresses
    each role's origin resolves to and the protected backends' addresses."""
    origins = _origins(config)
    if profile["request_origin"] != origins["signer"]:
        raise Refused("request_origin: the signer profile names another signer")
    if profile["registry_origin"] != origins["registry"]:
        raise Refused("registry_origin: the signer profile names another registry")
    records = []
    for authority in profile["namespace_authorities"]:
        name = awid_txt_name(authority["domain"])
        text = awid_txt_value(authority["controller_did"], profile["registry_origin"])
        # The record agents will be answered is one AWID itself accepts.
        _parse_awid_record(text, dns_name=name)
        records.append({"name": name, "text": text})
    return {
        "frontAddress": config["agents"]["resolverIp"],
        "privateIngressAddresses": list(config["egress"].get("privateIngressAddresses", [])),
        "deniedAddresses": [_pinned("denied", [address])[0] for address in denied],
        "humanOrigin": config["signer"]["humanOrigin"],
        "authorityRecords": records,
        "targets": {role: {"origin": origins[role], "addresses": _pinned(role, addresses[role])} for role in ROLES},
    }
