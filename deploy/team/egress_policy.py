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
# The roles agents may reach on the internet, each at one fixed origin: the
# operator turns a role on and never names a host.
EXTERNAL_ROLES = {"source": "https://github.com", "model": "https://api.anthropic.com"}


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


def _external(config: dict, own: set[str]) -> dict:
    """The external roles the operator turned on and the public resolvers
    egress alone asks for their addresses; nothing when no role is on."""
    external = config["egress"].get("external", {})
    roles = sorted(role for role in EXTERNAL_ROLES if external.get(role))
    resolvers = list(external.get("resolvers", []))
    if not roles:
        if resolvers:
            raise Refused("egress.external.resolvers: given without an external role")
        return {}
    if not resolvers:
        raise Refused("egress.external.resolvers: required when an external role is on")
    if len(set(resolvers)) != len(resolvers):
        raise Refused("egress.external.resolvers: must be distinct")
    if len(resolvers) > 4:
        raise Refused("egress.external.resolvers: needs one to four addresses")
    for resolver in resolvers:
        try:
            address = ipaddress.IPv4Address(resolver)
        except ValueError:
            raise Refused(f"egress.external.resolvers: {resolver!r} is not an IPv4 address") from None
        if resolver in own:
            raise Refused(f"egress.external.resolvers: {resolver} is one of the deployment's own addresses")
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise Refused(f"egress.external.resolvers: {resolver} is not a public address")
    return {
        "externalTargets": {role: {"origin": EXTERNAL_ROLES[role]} for role in roles},
        "externalResolverAddresses": resolvers,
    }


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
    policy = {
        "frontAddress": config["agents"]["resolverIp"],
        "privateIngressAddresses": list(config["egress"].get("privateIngressAddresses", [])),
        "deniedAddresses": [_pinned("denied", [address])[0] for address in denied],
        "humanOrigin": config["signer"]["humanOrigin"],
        "authorityRecords": records,
        "targets": {role: {"origin": origins[role], "addresses": _pinned(role, addresses[role])} for role in ROLES},
    }
    own = {config["agents"]["resolverIp"], *policy["privateIngressAddresses"], *policy["deniedAddresses"],
           *(address for target in policy["targets"].values() for address in target["addresses"])}
    return {**policy, **_external(config, own)}


# The probe's credential-free stand-ins for the agent's state, login and
# authorized keys, under the run directory, and where the agent sees them.
PROBE_MOUNTS = (
    ("probe/state", "/state", True),
    ("probe/login", "/etc/agent-login", False),
    ("probe/authorized_keys", "/etc/agent-ssh/authorized_keys", False),
    ("resolv.conf", "/etc/resolv.conf", False),
)
# Where the agent image's optional fragments mount the agents' public CA
# (compose.agent.trust.yaml) and the operator's Git mirrors
# (compose.agent.mirrors.yaml); the probe, as the agent service, has them too.
AGENT_CA = "/etc/agent-trust/ca.pem"
MIRRORS = "/mirrors"
# One existing GET route per role that answers 200 and changes nothing.
ALLOWED_PATHS = {"aweb": "/ready", "secrets": "/ready", "logs": "/ready", "signer": "/readyz", "registry": "/health"}


def boundary_plan(
    config: dict,
    policy: dict,
    *,
    project: str,
    images: dict[str, str],
    run_dir: str,
    backends: dict[str, str],
    protected_sources: list[str],
) -> dict:
    """The runtime plan of the OATS boundary probe (egress
    probe-compose-boundary.mjs) for this deployment's Compose project: its
    inert probe container and the egress proxy on the actual agents network,
    the mounts the probe is approved to have, the protected sources none may
    overlap, and the two backends no agent may reach."""
    for role, address in backends.items():
        if address not in policy["deniedAddresses"]:
            raise Refused(f"{role}: {address} is not one of the policy's denied addresses")
    agents = config["agents"]
    result = {
        "probeContainer": f"{project}-agent-probe",
        "proxyContainer": f"{project}-egress-1",
        "agentsNetwork": f"{project}_agents",
        "servicesNetwork": f"{project}_services",
        "probeImage": images["agent"],
        "proxyImage": images["egress"],
        "uid": agents.get("uid", 20001),
        "gid": agents.get("gid", 20001),
        "approvedProbeMounts": [
            {"Type": "bind", "Source": f"{run_dir}/{source}", "Destination": target, "RW": writable}
            for source, target, writable in PROBE_MOUNTS
        ] + [
            {"Type": "bind", "Source": agents[key], "Destination": target, "RW": False}
            for key, target in (("caFile", AGENT_CA), ("mirrorsDir", MIRRORS)) if key in agents
        ],
        "protectedSources": list(protected_sources),
        "policy": policy,
        "allowedPaths": dict(ALLOWED_PATHS),
        "deniedBackends": [
            {"role": "postgres", "address": backends["postgres"], "port": config.get("postgres", {}).get("port", 5432)},
            # Redis is on aweb's backend network alone.
            {"role": "redis", "address": backends["redis"], "port": 6379, "controlNetwork": f"{project}_backend"},
        ],
        "protectedPaths": [],
    }
    # The probe verifies its HTTPS controls with the agents' own trust: the
    # configured public CA, or else the image's public roots alone.
    if "caFile" in agents:
        result["caFile"] = AGENT_CA
    return result
