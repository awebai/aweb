"""deploy/team/egress_policy.py: the agents' egress policy, derived from the deployment."""

import importlib.util
from pathlib import Path

import pytest

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
spec = importlib.util.spec_from_file_location("egress_policy", TEAM / "egress_policy.py")
egress_policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(egress_policy)

CONTROLLER = "did:key:z6Mkon3Necd6NkkyfoGoHxid2znGc59LU3K7mubaRcFbLfLX"
CONFIG = {
    "team": {"id": "devteam:example.com", "registryUrl": "https://registry.example.com"},
    "aweb": {"publicOrigin": "https://aweb.example.com"},
    "secrets": {"publicOrigin": "https://secrets.example.com"},
    "logs": {"publicOrigin": "https://logs.example.com"},
    "signer": {"requestOrigin": "https://sign.example.com", "humanOrigin": "https://approve.example.com"},
    "agents": {"resolverIp": "172.30.0.2"},
    "egress": {"privateIngressAddresses": ["172.31.0.250"]},
}
PROFILE = {
    "request_origin": "https://sign.example.com",
    "human_origin": "https://approve.example.com",
    "registry_origin": "https://registry.example.com",
    "namespace_authorities": [{"domain": "example.com", "controller_did": CONTROLLER}],
}
INGRESS = {role: ["172.31.0.250"] for role in ("aweb", "secrets", "logs", "signer", "registry")}


def test_the_policy_names_exactly_the_five_origins_agents_use_at_their_pinned_addresses():
    policy = egress_policy.derive(CONFIG, PROFILE, INGRESS, ["172.31.0.3", "172.31.0.4"])
    assert policy == {
        "frontAddress": "172.30.0.2",
        "privateIngressAddresses": ["172.31.0.250"],
        "deniedAddresses": ["172.31.0.3", "172.31.0.4"],
        "humanOrigin": "https://approve.example.com",
        "authorityRecords": [
            {
                "name": "_awid.example.com",
                "text": f"awid=v1; controller={CONTROLLER}; registry=https://registry.example.com;",
            }
        ],
        "targets": {
            "aweb": {"origin": "https://aweb.example.com", "addresses": ["172.31.0.250"]},
            "secrets": {"origin": "https://secrets.example.com", "addresses": ["172.31.0.250"]},
            "logs": {"origin": "https://logs.example.com", "addresses": ["172.31.0.250"]},
            "signer": {"origin": "https://sign.example.com", "addresses": ["172.31.0.250"]},
            "registry": {"origin": "https://registry.example.com", "addresses": ["172.31.0.250"]},
        },
    }


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_origin", "https://other-sign.example.com"),
        ("registry_origin", "https://other-registry.example.com"),
    ],
)
def test_a_profile_that_names_another_signer_or_registry_is_refused(field, value):
    with pytest.raises(egress_policy.Refused, match=field):
        egress_policy.derive(CONFIG, {**PROFILE, field: value}, INGRESS, [])


@pytest.mark.parametrize(
    "addresses",
    [[], ["172.31.0.250"] * 2, [f"172.31.0.{n}" for n in range(1, 10)], ["fd00::1"], ["registry.example.com"]],
)
def test_each_origin_is_pinned_to_one_to_eight_distinct_ipv4_addresses(addresses):
    with pytest.raises(egress_policy.Refused, match="aweb"):
        egress_policy.derive(CONFIG, PROFILE, {**INGRESS, "aweb": addresses}, [])
