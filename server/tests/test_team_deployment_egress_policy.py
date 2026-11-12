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


POLICY = egress_policy.derive(CONFIG, PROFILE, INGRESS, ["172.31.0.6", "172.32.0.3"])
IMAGES = {"agent": "registry.example/agent@sha256:" + "a" * 64, "egress": "registry.example/egress@sha256:" + "b" * 64}
BACKENDS = {"postgres": "172.31.0.6", "redis": "172.32.0.3"}
PROTECTED = ["/srv/team/secrets", "/var/lib/docker/volumes/team_postgres_data/_data", "/run/docker.sock"]


def plan(**changes):
    arguments = {
        "project": "team",
        "images": IMAGES,
        "run_dir": "/srv/team/run",
        "backends": BACKENDS,
        "protected_sources": PROTECTED,
    } | changes
    return egress_policy.boundary_plan(CONFIG, POLICY, **arguments)


def test_the_boundary_plan_names_the_deployment_s_runtime_and_the_probe_s_credential_free_mounts():
    assert plan() == {
        "probeContainer": "team-agent-probe",
        "proxyContainer": "team-egress-1",
        "agentsNetwork": "team_agents",
        "servicesNetwork": "team_services",
        "probeImage": IMAGES["agent"],
        "proxyImage": IMAGES["egress"],
        "uid": 20001,
        "gid": 20001,
        "approvedProbeMounts": [
            {"Type": "bind", "Source": "/srv/team/run/probe/state", "Destination": "/state", "RW": True},
            {"Type": "bind", "Source": "/srv/team/run/probe/login", "Destination": "/etc/agent-login", "RW": False},
            {
                "Type": "bind",
                "Source": "/srv/team/run/probe/authorized_keys",
                "Destination": "/etc/agent-ssh/authorized_keys",
                "RW": False,
            },
            {"Type": "bind", "Source": "/srv/team/run/resolv.conf", "Destination": "/etc/resolv.conf", "RW": False},
        ],
        "protectedSources": PROTECTED,
        "policy": POLICY,
        "allowedPaths": {"aweb": "/ready", "secrets": "/ready", "logs": "/ready", "signer": "/readyz", "registry": "/health"},
        "deniedBackends": [
            {"role": "postgres", "address": "172.31.0.6", "port": 5432},
            {"role": "redis", "address": "172.32.0.3", "port": 6379, "controlNetwork": "team_backend"},
        ],
        "protectedPaths": [],
    }


def test_the_boundary_plan_uses_the_configured_agent_identity_and_database_port():
    config = CONFIG | {"agents": CONFIG["agents"] | {"uid": 30001, "gid": 30002}, "postgres": {"port": 6543}}
    result = egress_policy.boundary_plan(
        config, POLICY, project="team", images=IMAGES, run_dir="/r", backends=BACKENDS,
        protected_sources=PROTECTED,
    )
    assert (result["uid"], result["gid"]) == (30001, 30002)
    assert result["deniedBackends"][0]["port"] == 6543


def test_a_backend_the_policy_does_not_deny_is_refused():
    with pytest.raises(egress_policy.Refused, match="redis"):
        plan(backends={"postgres": "172.31.0.6", "redis": "172.32.0.9"})


def test_a_configured_agent_ca_and_mirrors_are_approved_probe_mounts_and_the_ca_verifies_the_controls():
    config = CONFIG | {"agents": CONFIG["agents"] | {"caFile": "/srv/team/agent-ca.pem", "mirrorsDir": "/srv/team/mirrors"}}
    result = egress_policy.boundary_plan(
        config, POLICY, project="team", images=IMAGES, run_dir="/r", backends=BACKENDS,
        protected_sources=PROTECTED,
    )
    mounts = {m["Destination"]: m for m in result["approvedProbeMounts"]}
    assert mounts["/etc/agent-trust/ca.pem"] == {"Type": "bind", "Source": "/srv/team/agent-ca.pem",
                                                  "Destination": "/etc/agent-trust/ca.pem", "RW": False}
    assert mounts["/mirrors"] == {"Type": "bind", "Source": "/srv/team/mirrors", "Destination": "/mirrors", "RW": False}
    assert "/public/world-ca.pem" not in mounts
    assert result["caFile"] == "/etc/agent-trust/ca.pem"


def test_without_an_agent_ca_the_controls_use_the_public_roots():
    result = egress_policy.boundary_plan(
        CONFIG, POLICY, project="team", images=IMAGES, run_dir="/r", backends=BACKENDS, protected_sources=PROTECTED,
    )
    assert "caFile" not in result
    assert [m["Destination"] for m in result["approvedProbeMounts"]] == [
        "/state", "/etc/agent-login", "/etc/agent-ssh/authorized_keys", "/etc/resolv.conf",
    ]
