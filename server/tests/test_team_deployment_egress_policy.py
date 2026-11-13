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


EXTERNAL = {"source": True, "model": True, "resolvers": ["9.9.9.9", "149.112.112.112"]}


def with_external(external: dict) -> dict:
    return {**CONFIG, "egress": {**CONFIG["egress"], "external": external}}


def test_the_external_roles_name_only_their_fixed_origins_and_the_operator_s_resolvers():
    policy = egress_policy.derive(with_external(EXTERNAL), PROFILE, INGRESS, [])
    assert policy["externalTargets"] == {
        "model": {"origin": "https://api.anthropic.com"},
        "source": {"origin": "https://github.com"},
    }
    assert policy["externalResolverAddresses"] == ["9.9.9.9", "149.112.112.112"]
    assert set(policy["targets"]) == {"aweb", "secrets", "logs", "signer", "registry"}


def test_a_role_left_off_is_not_an_external_target():
    policy = egress_policy.derive(with_external({"model": True, "source": False, "resolvers": ["9.9.9.9"]}),
                                  PROFILE, INGRESS, [])
    assert policy["externalTargets"] == {"model": {"origin": "https://api.anthropic.com"}}


def test_without_external_roles_the_policy_has_no_external_fields():
    for config in (CONFIG, with_external({"source": False, "model": False})):
        policy = egress_policy.derive(config, PROFILE, INGRESS, [])
        assert "externalTargets" not in policy and "externalResolverAddresses" not in policy


@pytest.mark.parametrize(
    ("external", "match"),
    [
        ({"source": True}, "egress.external.resolvers: required"),
        ({"source": True, "resolvers": []}, "egress.external.resolvers: required"),
        ({"resolvers": ["9.9.9.9"]}, "egress.external.resolvers: given without an external role"),
        ({"model": True, "resolvers": ["9.9.9.9", "9.9.9.9"]}, "distinct"),
        ({"model": True, "resolvers": ["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"]}, "one to four"),
        ({"model": True, "resolvers": ["dns.example.com"]}, "not an IPv4 address"),
        ({"model": True, "resolvers": ["2620:fe::fe"]}, "not an IPv4 address"),
        ({"model": True, "resolvers": ["10.0.0.53"]}, "not a public address"),
        ({"model": True, "resolvers": ["192.168.1.1"]}, "not a public address"),
        ({"model": True, "resolvers": ["127.0.0.53"]}, "not a public address"),
        ({"model": True, "resolvers": ["169.254.169.254"]}, "not a public address"),
        ({"model": True, "resolvers": ["224.0.0.251"]}, "not a public address"),
        ({"model": True, "resolvers": ["240.0.0.1"]}, "not a public address"),
        ({"model": True, "resolvers": ["0.0.0.0"]}, "not a public address"),
        ({"model": True, "resolvers": ["100.64.0.1"]}, "not a public address"),
    ],
)
def test_external_resolvers_are_one_to_four_distinct_public_ipv4_addresses_given_with_a_role(external, match):
    with pytest.raises(egress_policy.Refused, match=match):
        egress_policy.derive(with_external(external), PROFILE, INGRESS, [])


def test_a_resolver_cannot_be_one_of_the_deployment_s_own_addresses():
    # Public test-world addresses can stand for the deployment's own: none of
    # them is a resolver, whatever range it is in.
    ingress = {role: ["198.51.100.7"] for role in INGRESS}
    for config, denied in (
        (with_external({"model": True, "resolvers": ["198.51.100.7"]}), []),
        (with_external({"model": True, "resolvers": ["203.0.113.9"]}), ["203.0.113.9"]),
    ):
        with pytest.raises(egress_policy.Refused, match="egress.external.resolvers: .* is one of the deployment's"):
            egress_policy.derive(config, PROFILE, ingress, denied)


SERVICES = ["postgres", "redis", "aweb", "secrets", "logs", "signer", "front"]
PUBLIC_REGISTRY = {**CONFIG, "team": {"id": "devteam:example.com"}}
PUBLIC_PROFILE = {**PROFILE, "registry_origin": "https://api.awid.ai"}
PUBLIC_ADDRESSES = {**INGRESS, "registry": ["104.21.0.10", "172.67.0.10"]}


def local_route(role: str) -> dict:
    return {"path": egress_policy.ALLOWED_PATHS[role], "log": f"/logs/{role}.log"}


def test_the_public_registry_is_probed_as_an_external_route_without_a_backend_log():
    # The deployment's default registry is the public one, which is no service
    # of the deployment: its route has a positive control and no log witness.
    policy = egress_policy.derive(PUBLIC_REGISTRY, PUBLIC_PROFILE, PUBLIC_ADDRESSES, [])
    routes = egress_policy.ingress_routes(PUBLIC_REGISTRY, policy, SERVICES)
    assert routes == {
        **{role: local_route(role) for role in ("aweb", "secrets", "logs", "signer")},
        "registry": {"path": "/health", "external": True},
    }


def test_a_local_registry_route_keeps_its_backend_log():
    config = {**CONFIG, "team": {**CONFIG["team"], "registryRoute": "local"}}
    policy = egress_policy.derive(config, PROFILE, INGRESS, [])
    routes = egress_policy.ingress_routes(config, policy, [*SERVICES, "registry"])
    assert routes == {role: local_route(role) for role in egress_policy.ROLES}


def test_a_local_registry_route_needs_the_registry_service():
    # A missing local registry never becomes an external route.
    config = {**CONFIG, "team": {**CONFIG["team"], "registryRoute": "local"}}
    policy = egress_policy.derive(config, PROFILE, INGRESS, [])
    with pytest.raises(egress_policy.Refused, match="registry: .*not a service of this deployment"):
        egress_policy.ingress_routes(config, policy, SERVICES)


def test_an_external_registry_route_refuses_a_deployment_that_runs_a_registry():
    policy = egress_policy.derive(PUBLIC_REGISTRY, PUBLIC_PROFILE, PUBLIC_ADDRESSES, [])
    with pytest.raises(egress_policy.Refused, match="registry: .*external.*is a service of this deployment"):
        egress_policy.ingress_routes(PUBLIC_REGISTRY, policy, [*SERVICES, "registry"])


@pytest.mark.parametrize("address", ["172.31.0.250", "172.30.0.2", "172.31.0.3"])
def test_an_external_registry_route_refuses_an_address_of_the_deployments_own(address):
    # The front, the agents' resolver or a denied backend: a registry reached
    # there is the deployment's own, and only its log could witness it.
    policy = egress_policy.derive(PUBLIC_REGISTRY, PUBLIC_PROFILE, {**PUBLIC_ADDRESSES, "registry": [address]},
                                  ["172.31.0.3"])
    with pytest.raises(egress_policy.Refused, match=f"registry: .*{address}.*the deployment's own"):
        egress_policy.ingress_routes(PUBLIC_REGISTRY, policy, SERVICES)


@pytest.mark.parametrize("role", ["aweb", "secrets", "logs", "signer"])
def test_every_other_route_is_local_and_needs_its_service(role):
    policy = egress_policy.derive(PUBLIC_REGISTRY, PUBLIC_PROFILE, PUBLIC_ADDRESSES, [])
    with pytest.raises(egress_policy.Refused, match=f"{role}: .*not a service of this deployment"):
        egress_policy.ingress_routes(PUBLIC_REGISTRY, policy, [s for s in SERVICES if s != role])
