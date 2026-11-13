"""deploy/team's TLS front: the operator's reverse proxy for every public
origin of the deployment, rendered from deployment.yaml."""

import copy
import importlib.util
from pathlib import Path

import pytest
import yaml

TEAM = Path(__file__).resolve().parents[2] / "deploy" / "team"
EXAMPLE = yaml.safe_load((TEAM / "deployment.example.yaml").read_text(encoding="utf-8"))
FRONT = yaml.safe_load((TEAM / "compose.front.yaml").read_text(encoding="utf-8"))["services"]["front"]
IMAGE = "docker.io/library/caddy@sha256:" + "4" * 64

spec = importlib.util.spec_from_file_location("render_env", TEAM / "render_env.py")
render_env = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render_env)


def app(name: str) -> dict:
    return {
        "image": f"ghcr.io/awebai/aweb-{name}@sha256:" + "3" * 64,
        "appId": f"{name}-devteam",
        "publicOrigin": f"https://{name}.example.com",
        "consoleOrigin": f"https://{name}-console.example.com",
        "emailSmtpHost": "smtp.example.com",
        "emailFrom": f"{name}@example.com",
        "egressDeniedNetworks": ["169.254.0.0/16"],
    }


def with_front(**front) -> dict:
    return {**copy.deepcopy(EXAMPLE), "secrets": app("secrets"), "logs": app("logs"), "front": {"image": IMAGE, **front}}


def test_the_front_renders_its_image_secrets_and_public_address():
    rendered = render_env.render(with_front())
    assert {name: value for name, value in rendered.items() if name.startswith("FRONT_")} == {
        "FRONT_IMAGE": IMAGE,
        "FRONT_SECRETS": "front",
        "FRONT_BIND_ADDRESS": "0.0.0.0",
        "FRONT_PORT": "443",
    }
    assert rendered["COMPOSE_FILE"].split(":")[-1] == "compose.front.yaml"


def test_without_a_front_section_there_is_no_front():
    rendered = render_env.render({**copy.deepcopy(EXAMPLE), "secrets": app("secrets")})
    assert "compose.front.yaml" not in rendered["COMPOSE_FILE"]
    assert not [name for name in rendered if name.startswith("FRONT_")]
    with pytest.raises(render_env.Refused, match="front"):
        render_env.render_front(copy.deepcopy(EXAMPLE))


def test_the_front_serves_each_public_origin_with_the_operators_certificate_and_refuses_a_misdirected_host():
    caddyfile = render_env.render_front(with_front())
    # Caddy compares hostnames alone; a request whose Host its TLS SNI does
    # not name is refused, and each site refuses any authority but its own.
    assert caddyfile.startswith("{\n  auto_https off\n  servers {\n    strict_sni_host on\n  }\n}\n")
    sites = {
        "aweb.example.com": "aweb:8000",
        "secrets.example.com": "secrets:8770",
        "secrets-console.example.com": "secrets:8770",
        "logs.example.com": "logs:8765",
        "logs-console.example.com": "logs:8765",
    }
    for host, upstream in sites.items():
        assert (
            f"{host}:443 {{\n  tls /run/secrets/front/certificate.pem /run/secrets/front/key.pem\n"
            f"  @misdirected not header_regexp Host ^{host.replace('.', '[.]')}(:443)?$\n"
            "  respond @misdirected 421\n"
            f"  reverse_proxy {upstream}\n}}\n"
        ) in caddyfile
    assert caddyfile.count(":443 {") == len(sites)


def test_the_front_serves_the_signers_request_and_human_origins_apart(tmp_path):
    config = with_front()
    profile = tmp_path / "profile.json"
    profile.write_text(
        '{"request_origin": "https://signer.example.com", "human_origin": "https://human.example.com",'
        ' "registry_origin": "https://api.awid.ai"}'
    )
    scope = tmp_path / "scope.json"
    scope.write_text("{}")
    config["signer"] = {
        "image": "ghcr.io/awebai/aweb-protected@sha256:" + "5" * 64,
        "requestOrigin": "https://signer.example.com",
        "humanOrigin": "https://human.example.com",
        "profileFile": str(profile),
        "scopeFile": str(scope),
        "workerUids": [20001],
        "emailFrom": "signer@example.com",
        "emailSmtpHost": "smtp.example.com",
        "emailSmtpPort": 587,
        "emailUsername": "signer",
    }
    caddyfile = render_env.render_front(config)
    for host in ("signer.example.com", "human.example.com"):
        assert f"{host}:443 {{\n" in caddyfile
        assert f"@misdirected not header_regexp Host ^{host.replace('.', '[.]')}(:443)?$\n" in caddyfile
    assert caddyfile.count("reverse_proxy signer:8080\n") == 2


def test_an_origin_on_another_port_is_refused():
    config = with_front()
    config["aweb"]["publicOrigin"] = "https://aweb.example.com:8443"
    with pytest.raises(render_env.Refused, match="aweb.publicOrigin"):
        render_env.render_front(config)


def test_the_front_runs_the_pinned_image_with_its_certificate_and_rendered_configuration_read_only():
    assert FRONT["image"] == "${FRONT_IMAGE:?FRONT_IMAGE is required, front.image}"
    assert FRONT["networks"] == ["services"]
    assert FRONT["ports"] == ["${FRONT_BIND_ADDRESS:-0.0.0.0}:${FRONT_PORT:-443}:443"]
    assert FRONT["volumes"] == [
        "${SECRETS_DIR:?SECRETS_DIR is required, compose.secretsDir}/${FRONT_SECRETS:-front}:/run/secrets/front:ro",
        "${FRONT_CONFIG_DIR:?FRONT_CONFIG_DIR is required; teamctl writes it}:/etc/caddy:ro",
    ]
    assert FRONT["read_only"] is True
    assert "environment" not in FRONT
