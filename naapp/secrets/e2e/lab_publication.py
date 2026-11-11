"""Certify selected BYOT actors and publish an owned lab prerequisite snapshot.

Uses the real CLI's local certificate/signing-key checks and the runtime's
current-membership and signed team-server verifiers. No service credentials,
private keys, domain records, services or runners are created here.
"""

from __future__ import annotations

import asyncio
import json
import os
import tempfile
import time
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx
import yaml
from aweb_naapp.runtime.team_auth import AWIDTeamCache, require_active_certificate
from aweb_naapp.runtime.team_server import TeamServerDirectory
from awid.dns_verify import verify_domain
from awid.id_certificates import IDChainEvidence, status_request, verify_id_chain
from awid.registry import RegistryClient
from awid.team_certificate import verify_team_certificate_signature
from lab_environment import (
    ACTORS,
    PREFIX,
    LabConfigurationError,
    PrivateDNS,
    load_lab_environment,
    runner_uid,
)

from aweb_secrets.principal import is_did_aw, is_did_key

_CHECKS = (
    "local.workspace_yaml.parse",
    "local.workspace.aweb_url_syntax",
    "local.workspace.active_membership",
    "local.team_certificate.parse",
    "local.team_certificate.team_matches_workspace",
    "local.team_certificate.signature_valid",
    "local.signing_key.matches_certificate",
)


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.path.rstrip("/") not in ("", "/api") or parsed.query or parsed.fragment:
        raise ValueError
    if parsed.username is not None or parsed.password is not None or parsed.scheme != "https":
        raise ValueError
    host = (parsed.hostname or "").lower().rstrip(".")
    if not host:
        raise ValueError
    return f"https://{host}:{parsed.port or 443}"


def _metadata(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    value = yaml.safe_load(path.read_text())
    if not isinstance(value, dict):
        raise ValueError
    return value


async def _local_actor(environment: Mapping[str, str], actor: str) -> dict[str, Any]:
    __tracebackhide__ = True
    name = PREFIX + actor + "_IDENTITY_HOME"
    home = Path(environment[name])
    # Do not inherit this agent's identity, API key, proxy or dotenv authority.
    child_env = {
        "PATH": os.defpath,
        "LANG": "en_US.UTF-8",
        "AW_NO_UPDATE_CHECK": "1",
        "GOMAXPROCS": "2",
    }
    if "HOME" in os.environ:
        child_env["HOME"] = os.environ["HOME"]
    child_env["AWID_REGISTRY_URL"] = environment[PREFIX + "AWID_REGISTRY_URL"]
    command = (
        environment[PREFIX + "AW_BINARY"],
        "--identity-home",
        str(home),
        "--team",
        environment[PREFIX + "TEAM_ID"],
        "--json",
        "doctor",
        "local",
        "--offline",
    )
    # No inherited checkout dotenv/workspace. The CLI itself selects the home.
    with tempfile.TemporaryDirectory(prefix="aweb-lab-check-") as directory:
        process = await asyncio.create_subprocess_exec(
            *command,
            cwd=directory,
            env=child_env,
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            output, _ = await process.communicate()
        finally:
            if process.returncode is None:
                process.kill()
                await process.wait()
    if process.returncode != 0:
        raise ValueError
    report = json.loads(output)
    if report["version"] != "doctor.v1":
        raise ValueError
    checks = {check["id"]: check for check in report["checks"]}
    if any(checks[name]["status"] != "ok" for name in _CHECKS):
        raise ValueError
    subject = report["subject"]
    team = environment[PREFIX + "TEAM_ID"]
    if subject["team_id"] != team or _origin(subject["aweb_url"]) != _origin(
        environment[PREFIX + "COORDINATION_ORIGIN"]
    ):
        raise ValueError
    # Selection may prefer identity.yaml over the registry environment. Compare
    # public metadata without ever opening the key/credential files in Python.
    registry = _origin(environment[PREFIX + "AWID_REGISTRY_URL"])
    workspace = _metadata(home / "workspace.yaml")
    if _origin(workspace["aweb_url"]) != _origin(environment[PREFIX + "COORDINATION_ORIGIN"]):
        raise ValueError
    identity = _metadata(home / "identity.yaml")
    if identity.get("registry_url") and _origin(identity["registry_url"]) != registry:
        raise ValueError
    teams = _metadata(home / "teams.yaml")
    membership = next(item for item in teams["memberships"] if item["team_id"] == team)
    if membership.get("registry_url") and _origin(membership["registry_url"]) != registry:
        raise ValueError
    if membership.get("aweb_url") and _origin(membership["aweb_url"]) != _origin(
        subject["aweb_url"]
    ):
        raise ValueError
    cert_path = Path(checks["local.team_certificate.exists"]["target"]["id"])
    if not cert_path.resolve().is_relative_to(home.resolve()):
        raise ValueError
    certificate = json.loads(cert_path.read_text())
    if certificate["team_id"] != team or not is_did_key(certificate["member_did_key"]):
        raise ValueError
    return certificate


async def _public_human(
    environment: Mapping[str, str], registry_transport: httpx.AsyncBaseTransport | None
) -> dict[str, Any]:
    """Verify public protected-human facts, without probing or unlocking custody.

    HumanRecordDir is independent of every agent home. The foreground human
    signer/keychain resolver is never called here; signing readiness can only
    be demonstrated by the rehearsal's actual protected human gesture.
    """
    __tracebackhide__ = True
    name = PREFIX + "HUMAN_IDENTITY_HOME"
    home = Path(environment[name])
    try:
        record = _metadata(home / "identity.yaml")
        stable, did, domain = record["stable_id"], record["did_key"], record["domain"]
        if not is_did_aw(stable) or not is_did_key(did):
            raise ValueError
        # Same public directory rule as awconfig.HumanRecordDir/NormalizeDomain.
        if not isinstance(domain, str) or not domain or "/" in domain or "\\" in domain:
            raise ValueError
        domain = domain.strip().lower().rstrip(".")
        canonical = Path.home() / ".awid" / "humans" / domain / stable[7:]
        if home.resolve() != canonical.resolve() or record["state"] != "registered":
            raise ValueError
        registry_url = environment[PREFIX + "AWID_REGISTRY_URL"]
        if _origin(record["registry_url"]) != _origin(registry_url):
            raise ValueError
        team = environment[PREFIX + "TEAM_ID"]
        membership = next(
            item
            for item in _metadata(home / "teams.yaml")["memberships"]
            if item["team_id"] == team
        )
        if _origin(membership["aweb_url"]) != _origin(environment[PREFIX + "COORDINATION_ORIGIN"]):
            raise ValueError
        if membership.get("registry_url") and _origin(membership["registry_url"]) != _origin(
            registry_url
        ):
            raise ValueError
        path = home / membership["cert_path"]
        if not path.resolve().is_relative_to(home.resolve()):
            raise ValueError
        certificate = json.loads(path.read_text())
        if (
            certificate["team_id"],
            certificate["member_did_aw"],
            certificate["member_did_key"],
        ) != (team, stable, did):
            raise ValueError
        bundle = json.loads((home / "id-chain.json").read_text())
        subject = {"id": stable, "did_key": did}
        request = status_request(bundle, subject, domain=domain)
    except Exception:
        raise LabConfigurationError({name}, "lab_human_record_invalid") from None

    started = time.monotonic()
    client = RegistryClient(registry_url=registry_url, transport=registry_transport)
    try:
        authority = await verify_domain(domain)
        if authority.registry_explicit and _origin(authority.registry_url) != _origin(registry_url):
            raise LabConfigurationError({name}, "lab_human_registry_mismatch")
        status = await client.fetch_id_certificate_status(domain, request)
    except LabConfigurationError:
        raise
    except Exception:
        raise LabConfigurationError({name}, "lab_human_identity_unavailable") from None
    finally:
        await client.aclose()
    result = verify_id_chain(
        bundle,
        subject=subject,
        domain=domain,
        evidence=IDChainEvidence(
            status=status,
            namespace_authority={
                "domain": domain,
                "dns_name": authority.dns_name,
                "inherited": authority.inherited,
                "controller_key": authority.controller_did,
            },
            age_seconds=time.monotonic() - started,
        ),
    )
    if (
        result["identity_valid"] is not True
        or result["kind"] != "human"
        or result["human_id"] != stable
    ):
        reason = (
            "lab_human_identity_unavailable"
            if result["outcome"] == "unavailable"
            else "lab_human_identity_invalid"
        )
        raise LabConfigurationError({name}, reason)
    return certificate


async def _certify_lab_actors(
    environment: Mapping[str, str], *, registry_transport: httpx.AsyncBaseTransport | None = None
) -> dict[str, dict[str, str]]:
    """Fresh prerequisite evidence, never an installation/resource grant.

    registry_transport lets the owning S19 context use its real AWID app over
    an in-process transport, just as the production runtime supports. No
    authority callback or fabricated actor result is accepted.
    """
    __tracebackhide__ = True
    registry_url = environment[PREFIX + "AWID_REGISTRY_URL"]
    cache = AWIDTeamCache(registry_url=registry_url, ttl_seconds=60, transport=registry_transport)

    async def selected_registry(_domain: str) -> str:
        # This single-customer profile explicitly pins one registry. The
        # signed team-server record is still verified under its current key.
        return registry_url

    directory = TeamServerDirectory(
        team_cache=cache,
        transport=registry_transport,
        registry_override=selected_registry,
    )
    actors = {}
    deadline = asyncio.get_running_loop().time() + 30
    for actor in ACTORS:
        name = PREFIX + actor + "_IDENTITY_HOME"
        try:
            async with asyncio.timeout_at(deadline):
                certificate = (
                    await _public_human(environment, registry_transport)
                    if actor == "HUMAN"
                    else await _local_actor(environment, actor)
                )
                team, cid = certificate["team_id"], certificate["certificate_id"]
                facts = await require_active_certificate(cache, team_id=team, certificate_id=cid)
                verify_team_certificate_signature(certificate, facts.team_did_key)
                server = await directory.resolve(team, cid)
                if _origin(server.server_url) != _origin(
                    environment[PREFIX + "COORDINATION_ORIGIN"]
                ):
                    raise ValueError
                did = certificate["member_did_key"]
                stable = certificate.get("member_did_aw")
                if stable and (not is_did_aw(stable) or await cache.current_did_key(stable) != did):
                    raise ValueError
                actors[actor] = {
                    "principal_did": stable or did,
                    "did_key": did,
                    "certificate_id": cid,
                }
                if actor == "HUMAN":
                    actors[actor].update(custody="not_tested", signing_readiness="not_tested")
        except LabConfigurationError:
            raise
        except Exception:
            raise LabConfigurationError({name}, "lab_actor_unverified") from None
    if len({value["principal_did"] for value in actors.values()}) != len(ACTORS) or len(
        {value["did_key"] for value in actors.values()}
    ) != len(ACTORS):
        raise LabConfigurationError(
            {PREFIX + actor + "_IDENTITY_HOME" for actor in ACTORS},
            "lab_actors_not_distinct",
        )
    return actors


@asynccontextmanager
async def publish_lab_runtime(
    inputs: Mapping[str, str],
    *,
    directory: Path,
    private_dns: PrivateDNS,
    registry_transport: httpx.AsyncBaseTransport | None = None,
) -> AsyncIterator[Path]:
    """Publish only this lab snapshot, after reference and current actor checks.

    Does not claim KMS/runner/scenario success. S19 must still start and verify
    the actual separate-user worker and execute the selected real scenarios.
    """
    __tracebackhide__ = True
    environment = load_lab_environment(inputs, private_dns=private_dns)
    if not isinstance(directory, Path) or not directory.is_absolute() or ".." in directory.parts:
        raise LabConfigurationError(set(), "lab_publication_invalid")
    actors = await _certify_lab_actors(environment, registry_transport=registry_transport)
    body = {
        "profile": "byot-native-lab/1",
        "custody_mode": environment[PREFIX + "CUSTODY_MODE"],
        "inputs": dict(environment),
        "actors": actors,
        "runner_uid": runner_uid(environment),
        "coverage": {
            "private_address_refusal": private_dns,
            "full_release_gate": False,
            "custody": {
                mode: "not_tested" if mode == environment[PREFIX + "CUSTODY_MODE"] else "excluded"
                for mode in ("kms", "local_key_file")
            },
        },
    }
    path = directory / "runtime.json"
    try:
        directory.mkdir(mode=0o700)
    except OSError:
        raise LabConfigurationError(set(), "lab_publication_unavailable") from None
    try:
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(body, stream, sort_keys=True)
                stream.write("\n")
        except OSError:
            raise LabConfigurationError(set(), "lab_publication_unavailable") from None
        yield path
    finally:
        path.unlink(missing_ok=True)
        directory.rmdir()
