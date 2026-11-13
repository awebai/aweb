"""One operator command from a registered team to a ready protected signer.

It composes the existing local administrator actions in their order: read the
registry's current public keys and show them for the operator to confirm,
write the profile/scope/manifests, install the existing controller key,
record the first approver (B3 mails their enrolment link) and provision the
one initial admission policy. Once that person has created their passkey, the
same command checks the whole provisioning and reports the signer ready.

Every step is the existing command's code with its own checks. Nothing is
overwritten: a file that exists must hold exactly what setup would write.
"""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from pathlib import Path

from aweb_naapp.key_file import read_key_file
from aweb_naapp.runtime.protected_signer import SignerRefused
from awid.did import did_key_from_signing_key
from awid.registry import RegistryClient
from awid.signing import canonical_json_bytes, load_signing_key_pem
from awid.team_ids import parse_team_id

from .host import HostSettings, open_composition, validate_provisioning
from .profile import ProtectedServiceProfile

PROFILE, SCOPE, MEMBERS, POLICY, ENV = (
    "protected-profile.json", "protected-scope.json", "members.json", "admission-policy.json", "host.env")
CONTROLLER_KEY = "keys/team-controller.key"


@dataclass(frozen=True)
class SetupInputs:
    config_dir: Path
    service_id: str
    team_id: str
    human_id: str
    human_domain: str
    requester: str
    contact: str
    human_origin: str
    request_origin: str
    registry_origin: str
    controller_pem: Path
    member_pem: Path
    max_active: int
    rate_window_seconds: int
    max_per_window: int
    subject_kinds: tuple[str, ...]
    confirm_pins: str | None


def host_settings(config_dir: Path, host: dict) -> HostSettings:
    """The serving host's settings for the files setup writes; ``host`` (or
    the AWEB_PROTECTED_* environment) supplies database and worker settings."""
    return HostSettings(profile_file=config_dir / PROFILE, scope_file=config_dir / SCOPE,
        controller_key_file=config_dir / CONTROLLER_KEY, member_keys_file=config_dir / MEMBERS, **host)


async def read_pins(inputs: SetupInputs, *, member_key, registry_transport=None) -> dict:
    """The registry's current public keys this signer will pin."""
    domain, name = parse_team_id(inputs.team_id)
    registry = RegistryClient(registry_url=inputs.registry_origin, transport=registry_transport,
        member_signing_keys={inputs.team_id: member_key})
    try:
        team_key = await registry.get_team_public_key_fresh(domain, name, registry_origin=inputs.registry_origin)
        namespaces = {}
        for namespace in sorted({domain, inputs.human_domain}):
            found = await registry.get_namespace_fresh(namespace, registry_origin=inputs.registry_origin)
            if found is None or not found.controller_did:
                raise SignerRefused("authority_changed")
            namespaces[namespace] = found.controller_did
    finally:
        await registry.aclose()
    if team_key is None:
        raise SignerRefused("authority_changed")
    return {"team_controller": team_key, "namespace_controllers": namespaces}


def pins_fingerprint(pins: dict) -> str:
    return hashlib.sha256(canonical_json_bytes(pins)).hexdigest()[:16]


def profile_fields(inputs: SetupInputs, pins: dict) -> dict:
    domain, _ = parse_team_id(inputs.team_id)
    scope = {"v": 1, "kind": "protected_key", "service_id": inputs.service_id,
        "authority": {"kind": "team_controller", "id": inputs.team_id, "domain": domain},
        "human": {"id": inputs.human_id, "domain": inputs.human_domain}, "generation": 1}
    rp_id = inputs.human_origin.removeprefix("https://").split("/")[0].split(":")[0]
    return {"v": 1, "service_id": inputs.service_id, "request_origin": inputs.request_origin,
        "human_origin": inputs.human_origin, "rp_id": rp_id, "registry_origin": inputs.registry_origin,
        "namespace_authorities": [{"domain": d, "controller_did": k} for d, k in pins["namespace_controllers"].items()],
        "bindings": [{"scope": scope, "authority_key_did": pins["team_controller"],
            "policy": {"ref": "aweb.human-assurance/1", "version": 1}}]}


def _write_once(path: Path, data: bytes, mode: int = 0o600) -> None:
    """Create path with data, or accept exactly the same bytes already there."""
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    except FileExistsError:
        if path.is_symlink() or path.read_bytes() != data:
            raise SignerRefused("setup_conflict") from None
        return
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())


def _private_dir(path: Path) -> None:
    path.mkdir(mode=0o700, exist_ok=True)
    if path.is_symlink() or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o777 != 0o700:
        raise SignerRefused("custody_not_isolated")


def _env_file(settings: HostSettings) -> bytes:
    lines = {
        "AWEB_PROTECTED_PROFILE_FILE": settings.profile_file,
        "AWEB_PROTECTED_SCOPE_FILE": settings.scope_file,
        "AWEB_PROTECTED_CONTROLLER_KEY_FILE": settings.controller_key_file,
        "AWEB_PROTECTED_MEMBER_KEYS_FILE": settings.member_keys_file,
    }
    return "".join(f"{key}={value}\n" for key, value in lines.items()).encode()


async def setup(inputs: SetupInputs, *, host: dict | None = None, mailer=None, registry_transport=None) -> dict:
    from .admission import provision_policy
    from .bootstrap import initialise
    from .operator import install_controller

    host = {} if host is None else host
    member_key = load_signing_key_pem(read_key_file(inputs.member_pem))
    pins = await read_pins(inputs, member_key=member_key, registry_transport=registry_transport)
    fingerprint = pins_fingerprint(pins)
    if inputs.confirm_pins is None:
        return {"state": "confirm_pins", "pins": pins, "confirm_pins": fingerprint}
    if inputs.confirm_pins != fingerprint:
        # The keys changed since the operator checked them, or never matched.
        raise SignerRefused("authority_changed")
    seed = load_signing_key_pem(read_key_file(inputs.controller_pem))
    if did_key_from_signing_key(seed) != pins["team_controller"]:
        raise SignerRefused("authority_changed")

    profile_raw = canonical_json_bytes(profile_fields(inputs, pins))
    profile = ProtectedServiceProfile.from_json(profile_raw)
    binding = profile.bindings[0]
    scope = binding.scope.model_dump(mode="json")
    policy = {"version": 1, "teams": [inputs.team_id],
        "root_selector": {"kind": "service_endorsed_root", "service_id": inputs.service_id},
        "subject_kinds": sorted(inputs.subject_kinds), "member_role": "member",
        "bounds": {"max_active": inputs.max_active, "rate_window_seconds": inputs.rate_window_seconds,
            "max_per_window": inputs.max_per_window}}

    config = inputs.config_dir
    _private_dir(config)
    _private_dir(config / "keys")
    settings = host_settings(config, host)
    for name, data in ((PROFILE, profile_raw), (SCOPE, canonical_json_bytes(scope)),
            (MEMBERS, canonical_json_bytes({inputs.team_id: str(inputs.member_pem.resolve())})),
            (POLICY, canonical_json_bytes(policy)), (ENV, _env_file(settings))):
        _write_once(config / name, data)
    if settings.controller_key_file.exists():
        if settings.controller_key_file.read_text() != seed.hex() + "\n":
            raise SignerRefused("setup_conflict")
    else:
        install_controller(settings, profile=profile, scope=scope, source_pem=inputs.controller_pem)

    async with open_composition(settings, profile=profile, scope=scope, mailer=mailer,
            registry_transport=registry_transport) as c:
        from aweb_naapp.console import apply_console_migrations

        await c.migrate()
        await apply_console_migrations(c.db)
        try:
            await validate_provisioning(c)
        except SignerRefused:
            # No enrolled approver yet: record (or resend) the first one.
            delivery = await initialise(c, requester=inputs.requester, contact=inputs.contact)
            provisioned = await provision_policy(c, policy)
            return {"state": "awaiting_enrolment", "pins": pins, "admission_policy": provisioned,
                "delivery": delivery.get("delivery"), "env_file": str(config / ENV)}
        provisioned = await provision_policy(c, policy)
    return {"state": "ready", "pins": pins, "admission_policy": provisioned, "env_file": str(config / ENV)}
