"""One operator command from the registry's current facts to a ready signer.

Real customer AWID/PG, the real custody checks and the production bootstrap
and policy commands; only outbound mail is captured.
"""

import base64
import json
import os
from dataclasses import replace

import pytest
from aweb_naapp.runtime.protected_signer import SignerRefused

from urllib.parse import parse_qs, urlsplit

from aweb.protected_signing.bootstrap import prepare_completion
from aweb.protected_signing.host import open_composition
from aweb.protected_signing.profile import ProtectedServiceProfile
from aweb.protected_signing.setup import SetupInputs, host_settings, setup
from tests.test_independent_protected_signer import HUMAN_ORIGIN, ORIGIN, TEAM, did
from tests.test_protected_bootstrap_native import empty_authority
from tests.test_protected_signer_host import CapturedMail

pytest_plugins = ("tests.test_independent_protected_signer",)
CONTACT = "operator@customer.example"


def pem(path, key):
    path.write_bytes(b"-----BEGIN ED25519 PRIVATE KEY-----\n" + base64.b64encode(bytes(key))
        + b"\n-----END ED25519 PRIVATE KEY-----\n")
    path.chmod(0o400)
    return path


def inputs_for(w, tmp_path, **changes):
    private = tmp_path / "provisioning"
    private.mkdir(mode=0o700, exist_ok=True)
    config = tmp_path / "signer"
    return replace(SetupInputs(
        config_dir=config, service_id="customer-signer", team_id=TEAM,
        human_id=w.context.human_id, human_domain=w.context.human_domain,
        requester=w.root_id, contact=CONTACT,
        human_origin=HUMAN_ORIGIN, request_origin=ORIGIN, registry_origin=w.registry.registry_url,
        controller_pem=pem(private / "team.pem", w.controller) if not (private / "team.pem").exists() else private / "team.pem",
        member_pem=pem(private / "member.pem", w.root) if not (private / "member.pem").exists() else private / "member.pem",
        max_active=5, rate_window_seconds=3600, max_per_window=10,
        subject_kinds=("local_agent", "registered_agent"), confirm_pins=None,
    ), **changes)


def host_environment(w, tmp_path):
    secrets = tmp_path / "secrets"
    secrets.mkdir(mode=0o700, exist_ok=True)
    url = secrets / "database-url"
    if not url.exists():
        url.write_text(w.db.config.get_dsn() + "\n")
        url.chmod(0o400)
    return {"database_url_file": url, "database_schema": w.db.schema,
        "worker_uids": [65534 if os.geteuid() != 65534 else 65533]}


@pytest.mark.asyncio
async def test_one_command_takes_a_registered_team_to_a_ready_signer(world, tmp_path):
    w = world
    await empty_authority(w)
    await w.db.execute("TRUNCATE {{tables.protected_admission_policies}}")
    mail = CapturedMail()
    run = lambda inputs: setup(inputs, host=host_environment(w, tmp_path), mailer=mail,
        registry_transport=w.host.transport)

    # Without confirmation the registry's pins are shown and nothing is written.
    shown = await run(inputs_for(w, tmp_path))
    assert shown["state"] == "confirm_pins"
    assert shown["pins"]["team_controller"] == did(w.controller)
    assert shown["pins"]["namespace_controllers"] == w.registry.namespace_keys
    assert not (tmp_path / "signer").exists() and mail.messages == []

    confirmed = inputs_for(w, tmp_path, confirm_pins=shown["confirm_pins"])
    waiting = await run(confirmed)
    assert waiting["state"] == "awaiting_enrolment", waiting
    config = tmp_path / "signer"
    profile = ProtectedServiceProfile.from_json((config / "protected-profile.json").read_bytes())
    assert [b.authority_key_did for b in profile.bindings] == [did(w.controller)]
    assert profile.bindings[0].scope.human.id == w.context.human_id
    assert (config / "keys").stat().st_mode & 0o777 == 0o700
    assert [m.to for m in mail.messages] == [CONTACT]
    policy = waiting["admission_policy"]
    assert policy["teams"] == [TEAM] and policy["bounds"] == {"max_active": 5, "rate_window_seconds": 3600, "max_per_window": 10}
    # The host runs from exactly the files setup wrote.
    env = dict(line.split("=", 1) for line in (config / "host.env").read_text().splitlines() if line)
    assert env["AWEB_PROTECTED_PROFILE_FILE"] == str(config / "protected-profile.json")
    assert not any(k.startswith("AWEB_PROTECTED_DATABASE_URL") and not k.endswith("_FILE") for k in env)
    # Nothing secret is in setup's answer.
    assert bytes(w.controller).hex() not in json.dumps(waiting, default=str)

    # Rerun before enrolment: the same pending person gets the link again.
    again = await run(confirmed)
    assert again["state"] == "awaiting_enrolment" and again["admission_policy"] == policy
    assert [m.to for m in mail.messages] == [CONTACT, CONTACT]

    # The person creates their passkey from the mailed link.
    token = parse_qs(urlsplit(next(word for word in mail.messages[-1].text.split()
        if word.startswith(HUMAN_ORIGIN + "/enrolment#"))).fragment)["token"][0]
    async with open_composition(host_settings(config, host_environment(w, tmp_path)), profile=profile,
            scope=profile.bindings[0].scope.model_dump(mode="json"), mailer=mail,
            registry_transport=w.host.transport) as c:
        attestation = w.device.create(await c.passkeys.enrolment_options(token))
        await c.passkeys.complete_enrolment(token, attestation, fence=await prepare_completion(c, token))

    # The same command now finds a ready signer, and mails nobody.
    ready = await run(confirmed)
    assert ready["state"] == "ready", ready
    assert ready["admission_policy"] == policy and len(mail.messages) == 2

    # Changed inputs never overwrite what is there.
    with pytest.raises(SignerRefused, match="setup_conflict"):
        await run(inputs_for(w, tmp_path, confirm_pins=shown["confirm_pins"], max_active=6))
    assert ProtectedServiceProfile.from_json((config / "protected-profile.json").read_bytes()) == profile


@pytest.mark.asyncio
async def test_pins_that_change_after_they_were_shown_are_refused(world, tmp_path):
    w = world
    await empty_authority(w)
    shown = await setup(inputs_for(w, tmp_path), host=host_environment(w, tmp_path), mailer=CapturedMail(),
        registry_transport=w.host.transport)
    with pytest.raises(SignerRefused, match="authority_changed"):
        await setup(inputs_for(w, tmp_path, confirm_pins="0" * 16), host=host_environment(w, tmp_path),
            mailer=CapturedMail(), registry_transport=w.host.transport)
    assert shown["confirm_pins"] != "0" * 16
    assert not (tmp_path / "signer").exists()
