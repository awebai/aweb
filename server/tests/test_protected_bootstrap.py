"""No-I/O operator input and existing ceremony/page constructor checks."""

import pytest
from fastapi import FastAPI
from httpx import ASGITransport, AsyncClient

from aweb.protected_signing.bootstrap import bootstrap_router, operator_inputs
from aweb_naapp.runtime.protected_signer import SignerRefused


def test_operator_inputs_keep_explicit_registered_requester_and_contact():
    assert operator_inputs(
        "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", "operator@example.test"
    )


@pytest.mark.parametrize(
    "requester,contact",
    [
        ("did:key:z6MkOther", "operator@example.test"),
        ("did:aw:bad", "operator@example.test"),
        ("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", "x\nBcc:other@example.test"),
        ("did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", ""),
    ],
)
def test_operator_inputs_refuse_malformed_or_non_stable_identity(requester, contact):
    with pytest.raises(SignerRefused):
        operator_inputs(requester, contact)


@pytest.mark.asyncio
async def test_shared_enrollment_page_and_packaged_script_are_served():
    # Constructor/asset proof only: no database, passkey or authority is mocked
    # into a successful enrollment. Native tests exercise the real ceremony.
    from types import SimpleNamespace

    class Composition:
        passkeys = object()
        context = SimpleNamespace(
            human_id="did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
            authority_id="engineering:customer.example",
        )

    app = FastAPI()
    app.include_router(
        bootstrap_router(Composition(), csrf_key="aweb.protected.console.csrf")
    )
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="https://human.example"
    ) as client:
        page = await client.get("/enrolment")
        assert page.status_code == 200
        assert 'data-ceremony="enrolment"' in page.text
        assert "#token=" not in page.text
        script = await client.get("/console-bootstrap/bootstrap.js")
        assert script.status_code == 200
        assert "navigator.credentials.create" in script.text
        assert (await client.post("/enrolment", json={})).status_code == 400
        assert (await client.get("/contact-proof")).status_code == 404
        assert Composition.context.human_id in page.text


def test_install_existing_controller_checks_profile_and_never_overwrites(tmp_path):
    import base64
    import json

    from awid.did import did_key_from_signing_key, generate_keypair
    from aweb.protected_signing.operator import install_controller
    from aweb.protected_signing.profile import ProtectedServiceProfile
    from tests.test_protected_signer_host import settings

    seed, _ = generate_keypair()
    config = settings(tmp_path)
    private = config.controller_key_file.parent
    private.mkdir(mode=0o700)
    raw = json.loads(config.profile_file.read_bytes())
    raw["bindings"][0]["authority_key_did"] = did_key_from_signing_key(seed)
    profile = ProtectedServiceProfile.from_json(json.dumps(raw).encode())
    scope = raw["bindings"][0]["scope"]
    source = tmp_path / "controller.pem"
    source.write_bytes(
        b"-----BEGIN ED25519 PRIVATE KEY-----\n"
        + base64.b64encode(seed)
        + b"\n-----END ED25519 PRIVATE KEY-----\n"
    )
    source.chmod(0o400)
    result = install_controller(config, profile=profile, scope=scope, source_pem=source)
    assert result == {"authority_key_did": raw["bindings"][0]["authority_key_did"]}
    assert config.controller_key_file.read_text() == seed.hex() + "\n"
    assert config.controller_key_file.stat().st_mode & 0o777 == 0o400
    with pytest.raises(FileExistsError):
        install_controller(config, profile=profile, scope=scope, source_pem=source)
    config.controller_key_file.unlink()
    # A symlink is never a way to overwrite a second copy of the key.
    target = tmp_path / "untouched"
    target.write_text("untouched")
    config.controller_key_file.symlink_to(target)
    with pytest.raises(FileExistsError):
        install_controller(config, profile=profile, scope=scope, source_pem=source)
    assert target.read_text() == "untouched"
    config.controller_key_file.unlink()
    private.chmod(0o755)
    with pytest.raises(SignerRefused, match="custody_not_isolated"):
        install_controller(config, profile=profile, scope=scope, source_pem=source)
    assert not config.controller_key_file.exists()
    private.chmod(0o700)
    raw["bindings"][0]["authority_key_did"] = did_key_from_signing_key(
        generate_keypair()[0]
    )
    with pytest.raises(SignerRefused, match="authority_changed"):
        install_controller(
            config,
            profile=ProtectedServiceProfile.from_json(json.dumps(raw).encode()),
            scope=scope,
            source_pem=source,
        )
    assert not config.controller_key_file.exists()


def test_operator_help_exposes_only_local_actions():
    from aweb.protected_signing.operator import parser

    command = parser()
    args = command.parse_args(
        [
            "bootstrap",
            "--requester",
            "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w",
            "--contact",
            "operator@example.test",
        ]
    )
    assert args.command == "bootstrap"
    assert "install-controller" in command.format_help()


def test_operator_error_never_echoes_private_exception(monkeypatch, capsys):
    from aweb.protected_signing import operator

    monkeypatch.setattr("sys.argv", ["operator", "check"])

    def fail():
        raise RuntimeError("postgresql://private:SYNTH_PASSWORD@host/db")

    monkeypatch.setattr(operator, "HostSettings", fail)
    with pytest.raises(SystemExit):
        operator.main()
    captured = capsys.readouterr()
    assert "SYNTH_PASSWORD" not in captured.out + captured.err
    assert "protected_operator_failed" in captured.out


def test_operator_setup_flags_name_every_input_with_the_documented_defaults(tmp_path):
    from aweb.protected_signing.operator import parser, setup_inputs

    args = parser().parse_args([
        "setup", "--config-dir", str(tmp_path / "signer"), "--team", "engineering:customer.example",
        "--human", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", "--requester", "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8x",
        "--contact", "operator@customer.example", "--human-origin", "https://human.customer.example",
        "--request-origin", "https://signer.customer.example", "--registry-origin", "https://registry.customer.example",
        "--controller-pem", str(tmp_path / "team.pem"), "--member-pem", str(tmp_path / "member.pem"),
        "--max-active", "5", "--max-per-window", "10",
    ])
    inputs = setup_inputs(args)
    assert inputs.service_id == "human.customer.example"
    assert inputs.human_domain == "customer.example"
    assert inputs.rate_window_seconds == 3600
    assert inputs.subject_kinds == ("local_agent", "registered_agent")
    assert inputs.confirm_pins is None
    assert inputs.config_dir == tmp_path / "signer"
    assert "setup" in parser().format_help()
