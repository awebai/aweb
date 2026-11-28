"""The old approved setting must never silently turn into unconfigured issuance."""

import pytest
from approval_service.grading import EnrollmentGrading
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.keys import KeyStore, Refused
from older_store import older_store


def approved_store(directory):
    """A version 4 holder whose operator configured approved human issuance."""
    store = older_store(directory, version=4)
    with store._connection() as db, db:
        db.execute("UPDATE configuration SET human_issuance='approved'")
    return store


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("mode", ["operator", "approved"])
def test_legacy_holder_refuses_start_with_replacement_instruction(
    tmp_path, configured, mode
):
    if mode == "approved":
        store = approved_store(tmp_path / "private")
    else:
        store = older_store(tmp_path / "private", version=4)
    values = (
        dict(
            approval_origin="https://approval.example",
            rp_id="approval.example",
            grading=EnrollmentGrading("passkey_only", None),
        )
        if configured
        else {}
    )
    with pytest.raises(Refused, match="human_approval"):
        Holder(store, registry=None, origin="https://holder.example", **values)


def test_approved_database_requires_explicit_configured_migration(tmp_path):
    from approval_service.gate import Policy

    store = approved_store(tmp_path / "private")
    descriptor = store.descriptor()
    with pytest.raises(Refused, match="human_approval"):
        KeyStore.open(store.directory)
    for policy in (None, Policy.from_section(None)):
        with pytest.raises(Refused, match="human_approval"):
            store.migrate(policy=policy)
    assert store.audit() == []
    policy = Policy.from_section(
        {
            "service": "https://approval.example",
            "require": {"organisation.human.add": "passkey"},
        }
    )
    store.migrate(policy=policy)
    reopened = KeyStore.open(store.directory)
    assert reopened.descriptor() == descriptor
    assert reopened.audit()[0]["operation"] == "human_approval_change"
    with reopened._connection() as db:
        assert db.execute("PRAGMA user_version").fetchone()[0] == 6
        assert "human_issuance" not in {
            row[1] for row in db.execute("PRAGMA table_info(configuration)")
        }


@pytest.mark.parametrize("level", ["email", "unrecognised"])
def test_rendered_but_unsupported_level_refuses_start(tmp_path, level):
    import json
    from approval_service.verify import Refused as ApprovalRefused

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    path = tmp_path / "human-approval.json"
    path.write_text(
        json.dumps(
            {
                "organisation": "example.test",
                "human_approval": {
                    "service": "https://approval.example",
                    "require": {"organisation.human.add": level},
                },
            }
        )
    )
    with pytest.raises(ApprovalRefused, match="human_approval_invalid"):
        Holder(
            store,
            registry=None,
            origin="https://holder.example",
            human_approval_config=path,
        )


def test_unknown_action_and_unreadable_source_never_enable_off(tmp_path):
    import json
    from approval_service.verify import Refused as ApprovalRefused
    from policy_inputs import policy_file

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    path = policy_file(tmp_path / "policy.json", "example.test", None)
    holder = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=path,
    )
    path.unlink()
    with pytest.raises(ApprovalRefused, match="human_approval_unavailable"):
        holder.gate()
    path.write_text(
        json.dumps(
            {
                "organisation": "example.test",
                "human_approval": {
                    "service": "https://approval.example",
                    "require": {"unknown.action": "passkey"},
                },
            }
        )
    )
    with pytest.raises(ApprovalRefused, match="human_approval_invalid"):
        Holder(
            store,
            registry=None,
            origin="https://holder.example",
            human_approval_config=path,
        )


def test_actual_legacy_cli_names_the_replacement_section(tmp_path):
    import subprocess
    import sys

    store = approved_store(tmp_path / "private")
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(store.directory),
            "--registry-origin",
            "https://registry.example",
            "--origin",
            "https://holder.example",
            "serve",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode != 0
    assert "human_approval section in deployment.yaml" in result.stderr
    assert "--human-approval-config FILE migrate" in result.stderr


def test_migrated_approved_holder_requires_source_until_explicit_empty_policy(tmp_path):
    from approval_service.canonical import parse
    from approval_service.gate import Policy
    from policy_inputs import policy_file
    import base64

    store = approved_store(tmp_path / "private")
    store.migrate(
        policy=Policy.from_section(
            {
                "service": "https://approval.example",
                "require": {"organisation.human.add": "passkey"},
            }
        )
    )
    before = store.audit()
    with pytest.raises(Refused, match="human_approval_source_required"):
        Holder(store, registry=None, origin="https://holder.example")
    assert store.audit() == before
    path = policy_file(tmp_path / "policy.json", "example.test", None)
    holder = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=path,
    )
    assert holder.gate().policy.grade("organisation.human.add") is None
    rows = store.audit()
    assert len(rows) == len(before) + 1
    prefix = b"aweb.key-holder.human-approval/1\n"
    change = parse(base64.b64decode(rows[-1]["payload"])[len(prefix) :])
    assert change["from"]["require"] == {"organisation.human.add": "passkey"}
    assert change["to"]["require"] == {}
    # Once the operator explicitly turned it off, omission is no downgrade.
    Holder(store, registry=None, origin="https://holder.example")
    assert store.audit() == rows


def test_effect_in_older_source_less_process_cannot_disable_applied_requirement(
    tmp_path,
):
    from awid.did import generate_keypair, did_from_public_key, stable_id_from_did_key
    from policy_inputs import policy_file

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    old = Holder(store, registry=None, origin="https://holder.example")
    path = policy_file(tmp_path / "policy.json", "example.test")
    Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=path,
    )
    before = store.audit()
    _, public = generate_keypair()
    key = did_from_public_key(public)
    with pytest.raises(Refused, match="human_approval_source_required"):
        old.issue_person_certificate(stable_id_from_did_key(key), key)
    assert store.audit() == before


@pytest.mark.parametrize("explicit_passkey", [False, True])
def test_hardware_requirement_refuses_passkey_only_grading_before_start(
    tmp_path, explicit_passkey
):
    from policy_inputs import policy_file

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    path = policy_file(tmp_path / "policy.json", "example.test", "hardware")
    grading = (
        {"grading": EnrollmentGrading("passkey_only", None)} if explicit_passkey else {}
    )
    with pytest.raises(Refused, match="human_approval_hardware_grading_required"):
        Holder(
            store,
            registry=None,
            origin="https://holder.example",
            human_approval_config=path,
            **grading,
        )
    assert store.audit() == []


def test_hardware_grading_is_accepted_and_live_impossible_requirement_refuses(tmp_path):
    from policy_inputs import policy_file

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    path = policy_file(tmp_path / "policy.json", "example.test")
    holder = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=path,
    )
    before = store.audit()
    policy_file(path, "example.test", "hardware")
    with pytest.raises(Refused, match="human_approval_hardware_grading_required"):
        holder.gate()
    assert store.audit() == before
    hardware = Holder(
        store,
        registry=None,
        origin="https://holder.example",
        human_approval_config=path,
        grading=EnrollmentGrading("hardware", None),
    )
    assert (
        hardware.gate().policy.grade("organisation.human.add") == "certified_hardware"
    )


def test_cli_hardware_grading_uses_policy_site_and_names_missing_cache(tmp_path):
    import subprocess
    import sys
    from policy_inputs import policy_file

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    path = policy_file(tmp_path / "policy.json", "example.test", "hardware")
    answer = subprocess.run(
        [
            sys.executable,
            "-m",
            "aweb_key_holder.cli",
            "--state",
            str(store.directory),
            "--registry-origin",
            "https://registry.example",
            "--origin",
            "https://holder.example",
            "--human-approval-config",
            str(path),
            "--grading",
            "hardware",
            "serve",
        ],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
    )
    assert answer.returncode != 0
    assert "hardware grading requires --mds-cache" in answer.stderr


@pytest.mark.parametrize("problem", ["missing_source", "hardware"])
def test_cli_policy_refusal_explains_the_operator_action(tmp_path, problem):
    import os
    import subprocess
    import sys
    from approval_service.gate import Policy
    from policy_inputs import policy_file

    if problem == "missing_source":
        store = approved_store(tmp_path / "private")
    else:
        store = KeyStore.create(tmp_path / "private", organisation="example.test")
    command = [
        sys.executable,
        "-m",
        "aweb_key_holder.cli",
        "--state",
        str(store.directory),
        "--registry-origin",
        "https://registry.example",
        "--origin",
        "https://holder.example",
    ]
    if problem == "missing_source":
        store.migrate(
            policy=Policy.from_section(
                {
                    "service": "https://approval.example",
                    "require": {"organisation.human.add": "passkey"},
                }
            )
        )
        expected = (
            "--human-approval-config FILE",
            "explicitly render an empty human_approval section",
        )
    else:
        path = policy_file(tmp_path / "policy.json", "example.test", "hardware")
        command += ["--human-approval-config", str(path)]
        expected = ("--grading hardware", "--mds-cache DIR")
    environment = dict(os.environ)
    environment.pop("HUMAN_APPROVAL_CONFIG_FILE", None)
    result = subprocess.run(
        [*command, "serve"],
        capture_output=True,
        text=True,
        check=False,
        timeout=3,
        env=environment,
    )
    assert result.returncode == 1, result.stderr
    assert all(part in result.stderr for part in expected), result.stderr
