"""The old approved setting must never silently turn into unconfigured issuance."""

import pytest
from approval_service.grading import EnrollmentGrading
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.keys import KeyStore, Refused


@pytest.mark.parametrize("configured", [False, True])
@pytest.mark.parametrize("mode", ["operator", "approved"])
def test_legacy_holder_refuses_start_with_replacement_instruction(
    tmp_path, configured, mode
):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    # The actual persisted setting used by the previous version, not a mocked
    # policy source. Keep its upgrade behavior even after the column retires.
    with store._connection() as db, db:
        names = {row[1] for row in db.execute("PRAGMA table_info(configuration)")}
        if "human_issuance" not in names:
            db.execute("ALTER TABLE configuration ADD COLUMN human_issuance TEXT")
        db.execute("UPDATE configuration SET human_issuance=?", (mode,))
        db.execute("PRAGMA user_version=4")
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

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    descriptor = store.descriptor()
    with store._connection() as db, db:
        db.execute(
            "ALTER TABLE configuration ADD COLUMN human_issuance TEXT NOT NULL DEFAULT 'approved'"
        )
        db.execute("PRAGMA user_version=4")
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
        assert db.execute("PRAGMA user_version").fetchone()[0] == 5
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

    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    with store._connection() as db, db:
        db.execute(
            "ALTER TABLE configuration ADD COLUMN human_issuance TEXT DEFAULT 'approved'"
        )
        db.execute("PRAGMA user_version=4")
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
