"""Actual private storage, Ed25519 signatures, encrypted backup and audit writes."""

import json
import os
import sqlite3
import subprocess
from dataclasses import asdict, replace

import pytest
from aweb_key_holder.keys import KeyStore, Refused
from awid.controller_signing import (
    ControllerSigningContext,
    parse_controller_object,
    parse_controller_request,
)
from awid.did import public_key_from_did, stable_id_from_did_key
from nacl.exceptions import CryptoError
from nacl.public import PrivateKey, SealedBox
from nacl.signing import VerifyKey


@pytest.fixture
def store(tmp_path):
    return KeyStore.create(tmp_path / "private", organisation="local")


def context(store):
    descriptor = store.descriptor()
    return ControllerSigningContext(
        parse_controller_request(
            {
                "operation": "namespace_register",
                "domain": "local",
                "controller_did": descriptor.did_key,
            }
        ),
        descriptor,
        timestamp="2026-11-16T00:00:00Z",
        registry_origin="https://registry.example",
    )


def test_keys_are_born_inside_and_only_public_descriptors_leave(store):
    assert store.directory.stat().st_mode & 0o777 == 0o700
    assert (store.directory / "holder.sqlite").stat().st_mode & 0o777 == 0o600
    first = asdict(store.descriptor())
    assert set(first) == {
        "scope",
        "domain",
        "did_key",
        "key_reference",
        "generation",
        "team",
    }
    assert store.descriptor() == KeyStore.open(store.directory).descriptor()
    with pytest.raises(Refused, match="already_initialized"):
        KeyStore.create(store.directory, organisation="local")


def test_typed_signature_has_durable_append_only_audit(store):
    operation = context(store)
    did, signature = store.sign_controller(operation, actor="operator")
    VerifyKey(public_key_from_did(did)).verify(operation.signing_bytes(), signature)
    audit = store.audit()
    assert len(audit) == 1
    assert audit[0]["operation"] == "namespace_register"
    assert audit[0]["actor"] == "operator"
    assert audit[0]["approval"] is None
    assert audit[0]["key"] == did
    with sqlite3.connect(store.directory / "holder.sqlite") as db:
        with pytest.raises(sqlite3.IntegrityError, match="append_only"):
            db.execute("DELETE FROM signatures")
        with pytest.raises(sqlite3.IntegrityError, match="append_only"):
            db.execute("UPDATE signatures SET actor='changed'")


def test_team_keys_are_created_inside_and_selected_by_the_owned_descriptor(store):
    team = store.create_team_key("team")
    assert team.scope == "team" and team.did_key != store.descriptor().did_key
    assert store.descriptor(team="team") == team
    with pytest.raises(Refused, match="key_already_exists"):
        store.create_team_key("team")
    operation = ControllerSigningContext(
        parse_controller_request(
            {
                "operation": "team_visibility",
                "domain": "local",
                "name": "team",
                "visibility": "private",
            }
        ),
        team,
        timestamp="2026-11-16T00:00:00Z",
        registry_origin="https://registry.example",
    )
    did, signature = store.sign_controller(operation, actor="operator")
    VerifyKey(public_key_from_did(did)).verify(operation.signing_bytes(), signature)
    assert store.audit()[0]["key"] == team.did_key


def test_operations_without_a_routine_rule_do_not_sign(store):
    operation = ControllerSigningContext(
        parse_controller_request({"operation": "namespace_delete", "domain": "local"}),
        store.descriptor(),
        timestamp="2026-11-16T00:00:00Z",
        registry_origin="https://registry.example",
    )
    with pytest.raises(Refused, match="operation_not_served"):
        store.sign_controller(operation, actor="operator")
    assert store.audit() == []


def test_failed_audit_never_returns_a_signature(store):
    with sqlite3.connect(store.directory / "holder.sqlite") as db:
        db.execute(
            "CREATE TRIGGER refuse_signature BEFORE INSERT ON signatures BEGIN SELECT RAISE(ABORT,'write_failed'); END"
        )
    with pytest.raises(sqlite3.IntegrityError, match="write_failed"):
        store.sign_controller(context(store), actor="operator")
    assert store.audit() == []


@pytest.mark.parametrize("change", ["domain", "key_reference", "generation"])
def test_signature_requires_the_actual_current_key_descriptor(store, change):
    operation = context(store)
    values = {"domain": "foreign.local", "key_reference": "foreign", "generation": 1}
    changed = replace(
        operation, controller=replace(operation.controller, **{change: values[change]})
    )
    with pytest.raises(Refused, match="controller_mismatch"):
        store.sign_controller(changed, actor="operator")
    assert store.audit() == []


def test_no_sign_bytes_port_or_unapproved_human_id_issuance(store):
    with pytest.raises(Refused, match="operation_invalid"):
        store.sign_controller(b"arbitrary bytes", actor="operator")
    descriptor = store.descriptor()
    certificate = {
        "v": 1,
        "type": "aweb.id-certificate",
        "id": stable_id_from_did_key(descriptor.did_key),
        "domain": "local",
        "parent": {"kind": "namespace", "id": "local"},
        "kind": "human",
        "issuer_key": descriptor.did_key,
        "issued_at": "2026-11-16T00:00:00Z",
    }
    operation = ControllerSigningContext(
        parse_controller_object(
            {
                "operation": "namespace_id_issue",
                "domain": "local",
                "kind": "human",
                "certificate": certificate,
            }
        ),
        descriptor,
    )
    with pytest.raises(Refused, match="human_approval_required"):
        store.sign_controller(operation, actor="operator")
    assert store.audit() == []


def test_backup_only_leaves_encrypted_to_the_offline_operator_key(store):
    offline = PrivateKey.generate()
    encrypted = store.encrypted_backup(bytes(offline.public_key))
    with sqlite3.connect(store.directory / "holder.sqlite") as db:
        secret = db.execute("SELECT seed FROM keys").fetchone()[0]
    assert secret not in encrypted
    with sqlite3.connect(":memory:") as restored:
        restored.deserialize(SealedBox(offline).decrypt(encrypted))
        assert (
            restored.execute("SELECT organisation FROM configuration").fetchone()[0]
            == "local"
        )
        assert restored.execute("SELECT seed FROM keys").fetchone()[0] == secret
        assert restored.execute("PRAGMA user_version").fetchone()[0] == 6
        assert restored.execute("SELECT count(*) FROM enrollments").fetchone()[0] == 0
    with pytest.raises(CryptoError):
        SealedBox(PrivateKey.generate()).decrypt(encrypted)


def test_rejects_shared_or_symlinked_storage(store, tmp_path):
    os.chmod(store.directory, 0o755)
    with pytest.raises(Refused, match="storage_permissions"):
        KeyStore.open(store.directory)
    os.chmod(store.directory, 0o700)
    alias = tmp_path / "alias"
    alias.symlink_to(store.directory, target_is_directory=True)
    with pytest.raises(Refused, match="storage_permissions"):
        KeyStore.open(alias)


def test_executable_initialization_and_public_descriptor(tmp_path):
    directory = tmp_path / "private"

    def run(*args):
        return subprocess.run(
            ["aweb-key-holder", "--state", str(directory), *args],
            capture_output=True,
            text=True,
            check=True,
        )

    created = json.loads(run("init", "--organisation", "local").stdout)
    assert created == json.loads(run("descriptor").stdout)
    assert set(created) == {
        "scope",
        "domain",
        "did_key",
        "key_reference",
        "generation",
        "team",
    }
    assert len(list(directory.iterdir())) == 1
