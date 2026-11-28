"""Operator checks read active issuer inventory and emit aggregate status."""

import json
import stat
import sys
from base64 import b64encode
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from approval_service.encoding import encode
from approval_service.grading import EnrollmentGrading
from attestation_inventory_migration import corrupt_inventory_assessment
from authenticator import packed_device
from aweb_key_holder import cli
from aweb_key_holder.http import create_app
from metadata_fixtures import signed_cache
from test_native_holder import (
    call,
    commit_identity,
    creation_receipt,
    material_for,
    register_identity,
    register_namespace,
)


async def hardware_enrollment(native_holder, *, activate):
    holder, registry = native_holder.holder, native_holder.registry
    await register_namespace(holder, registry)
    seed, key, person = await register_identity(registry)
    device, snapshot, attestation = packed_device(holder.approval_origin, holder.rp_id)
    holder.grading = EnrollmentGrading("hardware", snapshot)
    intent = (await holder.bootstrap(person, key))["intent"]
    _, material = material_for(holder, intent, device=device)
    requester = dict(seed=seed, key=key, identity=person, chain=[])
    path = f"/v1/enrollments/{person}"
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=create_app(holder)), base_url=holder.origin
    ) as client:
        bound = await call(
            client,
            path + "/binding",
            {"material": material, "registration_count": 1},
            **requester,
        )
        assert bound.status_code == 200, bound.text
        receipt = creation_receipt(bound.json(), device)
        if activate:
            finished = await call(client, path + "/finish", receipt, **requester)
            assert finished.status_code == 200, finished.text
            activation = finished.json()
            await commit_identity(registry, activation, seed, key)
            requester["chain"] = activation["id_chain"]
            activated = await call(client, path + "/activate", {}, **requester)
            assert activated.status_code == 200, activated.text
    return person, receipt, snapshot, attestation


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "exit_code"),
    [
        ("model", 3),
        ("batch", 3),
        ("root", 3),
        ("other_batch", 2),
        ("future", 2),
        ("healthy", 0),
        ("pending", 2),
        ("retired", 2),
        ("invalid_inventory", 1),
        ("invalid_inventory_null_aaguid", 1),
        ("invalid_inventory_numeric_aaguid", 1),
    ],
)
async def test_metadata_check_matches_effective_withdrawals_for_active_credentials(
    native_holder, tmp_path, monkeypatch, capsys, status, exit_code
):
    holder = native_holder.holder
    person, receipt, snapshot, (aaguid, leaf, root) = await hardware_enrollment(
        native_holder, activate=status != "pending"
    )
    credential = receipt["assertion"]["id"]
    if status.startswith("invalid_inventory"):
        with holder.store._connection() as db:
            assessment = json.loads(
                db.execute(
                    "SELECT assessment FROM attestation_inventory WHERE person=? AND credential=?",
                    (person, credential),
                ).fetchone()["assessment"]
            )
        if status == "invalid_inventory":
            assessment = [aaguid]
        elif status == "invalid_inventory_null_aaguid":
            assessment["aaguid"] = None
        else:
            assessment["aaguid"] = 42
        corrupt_inventory_assessment(holder.store, person, credential, assessment)
    if status == "retired":
        holder.store.retire_person(person)

    report = {"status": "REVOKED"}
    if status == "batch":
        report["batchCertificate"] = b64encode(leaf).decode("ascii")
    elif status == "root":
        report["certificate"] = b64encode(root).decode("ascii")
    elif status == "other_batch":
        report["batchCertificate"] = b64encode(b"unrelated").decode("ascii")
    elif status == "future":
        report["effectiveDate"] = (
            (datetime.now(UTC) + timedelta(days=2)).date().isoformat()
        )
    if status == "healthy":
        cutoff = datetime.now(UTC) + timedelta(days=8)
        snapshot = replace(snapshot, next_update=cutoff, valid_until=cutoff)
    else:
        snapshot.by_aaguid[aaguid]["statusReports"].append(report)
    cache = tmp_path / "metadata-cache"
    manifest = tmp_path / "pin.json"
    manifest.write_text("{}")

    # Bind the CLI to a synthetic verified-snapshot input. The shared
    # library tests its matcher against signed synthetic metadata.
    from aweb_key_holder import metadata_monitor

    def verified_snapshot(path, *, manifest, now):
        assert path == cache and manifest == {} and now.tzinfo is UTC
        return snapshot

    monkeypatch.setattr(metadata_monitor, "fetch_and_pin", verified_snapshot)
    exit_status, output = run_monitor(holder, cache, manifest, monkeypatch, capsys)
    assert exit_status == exit_code
    if exit_code == 1:
        assert output.out == ""
        assert json.loads(output.err)["error"] == "metadata_check_unavailable"
    else:
        assert output.err == ""
        result = json.loads(output.out)
        assert result["warning"] == (None if exit_code == 0 else "metadata_expiring")
        if exit_code == 3:
            assert result["withdrawal"] == "fido_withdrawal_matches_inventory"
            assert "Pause" in result["message"]
        else:
            assert result["withdrawal"] is None
    for value in (
        aaguid,
        person,
        credential,
        b64encode(leaf).decode(),
        b64encode(root).decode(),
    ):
        assert value not in output.out and value not in output.err


def run_monitor(holder, cache, manifest, monkeypatch, capsys):
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "aweb-key-holder",
            "--state",
            str(holder.store.directory),
            "--mds-cache",
            str(cache),
            "--mds-manifest",
            str(manifest),
            "metadata-check",
        ],
    )
    with pytest.raises(SystemExit) as exited:
        cli.main()
    return exited.value.code, capsys.readouterr()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "expired", [False, True], ids=["valid_then_corrupt", "expired"]
)
async def test_metadata_check_verifies_real_signed_cache(
    native_holder, tmp_path, monkeypatch, capsys, expired
):
    holder = native_holder.holder
    person, receipt, snapshot, (aaguid, leaf, root) = await hardware_enrollment(
        native_holder, activate=True
    )
    entry = snapshot.by_aaguid[aaguid]
    entry["statusReports"].append(
        {
            "status": "ATTESTATION_KEY_COMPROMISE",
            "batchCertificate": b64encode(leaf).decode("ascii"),
        }
    )
    cache = tmp_path / "metadata-cache"
    manifest = tmp_path / "pin.json"
    now = datetime.now(UTC)
    blob = signed_cache(
        cache,
        manifest,
        entry=entry,
        now=now,
        next_update=now + timedelta(days=-1 if expired else 2),
    )
    assert stat.S_IMODE(cache.stat().st_mode) == 0o700
    status, output = run_monitor(holder, cache, manifest, monkeypatch, capsys)
    if not expired:
        assert status == 3
        assert output.err == ""
        assert (
            json.loads(output.out)["withdrawal"] == "fido_withdrawal_matches_inventory"
        )
        for value in (
            aaguid,
            person,
            receipt["assertion"]["id"],
            encode(leaf),
            encode(root),
        ):
            assert value not in output.out
        blob.write_bytes(b"corrupted cached artifact")
        status, output = run_monitor(holder, cache, manifest, monkeypatch, capsys)

    assert status == 1
    assert output.out == ""
    assert json.loads(output.err) == {
        "error": "metadata_check_unavailable",
        "message": "Check the reviewed metadata pin, its private cache and the holder state.",
    }
