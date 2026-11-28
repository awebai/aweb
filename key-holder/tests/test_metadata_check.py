"""Operator checks read active issuer inventory and emit aggregate status."""

import json
import sys
from base64 import b64encode
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
from approval_service.grading import EnrollmentGrading
from authenticator import packed_device
from aweb_key_holder import cli
from test_enrollment import creation
from test_enrollment import holder as holder


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
    ],
)
def test_metadata_check_matches_effective_withdrawals_for_active_credentials(
    holder, tmp_path, monkeypatch, capsys, status, exit_code
):
    device, snapshot, (aaguid, leaf, root) = packed_device(
        holder.approval_origin, holder.rp_id
    )
    holder.grading = EnrollmentGrading("hardware", snapshot)
    person, receipt = creation(holder, device=device)
    credential = receipt["assertion"]["id"]
    with holder.store._connection() as db, db:
        # Activation itself is covered by the native enrollment journey.
        if status != "pending":
            db.execute("UPDATE enrollments SET active=1 WHERE person=?", (person,))
        if status == "invalid_inventory":
            db.execute(
                "UPDATE attestation_inventory SET assessment=? WHERE person=?",
                (json.dumps([aaguid]), person),
            )
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
    assert exited.value.code == exit_code
    output = capsys.readouterr()
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
