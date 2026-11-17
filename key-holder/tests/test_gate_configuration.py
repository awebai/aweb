"""The old approved setting must never silently turn into unconfigured issuance."""

import pytest
from approval_service.grading import EnrollmentGrading
from aweb_key_holder.enrollment import Holder
from aweb_key_holder.keys import KeyStore, Refused


@pytest.mark.parametrize("configured", [False, True])
def test_legacy_approved_holder_refuses_start_with_replacement_instruction(tmp_path, configured):
    store = KeyStore.create(tmp_path / "private", organisation="example.test")
    # The actual persisted setting used by the previous version, not a mocked
    # policy source. Keep its upgrade behavior even after the column retires.
    with store._connection() as db, db:
        names = {row[1] for row in db.execute("PRAGMA table_info(configuration)")}
        if "human_issuance" not in names:
            db.execute("ALTER TABLE configuration ADD COLUMN human_issuance TEXT")
        db.execute("UPDATE configuration SET human_issuance='approved'")
    values = dict(
        approval_origin="https://approval.example",
        rp_id="approval.example",
        grading=EnrollmentGrading("passkey_only", None),
    ) if configured else {}
    with pytest.raises(Refused, match="human_approval"):
        Holder(store, registry=None, origin="https://holder.example", **values)
