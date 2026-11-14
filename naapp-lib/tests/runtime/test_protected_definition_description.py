"""Published/pinned definition data is generated from the same runtime rows."""

import json
import subprocess
import sys
from pathlib import Path

from aweb_naapp.runtime.protected_signer.catalog import OPERATIONS, operation_description


def test_description_covers_every_runtime_definition_with_its_frozen_display_and_prepared_members():
    description = operation_description()
    assert description["v"] == 1 and description["type"] == "aweb.protected-operations"
    rows = {row["operation"] + "|" + row["variant"]: row for row in description["operations"]}
    assert set(rows) == {"|".join(selector) for selector in OPERATIONS}
    for selector, definition in OPERATIONS.items():
        row = rows["|".join(selector)]
        assert row["prepared_fields"] == sorted(definition.prepared_fields)
        display = row["display"]
        assert set(display) == {"title", "consequences", "names", "technical", "refusals"}
        assert display["title"] and display["consequences"] and display["technical"]
        assert all(source.startswith("/") for source in [*display["names"].values(), *display["technical"].values()])
        assert set(display["refusals"]) == {"subject_ineligible", "issuer_kind_forbidden"}
        assert row["bindings"] and all(source.startswith("/") for source in row["bindings"].values())
    rows["identity.root.endorse|default"]["display"]["consequences"].clear()
    assert operation_description()["operations"] != list(rows.values())


def test_published_description_and_go_table_are_exactly_generated_from_the_current_rows():
    root = Path(__file__).resolve().parents[3]
    description = json.loads((root / "docs/protected-operations-v1.json").read_bytes())
    assert description == operation_description()
    result = subprocess.run([sys.executable, "scripts/generate_protected_operations.py", "--check"],
        cwd=root, capture_output=True, text=True, timeout=20)
    assert result.returncode == 0, result.stdout + result.stderr


def test_binding_paths_are_required_and_projected_from_the_actual_frozen_request():
    import copy

    import pytest

    from aweb_naapp.runtime.protected_signer import SignerRefused
    from aweb_naapp.runtime.protected_signer.codecs import artifact_for
    from tests.runtime.test_protected_identity_artifacts import HKEY, NOW, operation

    op = operation("team.agent.admit")
    request = {**op.intent(), "artifact": artifact_for(op, HKEY, NOW),
        "request_id": op.operation_id, "admission_policy_version": op.subject["expected_policy_version"]}
    values = op.spec.bound_values(request)
    assert values["certificate_fields"] == request["artifact"]
    assert values["request_id"] == op.operation_id and values["service_id"] == op.context.service_id
    for path in op.spec.bindings().values():
        changed = copy.deepcopy(request)
        target = changed
        parts = path.split("/")[1:]
        for part in parts[:-1]:
            target = target[part]
        del target[parts[-1]]
        with pytest.raises(SignerRefused, match="operation_mismatch"):
            op.spec.bound_values(changed)
