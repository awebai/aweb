"""The role names a manifest declares are exactly the ones the role store accepts."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from aweb_naapp import roles
from aweb_naapp.manifest import ManifestError, load_manifest

VECTORS = Path(__file__).resolve().parents[3] / "test-vectors" / "app-manifests"
V2 = json.loads((VECTORS / "app-manifest-v2-v1.json").read_text(encoding="utf-8"))
RESERVED = frozenset(V2["reserved_names"])


def test_role_names_follow_the_designatable_role_grammar() -> None:
    # The manifest accepts exactly the names aweb_naapp.roles accepts.
    names = [
        "fixture.approver",
        "a.b",
        "secrets.owner",
        "x-1.y_2.z",
        "fixture." + "x" * 120,
        "fixture." + "x" * 121,
        "owner",
        "Secrets.owner",
        "secrets:owner",
        "secrets..owner",
        "secrets.owner.",
        " secrets.owner",
        ".secrets.owner",
        "-a.b",
        "a.-b",
        "a.b c",
        "é.b",
        "",
    ]
    base = V2["base_manifests"]["v2"]
    for name in names:
        doc = copy.deepcopy(base)
        doc["roles"] = [{"name": name, "label": "Role"}]
        try:
            load_manifest(json.dumps(doc).encode("utf-8"), reserved_names=RESERVED)
            accepted = True
        except ManifestError as refused:
            assert refused.code == "role_invalid", refused
            accepted = False
        assert accepted == roles.is_role_name(name), name
