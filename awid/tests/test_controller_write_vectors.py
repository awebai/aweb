"""The Python client still sends the bytes frozen in
docs/vectors/awid-controller-writes-v1.json, which aw is tested against."""

import asyncio
import importlib.util
import json
from pathlib import Path

VECTOR = (
    Path(__file__).resolve().parents[2]
    / "docs"
    / "vectors"
    / "awid-controller-writes-v1.json"
)
GENERATOR = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "generate_controller_write_vectors.py"
)


def test_the_python_client_regenerates_the_frozen_controller_write_vectors(monkeypatch):
    spec = importlib.util.spec_from_file_location(
        "generate_controller_write_vectors", GENERATOR
    )
    generator = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(generator)
    import awid.registry as registry_module

    monkeypatch.setattr(
        registry_module, "_utc_timestamp", registry_module._utc_timestamp
    )
    regenerated = asyncio.run(generator.generate())
    assert regenerated == json.loads(VECTOR.read_text())
