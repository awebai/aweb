"""awid's protocol vectors ship inside the awid-service wheel.

Naapps check their implementations of awid's protocols against these vectors
from the release they pin, with no aweb checkout. Each packaged file is the
docs/vectors authority byte for byte; scripts/check_vector_provenance.py holds
the repository copies to it, and this test holds the built wheel.
"""

from __future__ import annotations

import subprocess
import zipfile
from pathlib import Path

AWID = Path(__file__).resolve().parents[1]
AUTHORITY = AWID.parent / "docs" / "vectors"
PACKAGED = (
    "canonical-json-v1.json",
    "message-signing-v1.json",
    "principal-attestation-v1.json",
    "signature-point-encoding-v2.json",
    "signature-primitives-v1.json",
    "team-auth-envelope-v2.json",
    "team-certificate-verification-v1.json",
)


def test_the_wheel_carries_awids_protocol_vectors(tmp_path: Path) -> None:
    # Build with the locked hatchling in this environment, not an isolated one
    # that would fetch the backend: the test then runs offline on a cold cache.
    subprocess.run(
        ["uv", "build", "--wheel", "--no-build-isolation", "--out-dir", str(tmp_path), str(AWID)],
        capture_output=True,
        check=True,
    )
    (wheel,) = tmp_path.glob("awid_service-*.whl")
    with zipfile.ZipFile(wheel) as archive:
        shipped = {
            name.rsplit("/", 1)[1]: archive.read(name)
            for name in archive.namelist()
            if name.startswith("awid/vectors/") and name.endswith(".json")
        }
    assert sorted(shipped) == sorted(PACKAGED)
    for name, data in shipped.items():
        assert data == (AUTHORITY / name).read_bytes(), name
