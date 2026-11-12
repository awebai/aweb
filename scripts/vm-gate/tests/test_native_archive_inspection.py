import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from vm_gate.errors import Refused
from vm_gate.native_oci import inspect_archive

HELPER = Path(__file__).resolve().parents[2] / "oci-exact-publish.sh"


def make_archive(path):
    members = {}

    def blob(value):
        data = json.dumps(value).encode() if isinstance(value, dict) else value
        digest = "sha256:" + hashlib.sha256(data).hexdigest()
        members["blobs/sha256/" + digest.split(":")[1]] = data
        return {"digest": digest, "size": len(data)}

    layer = blob(b"layer")
    platforms = []
    for arch in ["amd64", "arm64"]:
        cfg = blob(
            {
                "architecture": arch,
                "os": "linux",
                "config": {
                    "Labels": {
                        "org.opencontainers.image.revision": "a" * 40,
                        "org.opencontainers.image.version": "1.2.3",
                    }
                },
            }
        )
        manifest = blob({"config": cfg, "layers": [layer]})
        platforms.append(
            {**manifest, "platform": {"os": "linux", "architecture": arch}}
        )
    index = blob({"manifests": platforms})
    members["index.json"] = json.dumps(
        {
            "manifests": [
                {**index, "mediaType": "application/vnd.oci.image.index.v1+json"}
            ]
        }
    ).encode()
    members["oci-layout"] = b'{"imageLayoutVersion":"1.0.0"}'
    with tarfile.open(path, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    data = path.read_bytes()
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "bytes": len(data),
        "index": index["digest"],
        "source_sha": "a" * 40,
        "version": "1.2.3",
    }


class Inspection(unittest.TestCase):
    def test_actual_existing_helper_accepts_exact_dual_platform_archive(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / "archive.tar"
            identity = make_archive(p)
            result = inspect_archive(p, identity, HELPER.read_text(), root)
            self.assertEqual(set(result["platforms"]), {"linux/amd64", "linux/arm64"})

    def test_actual_archive_source_version_and_index_mismatch_refuse(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / "archive.tar"
            identity = make_archive(p)
            for key, value in [
                ("source_sha", "b" * 40),
                ("version", "2.0.0"),
                ("index", "sha256:" + "c" * 64),
            ]:
                with self.subTest(key=key), self.assertRaises(Refused):
                    inspect_archive(
                        p, {**identity, key: value}, HELPER.read_text(), root
                    )


if __name__ == "__main__":
    unittest.main()
