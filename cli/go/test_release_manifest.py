import base64
import json
import hashlib
from pathlib import Path
import subprocess
import tempfile
import unittest

import generate_install_verifier
import release_manifest as releases
import release_signing_proof as proof


class ReleaseManifestTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.private = self.root / "key.pem"
        subprocess.run(
            ["openssl", "genpkey", "-algorithm", "ED25519", "-out", str(self.private)],
            check=True,
            capture_output=True,
        )
        public = subprocess.run(
            ["openssl", "pkey", "-in", str(self.private), "-pubout", "-outform", "DER"],
            check=True,
            capture_output=True,
        ).stdout[-32:]
        second_private = self.root / "next.pem"
        subprocess.run(
            [
                "openssl",
                "genpkey",
                "-algorithm",
                "ED25519",
                "-out",
                str(second_private),
            ],
            check=True,
            capture_output=True,
        )
        second = subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(second_private),
                "-pubout",
                "-outform",
                "DER",
            ],
            check=True,
            capture_output=True,
        ).stdout[-32:]
        self.keys = {
            "test-only": base64.b64encode(public).decode(),
            "next-test-only": base64.b64encode(second).decode(),
        }
        self.artifact = self.root / "aw_2.0.0_linux_amd64.tar.gz"
        self.artifact.write_bytes(b"a staged executable archive")
        self.manifest = self.root / "release-manifest.json"
        self.raw = releases.create_manifest(
            version="2.0.0",
            source_commit="a" * 40,
            artifacts=[self.artifact],
            output=self.manifest,
        )
        self.statement = self.root / "release-statement.txt"
        self.statement.write_bytes(releases.create_statement(self.raw))
        signature = self.root / "sig"
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-inkey",
                str(self.private),
                "-rawin",
                "-in",
                str(self.statement),
                "-out",
                str(signature),
            ],
            check=True,
            capture_output=True,
        )
        self.detached = json.dumps(
            {
                "key_id": "test-only",
                "statement": base64.b64encode(self.statement.read_bytes()).decode(),
                "signature": base64.b64encode(signature.read_bytes()).decode(),
            }
        ).encode()
        self.signature = self.root / "release-manifest.sig"
        self.signature.write_bytes(self.detached)

    def test_canonical_statement_authenticates_exact_manifest(self):
        statement = (
            "aw-release-statement-v1\n"
            "version=2.0.0\n"
            f"source_commit={'a' * 40}\n"
            f"manifest_sha256={hashlib.sha256(self.raw).hexdigest()}\n"
        ).encode()
        statement_path = self.root / "statement"
        statement_path.write_bytes(statement)
        result = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(self.private),
                "-in",
                str(statement_path),
            ],
            check=True,
            capture_output=True,
        )
        envelope = json.dumps(
            {
                "key_id": "test-only",
                "statement": base64.b64encode(statement).decode(),
                "signature": base64.b64encode(result.stdout).decode(),
            }
        ).encode()
        releases.verify_manifest(
            manifest_bytes=self.raw,
            signature_bytes=envelope,
            keys=self.keys,
            requested_version="2.0.0",
        )

    def test_statement_version_and_commit_must_equal_manifest(self):
        for original, replacement in (
            (b"version=2.0.0", b"version=3.0.0"),
            (b"source_commit=" + b"a" * 40, b"source_commit=" + b"b" * 40),
        ):
            statement = self.statement.read_bytes().replace(original, replacement)
            self.statement.write_bytes(statement)
            signed = subprocess.run(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    str(self.private),
                    "-in",
                    str(self.statement),
                ],
                capture_output=True,
                check=True,
            ).stdout
            envelope = json.dumps(
                {
                    "key_id": "test-only",
                    "statement": base64.b64encode(statement).decode(),
                    "signature": base64.b64encode(signed).decode(),
                }
            ).encode()
            with self.assertRaisesRegex(ValueError, "differs from manifest"):
                releases.verify_manifest(
                    manifest_bytes=self.raw,
                    signature_bytes=envelope,
                    keys=self.keys,
                    requested_version="2.0.0",
                )
            self.statement.write_bytes(releases.create_statement(self.raw))

    def test_statement_is_bounded_and_canonical(self):
        canonical = self.statement.read_bytes()
        for bad in (canonical + b"\n", canonical.replace(b"\n", b"\r\n"), b"x" * 257):
            with self.assertRaises(ValueError):
                releases.parse_statement(bad)

    def test_proof_harness_with_software_fixture_only(self):
        directory = self.root / "proof"
        proof.prepare_proof(directory=directory, source_commit="a" * 40)
        public = self.root / "proof-public.pem"
        subprocess.run(
            [
                "openssl",
                "pkey",
                "-in",
                str(self.private),
                "-pubout",
                "-out",
                str(public),
            ],
            capture_output=True,
            check=True,
        )
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                str(self.private),
                "-in",
                str(directory / "release-statement.txt"),
                "-out",
                str(directory / "release-statement.rawsig"),
            ],
            capture_output=True,
            check=True,
        )
        proof.verify_proof(directory=directory, public_key=public)

    def test_raw_bytes_and_rotation_pin(self):
        manifest = releases.verify_manifest(
            manifest_bytes=self.raw,
            signature_bytes=self.detached,
            keys=self.keys,
            requested_version="2.0.0",
            running_version="1.0.0",
        )
        releases.verify_artifact(self.artifact, manifest)
        with self.assertRaisesRegex(ValueError, "digest"):
            releases.verify_manifest(
                manifest_bytes=self.raw + b"\n",
                signature_bytes=self.detached,
                keys=self.keys,
                requested_version="2.0.0",
            )
        with self.assertRaisesRegex(ValueError, "pinned"):
            releases.verify_manifest(
                manifest_bytes=self.raw,
                signature_bytes=self.detached,
                keys={},
                requested_version="2.0.0",
            )
        self.artifact.write_bytes(b"changed")
        with self.assertRaisesRegex(ValueError, self.artifact.name):
            releases.verify_artifact(self.artifact, manifest)

    def test_requested_and_running_rollback(self):
        for requested, current in (("3.0.0", "1.0.0"), ("2.0.0", "3.0.0")):
            with self.assertRaisesRegex(ValueError, "older"):
                releases.verify_manifest(
                    manifest_bytes=self.raw,
                    signature_bytes=self.detached,
                    keys=self.keys,
                    requested_version=requested,
                    running_version=current,
                )

    def test_installer_uses_the_same_verifier_and_pins(self):
        script = generate_install_verifier.generated(json.dumps(self.keys))
        command = script + '\nverify_signed_release "$1" "$2" "$3" "$4"'
        args = [
            "bash",
            "-c",
            command,
            "test",
            str(self.artifact),
            str(self.manifest),
            str(self.signature),
            "2.0.0",
        ]
        result = subprocess.run(args, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = subprocess.run(args[:-1] + ["3.0.0"], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(self.artifact.name, result.stderr)
        self.assertIn("Retry the installer", result.stderr)

    def test_readback_checks_bytes_at_two_independent_hosts(self):
        def fetch(url, limit=1 << 20):
            if url.endswith("release-manifest.json"):
                return self.raw
            if url.endswith("release-manifest.sig"):
                return self.detached
            return self.artifact.read_bytes()

        releases.readback_release(
            manifest_bytes=self.raw,
            signature_bytes=self.detached,
            keys=self.keys,
            requested_version="2.0.0",
            locations=["https://one.example/v2", "https://two.example/v2"],
            fetch_bytes=fetch,
        )
        with self.assertRaisesRegex(ValueError, "two independent"):
            releases.readback_release(
                manifest_bytes=self.raw,
                signature_bytes=self.detached,
                keys=self.keys,
                requested_version="2.0.0",
                locations=["https://one.example/a", "https://one.example/b"],
                fetch_bytes=fetch,
            )

        def changed(url, limit=1 << 20):
            data = fetch(url, limit)
            return data + b"\n" if url.startswith("https://two.example") else data

        with self.assertRaisesRegex(ValueError, "bytes differ"):
            releases.readback_release(
                manifest_bytes=self.raw,
                signature_bytes=self.detached,
                keys=self.keys,
                requested_version="2.0.0",
                locations=["https://one.example/v2", "https://two.example/v2"],
                fetch_bytes=changed,
            )

    def test_signed_stage_cannot_be_overwritten(self):
        with self.assertRaises(FileExistsError):
            releases.create_manifest(
                version="2.0.0",
                source_commit="a" * 40,
                artifacts=[self.artifact],
                output=self.manifest,
            )
        self.assertEqual(self.manifest.read_bytes(), self.raw)


if __name__ == "__main__":
    unittest.main()
