"""Real OCI image-cache pin controls, before any credential or runtime execution."""

import hashlib
import json
import os
import unittest
from unittest.mock import patch

import test_runtime

from aweb_secrets_runner.errors import Refused
from aweb_secrets_runner.oci_images import ImageStore


@unittest.skipUnless(os.environ.get("AWEB_SECRETS_OCI_PROOF") == "1", "explicit Linux OCI proof")
class ImagePinTests(unittest.TestCase):
    setUp = test_runtime.RuntimeCapabilityTests.setUp
    command = test_runtime.RuntimeCapabilityTests.command
    run_job = test_runtime.RuntimeCapabilityTests.run_job

    def pin(self):
        descriptor = json.loads((self.layout / "index.json").read_bytes())["manifests"][0]
        return "registry.example/image@" + descriptor["digest"]

    def blob(self, digest):
        return self.layout / "blobs" / "sha256" / digest.removeprefix("sha256:")

    def manifest(self):
        return json.loads(self.blob(self.pin().split("@", 1)[1]).read_bytes())

    def put(self, document):
        raw = json.dumps(document).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.blob(digest).write_bytes(raw)
        return {"digest": digest, "size": len(raw), "mediaType": document["mediaType"]}

    def stage(self, reference=None):
        return ImageStore(self.layout).stage(reference or self.pin(), self.root)

    def test_fixed_digest_ignores_a_poisoned_mutable_index_and_runs_exact_image(self):
        reference = self.pin()
        expected = self.blob(reference.split("@", 1)[1]).read_bytes()
        index = self.layout / "index.json"
        index.write_text(json.dumps({"schemaVersion": 2, "manifests": []}))
        staged = self.stage(reference)
        self.assertEqual(staged.source_digest, reference.split("@", 1)[1])
        self.assertEqual(staged.manifest_digest, staged.source_digest)
        self.assertEqual(
            (
                staged.layout / "blobs" / "sha256" / staged.manifest_digest.split(":")[1]
            ).read_bytes(),
            expected,
        )
        self.image = str(staged.layout) + ":verified"
        result = self.run_job(["HOME=/pinned-home", "DECLARED=non-credential-test-value"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            set(result.stdout.splitlines()),
            {b"HOME=/pinned-home", b"DECLARED=non-credential-test-value"},
        )

    def test_corrupt_manifest_configuration_and_layer_are_refused(self):
        reference = self.pin()
        manifest = self.manifest()
        for digest in (
            reference.split("@", 1)[1],
            manifest["config"]["digest"],
            manifest["layers"][0]["digest"],
        ):
            path = self.blob(digest)
            original = path.read_bytes()
            try:
                path.write_bytes(original + b" ")
                with self.assertRaisesRegex(Refused, "oci_image_invalid"):
                    self.stage(reference)
            finally:
                path.write_bytes(original)
        self.assertEqual(list(self.root.glob("image-*")), [])

    def test_descriptor_size_is_checked_even_when_the_manifest_hash_is_valid(self):
        manifest = self.manifest()
        manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        for size in (None, True, -1, 1.0, manifest["config"]["size"] + 1):
            manifest["config"]["size"] = size
            descriptor = self.put(manifest)
            with self.assertRaisesRegex(Refused, "oci_image_invalid"):
                self.stage("registry.example/image@" + descriptor["digest"])
        self.assertEqual(list(self.root.glob("image-*")), [])

    def test_unknown_or_traversing_digest_and_missing_blob_are_refused(self):
        for reference in (
            "registry.example/image:latest",
            "registry.example/image@sha256:../outside",
            "registry.example/image@sha256:" + "0" * 64,
        ):
            with self.assertRaisesRegex(Refused, "oci_image_invalid"):
                self.stage(reference)
        self.assertEqual(list(self.root.glob("image-*")), [])

    def test_index_selects_only_the_current_platform_from_its_pinned_children(self):
        manifest = self.manifest()
        config = json.loads(self.blob(manifest["config"]["digest"]).read_bytes())
        descriptor = json.loads((self.layout / "index.json").read_bytes())["manifests"][0]
        selected = dict(
            descriptor, platform={"os": "linux", "architecture": config["architecture"]}
        )
        foreign = dict(
            descriptor,
            digest="sha256:" + "0" * 64,
            platform={"os": "windows", "architecture": "not-current"},
        )
        index = self.put(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [foreign, selected],
            }
        )
        staged = self.stage("registry.example/image@" + index["digest"])
        self.assertEqual(staged.source_digest, index["digest"])
        self.assertEqual(staged.manifest_digest, descriptor["digest"])
        self.image = str(staged.layout) + ":verified"
        result = self.run_job(["HOME=/pinned-home"], args=("/bin/pwd",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"/pinned-work\n")

    def test_same_platform_choices_follow_the_pinned_index_order(self):
        manifest = self.manifest()
        manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        first = self.put(manifest)
        manifest["annotations"] = {"different": "second-approved-choice"}
        second = self.put(manifest)
        config = json.loads(self.blob(manifest["config"]["digest"]).read_bytes())
        platform = {"os": "linux", "architecture": config["architecture"]}
        index = self.put(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [dict(first, platform=platform), dict(second, platform=platform)],
            }
        )
        staged = self.stage("registry.example/image@" + index["digest"])
        self.assertEqual(staged.manifest_digest, first["digest"])
        document = json.loads(self.blob(index["digest"]).read_bytes())
        document["manifests"].reverse()
        reversed_index = self.put(document)
        self.assertNotEqual(reversed_index["digest"], index["digest"])
        reversed_stage = self.stage("registry.example/image@" + reversed_index["digest"])
        self.assertEqual(reversed_stage.manifest_digest, second["digest"])

    def test_staged_bytes_survive_cache_rotation_without_reopening_the_cache(self):
        staged = self.stage()
        manifest = self.manifest()
        for digest in (manifest["config"]["digest"], manifest["layers"][0]["digest"]):
            self.blob(digest).write_bytes(b"changed-after-verification")
        for path in staged.layout.rglob("*"):
            self.assertEqual(path.stat().st_mode & 0o777, 0o700 if path.is_dir() else 0o600)
        self.image = str(staged.layout) + ":verified"
        result = self.run_job(["HOME=/pinned-home"])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"HOME=/pinned-home\n")

    def test_layer_hash_is_checked_without_a_size_or_json_refusal_masking_it(self):
        path = self.blob(self.manifest()["layers"][0]["digest"])
        content = bytearray(path.read_bytes())
        content[-1] ^= 1
        path.write_bytes(content)
        with self.assertRaisesRegex(Refused, "oci_image_invalid"):
            self.stage()
        self.assertEqual(list(self.root.glob("image-*")), [])

    def test_nested_index_still_binds_the_original_pin(self):
        initial = self.pin().split("@", 1)[1]
        descriptor = json.loads((self.layout / "index.json").read_bytes())["manifests"][0]
        inner = self.put(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [descriptor],
            }
        )
        outer = self.put(
            {
                "schemaVersion": 2,
                "mediaType": "application/vnd.oci.image.index.v1+json",
                "manifests": [inner],
            }
        )
        staged = self.stage("registry.example/image@" + outer["digest"])
        self.assertEqual(staged.source_digest, outer["digest"])
        self.assertEqual(staged.manifest_digest, initial)

    def test_manifest_with_a_foreign_actual_configuration_is_refused(self):
        manifest = self.manifest()
        configuration = json.loads(self.blob(manifest["config"]["digest"]).read_bytes())
        configuration["architecture"] = "not-the-host"
        raw = json.dumps(configuration).encode()
        digest = "sha256:" + hashlib.sha256(raw).hexdigest()
        self.blob(digest).write_bytes(raw)
        manifest["config"].update(digest=digest, size=len(raw))
        manifest["mediaType"] = "application/vnd.oci.image.manifest.v1+json"
        descriptor = self.put(manifest)
        with self.assertRaisesRegex(Refused, "oci_image_invalid"):
            self.stage("registry.example/image@" + descriptor["digest"])

    def test_failed_name_collision_never_deletes_an_existing_workspace(self):
        # Only stdlib entropy is fixed; mkdir/collision/cleanup use real files.
        existing = self.root / ("image-" + "f" * 32)
        existing.mkdir(mode=0o700)
        marker = existing / "existing-owner-state"
        marker.write_bytes(b"must-survive")
        with patch("secrets.token_hex", return_value="f" * 32):
            with self.assertRaisesRegex(Refused, "oci_image_invalid"):
                self.stage()
        self.assertEqual(marker.read_bytes(), b"must-survive")

    def test_agent_writable_cached_content_is_refused(self):
        path = self.blob(self.pin().split("@", 1)[1])
        path.chmod(0o666)
        with self.assertRaisesRegex(Refused, "oci_image_invalid"):
            self.stage()
        self.assertEqual(list(self.root.glob("image-*")), [])


if __name__ == "__main__":
    unittest.main()
