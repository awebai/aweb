"""Service preparation refuses mismatched locks, source and artifact bytes."""

import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "approval_gate_preparation", ROOT / "scripts/test-egress/approval_service.py"
)
preparation = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preparation
SPEC.loader.exec_module(preparation)


class PreparationTests(unittest.TestCase):
    def test_root_make_delegates_once_with_retained_receipt_and_propagates_failure(
        self,
    ):
        # The disposable owner records Make's boundary, not native service behavior.
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            service = root / "service"
            service.mkdir()
            subprocess.run(["git", "init", "-q", str(service)], check=True)
            (service / "Makefile").write_text(
                ".PHONY: test\ntest:\n"
                '\t@printf "%s\\n" "$(APPROVAL_TEST_DATABASE_URL)" "$(APPROVAL_TEST_REDIS_URL)" "$(APPROVAL_TEST_COREDNS_BINARY)" "$(JUNIT_XML)" "$(PYTEST_ADDOPTS)" >> "$(CALLS)"\n'
                "\t@exit $(OWNER_STATUS)\n"
            )
            subprocess.run(["git", "add", "."], cwd=service, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Gate fixture",
                    "-c",
                    "user.email=gate@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=service,
                check=True,
            )
            revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=service, text=True
            ).strip()
            holder = root / "key-holder"
            holder.mkdir()
            (holder / "pyproject.toml").write_text(
                f'[tool.uv.sources]\naweb-approval-service = {{git = "{preparation.REPOSITORY}", rev = "{revision}"}}\n'
            )
            (holder / "uv.lock").write_text(
                f'[[package]]\nname = "aweb-approval-service"\nsource = {{git = "{preparation.REPOSITORY}?rev={revision}#{revision}"}}\n'
            )
            binary = service / ".gate-coredns"
            binary.write_bytes(b"prepared fixture bytes")
            receipt = {
                "service_revision": revision,
                "holder_lock_sha256": preparation.selected_service(root).lock_sha256,
                "coredns_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            }
            (service / ".gate-prepared.json").write_text(json.dumps(receipt))
            scripts = root / "scripts/test-egress"
            scripts.mkdir(parents=True)
            shutil.copyfile(
                ROOT / "scripts/test-egress/approval_service.py",
                scripts / "approval_service.py",
            )
            evidence = root / "evidence"
            evidence.mkdir()
            calls = root / "calls"
            command = [
                "make",
                "--no-print-directory",
                "-f",
                str(ROOT / "Makefile"),
                "test-approval-service",
                f"APPROVAL_SERVICE_SOURCE={service}",
                f"AWEB_UNIT_EVIDENCE_DIR={evidence}",
            ]
            for status in (0, 17):
                with self.subTest(owner_status=status):
                    calls.write_text("")
                    result = subprocess.run(
                        command,
                        cwd=root,
                        env={
                            **os.environ,
                            "CALLS": str(calls),
                            "OWNER_STATUS": str(status),
                            "PYTEST_ADDOPTS": "--durations=0",
                        },
                        capture_output=True,
                        text=True,
                        timeout=10,
                    )
                    self.assertEqual(
                        result.returncode,
                        0 if status == 0 else 2,
                        result.stdout + result.stderr,
                    )
                    self.assertEqual(
                        calls.read_text().splitlines(),
                        [
                            "postgresql://postgres:postgres@127.0.0.1:5432/postgres",
                            "redis://127.0.0.1:6379/0",
                            str(binary),
                            str(evidence / "service.xml"),
                            "--durations=0",
                        ],
                    )
                    self.assertEqual(
                        json.loads((evidence / "service-prepared.json").read_text()),
                        receipt,
                    )
            binary.write_bytes(b"changed")
            calls.write_text("")
            refused = subprocess.run(
                command,
                cwd=root,
                env={**os.environ, "CALLS": str(calls), "OWNER_STATUS": "0"},
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("rebuild the test image", refused.stderr)
            self.assertEqual(calls.read_text(), "")

    def test_coredns_declaration_requires_the_official_hash_bound_platform(self):
        declaration = {
            "version": "1.12.0",
            "linux": {
                "arm64": {
                    "url": "https://github.com/coredns/coredns/releases/download/v1.12.0/coredns_1.12.0_linux_arm64.tgz",
                    "sha256": "a" * 64,
                }
            },
        }
        artifact = preparation.coredns_artifact(
            declaration=declaration, architecture="arm64"
        )
        self.assertEqual(artifact.version, "1.12.0")
        for invalid in (None, {}, {"version": 12}, {**declaration, "linux": []}):
            with (
                self.subTest(declaration=invalid),
                self.assertRaisesRegex(
                    ValueError, "correct the service's pinned artifact metadata"
                ),
            ):
                preparation.coredns_artifact(declaration=invalid, architecture="arm64")
        declaration["linux"]["arm64"]["sha256"] = "bad"
        with self.assertRaisesRegex(
            ValueError, "correct the service's pinned artifact metadata"
        ):
            preparation.coredns_artifact(declaration=declaration, architecture="arm64")

    def test_holder_metadata_and_lock_must_select_the_same_immutable_repository(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            holder = source / "key-holder"
            holder.mkdir()
            revision = "a" * 40
            metadata = (
                '[tool.uv.sources]\naweb-approval-service = {git = "'
                + preparation.REPOSITORY
                + '", rev = "'
                + revision
                + '"}\n'
            )
            (holder / "pyproject.toml").write_text(metadata)
            lock = (
                '[[package]]\nname = "aweb-approval-service"\nsource = {git = "'
                + preparation.REPOSITORY
                + "?rev="
                + revision
                + "#"
                + revision
                + '"}\n'
            )
            (holder / "uv.lock").write_text(lock)
            self.assertEqual(preparation.selected_service(source).revision, revision)
            for invalid in ("main", "b" * 40):
                with self.subTest(revision=invalid):
                    (holder / "pyproject.toml").write_text(
                        metadata.replace(revision, invalid)
                    )
                    with self.assertRaisesRegex(
                        ValueError, "regenerate the committed lock"
                    ):
                        preparation.selected_service(source)

    def test_real_git_checkout_must_match_the_locked_commit_and_remain_clean(self):
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            tracked = source / "source.txt"
            tracked.write_text("locked source\n")
            subprocess.run(["git", "add", "."], cwd=source, check=True)
            subprocess.run(
                [
                    "git",
                    "-c",
                    "user.name=Gate fixture",
                    "-c",
                    "user.email=gate@example.invalid",
                    "commit",
                    "-qm",
                    "fixture",
                ],
                cwd=source,
                check=True,
            )
            revision = subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=source, text=True
            ).strip()
            pin = preparation.ServicePin(revision, "unused-lock-digest")
            preparation.require_checkout(destination=source, pin=pin)
            with self.assertRaisesRegex(ValueError, "rebuild the isolated test image"):
                preparation.require_checkout(
                    destination=source,
                    pin=preparation.ServicePin("0" * 40, pin.lock_sha256),
                )
            tracked.write_text("changed source\n")
            with self.assertRaisesRegex(ValueError, "rebuild the isolated test image"):
                preparation.require_checkout(destination=source, pin=pin)

    def test_only_the_hash_bound_regular_coredns_member_is_prepared(self):
        archive = io.BytesIO()
        binary = b"fixture artifact bytes"
        with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
            entry = tarfile.TarInfo("coredns")
            entry.size = len(binary)
            bundle.addfile(entry, io.BytesIO(binary))
        raw = archive.getvalue()
        self.assertEqual(
            preparation.coredns_bytes(
                archive=raw, expected_sha256=hashlib.sha256(raw).hexdigest()
            ),
            binary,
        )
        with self.assertRaisesRegex(ValueError, "archive hash differs"):
            preparation.coredns_bytes(archive=raw, expected_sha256="0" * 64)
        archive = io.BytesIO()
        with tarfile.open(fileobj=archive, mode="w:gz") as bundle:
            entry = tarfile.TarInfo("coredns")
            entry.type = tarfile.SYMTYPE
            entry.linkname = "/etc/passwd"
            bundle.addfile(entry)
        raw = archive.getvalue()
        with self.assertRaisesRegex(ValueError, "one regular binary"):
            preparation.coredns_bytes(
                archive=raw, expected_sha256=hashlib.sha256(raw).hexdigest()
            )


if __name__ == "__main__":
    unittest.main()
