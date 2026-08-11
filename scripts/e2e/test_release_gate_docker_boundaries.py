#!/usr/bin/env python3
"""Focused real-Docker proof for the local gate's host-daemon boundaries."""

from __future__ import annotations

import argparse
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, capture_output=True, text=True)


class DockerBoundaryTests(unittest.TestCase):
    image: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = os.environ["RELEASE_GATE_TEST_IMAGE"]
        run("docker", "info")

    def socket_gid(self) -> str:
        return run(
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            self.image, "stat", "-c", "%g", "/var/run/docker.sock",
        ).stdout.strip()

    def test_nonroot_user_has_only_socket_group_and_permission_semantics(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            probe = Path(tmp) / "unreadable"
            probe.write_text("must stay unreadable\n")
            probe.chmod(0)
            result = run(
                "docker", "run", "--rm", "--init",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--group-add", self.socket_gid(),
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{tmp}:{tmp}",
                self.image, "bash", "-ceu",
                f"docker info >/dev/null; ! cat {probe} >/dev/null 2>&1",
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_disposable_container_builder_exports_two_platform_oci(self) -> None:
        builder = f"aweb-gate-proof-{uuid.uuid4().hex[:12]}"
        try:
            run("docker", "buildx", "create", "--name", builder,
                "--driver", "docker-container", "--bootstrap")
            with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
                root = Path(tmp)
                (root / "Dockerfile").write_text("FROM scratch\nCOPY marker /marker\n")
                (root / "marker").write_text("proof\n")
                output = root / "proof.oci.tar"
                run(
                    "docker", "buildx", "build", "--builder", builder,
                    "--platform", "linux/amd64,linux/arm64",
                    "--output", f"type=oci,dest={output}", str(root),
                )
                self.assertGreater(output.stat().st_size, 0)
        finally:
            run("docker", "buildx", "rm", builder, check=False)
        listed = run("docker", "buildx", "ls").stdout
        self.assertNotIn(builder, listed)

    def test_identical_tmp_mount_is_visible_to_inner_bind(self) -> None:
        with tempfile.TemporaryDirectory(dir="/tmp") as tmp:
            probe = Path(tmp) / "host-visible"
            probe.write_text("visible\n")
            command = (
                f"docker run --rm -v {probe}:{probe}:ro alpine:3.20 "
                f"cat {probe}"
            )
            result = run(
                "docker", "run", "--rm", "--init",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--group-add", self.socket_gid(),
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", "/tmp:/tmp",
                self.image, "bash", "-ceu", command,
            )
            self.assertEqual(result.stdout.strip(), "visible")

    def test_fixed_docker_host_reaches_published_port_but_loopback_does_not(self) -> None:
        container = run(
            "docker", "run", "--detach", "--publish", "127.0.0.1::80",
            "nginx:alpine",
        ).stdout.strip()
        try:
            port = run("docker", "port", container, "80/tcp").stdout.strip().rsplit(":", 1)[1]
            result = run(
                "docker", "run", "--rm",
                "--add-host", "host.docker.internal:host-gateway",
                self.image, "bash", "-ceu",
                f"ready=; for _ in $(seq 1 30); do "
                f"curl -fsS http://host.docker.internal:{port} >/dev/null && {{ ready=1; break; }}; "
                f"sleep 0.2; done; test -n \"$ready\"; "
                f"! curl -fsS --connect-timeout 1 http://127.0.0.1:{port} >/dev/null 2>&1",
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            run("docker", "rm", "-f", container, check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args, remaining = parser.parse_known_args()
    os.environ["RELEASE_GATE_TEST_IMAGE"] = args.image
    program = unittest.main(argv=[__file__, *remaining], exit=False)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
