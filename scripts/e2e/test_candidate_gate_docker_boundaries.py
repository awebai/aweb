#!/usr/bin/env python3
"""Focused real-Docker proof for the local gate's host-daemon boundaries."""

from __future__ import annotations

import argparse

# Reviewed digest-pinned probe service image; a constant, not a discovery.
def _bind_tmp() -> tempfile.TemporaryDirectory:
    """A temp dir whose path resolves identically on the Docker host.

    In-suite, this test runs inside the gate container while every `docker`
    call it makes resolves bind paths on the host daemon. The wrapper mounts
    the dedicated bind root at an identical path on both sides; a plain /tmp
    allocation would bind an empty host directory instead.
    """

    return tempfile.TemporaryDirectory(
        dir=os.environ.get("AWEB_DOCKER_BIND_ROOT") or "/tmp"
    )


PROBE_SERVICE_IMAGE = (
    "nginx:alpine@sha256:1d40e3eb3bf4f138de1d67193f2aa5309fcaf343eb5ffadbf5e9439de1eb1ebb"
)
import os
import subprocess
import tempfile
import unittest
import uuid
from pathlib import Path


def run(
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, check=check, capture_output=True, text=True, env=env)


class DockerBoundaryTests(unittest.TestCase):
    image: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = os.environ["CANDIDATE_GATE_TEST_IMAGE"]
        run("docker", "info")

    def socket_gid(self) -> str:
        return run(
            "docker", "run", "--rm",
            "-v", "/var/run/docker.sock:/var/run/docker.sock",
            self.image, "stat", "-c", "%g", "/var/run/docker.sock",
        ).stdout.strip()

    def test_go_module_cache_is_fresh_per_candidate_run(self) -> None:
        source = (
            Path(__file__).resolve().parents[2] / "scripts/candidate-docker-gate.sh"
        ).read_text()
        self.assertIn('go_mod_cache="$work/go-mod"', source)
        self.assertIn('mkdir -p "$go_mod_cache"', source)
        self.assertIn('-e GOMODCACHE="$go_mod_cache"', source)
        self.assertIn('-v "$go_mod_cache:$go_mod_cache"', source)
        self.assertNotIn("$CACHE_ROOT/go-mod", source)
        self.assertNotIn("GOMODCACHE=/tmp/go-mod", source)

    def test_nonroot_user_has_only_socket_group_and_permission_semantics(self) -> None:
        # A named volume lives on the daemon's native filesystem, so mode
        # bits are real on every platform; a bind-mounted file's chmod does
        # not survive the macOS virtiofs round-trip, which made the previous
        # probe's precondition silently unsatisfiable in-gate.
        volume = f"aweb-gate-perm-probe-{uuid.uuid4().hex[:12]}"
        run("docker", "volume", "create", volume)
        try:
            run(
                "docker", "run", "--rm", "--user", "0:0",
                "-v", f"{volume}:/probe",
                self.image, "bash", "-ceu",
                "echo 'must stay unreadable' > /probe/unreadable; "
                "chmod 0 /probe/unreadable; "
                "test \"$(stat -c %a /probe/unreadable)\" = 0",
            )
            result = run(
                "docker", "run", "--rm", "--init",
                "--user", f"{os.getuid()}:{os.getgid()}",
                "--group-add", self.socket_gid(),
                "-v", "/var/run/docker.sock:/var/run/docker.sock",
                "-v", f"{volume}:/probe",
                self.image, "bash", "-ceu",
                "docker info >/dev/null; ! cat /probe/unreadable >/dev/null 2>&1",
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            removed = run("docker", "volume", "rm", volume, check=False)
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            remains = run("docker", "volume", "inspect", volume, check=False)
            self.assertNotEqual(remains.returncode, 0, "probe volume survived cleanup")

    def test_builder_cache_reclaim_is_scoped_bounded_and_builder_remains_usable(self) -> None:
        source = (Path(__file__).resolve().parents[1] / "candidate-suite.sh").read_text()
        self.assertIn('${BUILDX_BUILDER:?BUILDX_BUILDER is required}', source)
        self.assertIn('${BUILDX_CONFIG:?BUILDX_CONFIG is required}', source)
        self.assertIn('docker buildx prune --all --force --keep-storage=10GB', source)

        builder = f"aweb-gate-proof-{uuid.uuid4().hex[:12]}"
        unrelated = f"aweb-unrelated-proof-{uuid.uuid4().hex[:12]}"
        with _bind_tmp() as tmp:
            root = Path(tmp)
            config = root / "buildx-config"
            unrelated_config = root / "unrelated-buildx-config"
            context = root / "context"
            config.mkdir()
            unrelated_config.mkdir()
            context.mkdir()
            (context / "Dockerfile").write_text("FROM scratch\nCOPY marker /marker\n")
            (context / "marker").write_text("proof\n")
            output = root / "proof.oci.tar"
            buildx_env = {**os.environ, "BUILDX_CONFIG": str(config)}
            unrelated_env = {**os.environ, "BUILDX_CONFIG": str(unrelated_config)}
            try:
                run(
                    "docker", "buildx", "create", "--name", builder,
                    "--driver", "docker-container", "unix:///var/run/docker.sock",
                    "--bootstrap", env=buildx_env,
                )
                run(
                    "docker", "buildx", "create", "--name", unrelated,
                    "--driver", "docker-container", "unix:///var/run/docker.sock",
                    "--bootstrap", env=unrelated_env,
                )
                command = (
                    f"docker buildx inspect {builder} >/dev/null; "
                    f"docker buildx build --builder {builder} "
                    "--platform linux/amd64,linux/arm64 "
                    f"--output type=oci,dest={output} {context}"
                )
                result = run(
                    "docker", "run", "--rm", "--init",
                    "--user", f"{os.getuid()}:{os.getgid()}",
                    "--group-add", self.socket_gid(),
                    "-e", f"BUILDX_CONFIG={config}",
                    "-v", "/var/run/docker.sock:/var/run/docker.sock",
                    "-v", f"{root}:{root}",
                    self.image, "bash", "-ceu", command,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertGreater(output.stat().st_size, 0)
                unrelated_output = root / "unrelated.oci.tar"
                run(
                    "docker", "buildx", "build", "--builder", unrelated,
                    "--platform", "linux/amd64,linux/arm64",
                    "--output", f"type=oci,dest={unrelated_output}", str(context),
                    env=unrelated_env,
                )
                du_format = "{{json .}}"
                owned_before = run(
                    "docker", "buildx", "du", "--builder", builder,
                    "--format", du_format, env=buildx_env,
                ).stdout
                unrelated_before = run(
                    "docker", "buildx", "du", "--builder", unrelated,
                    "--format", du_format, env=unrelated_env,
                ).stdout
                self.assertTrue(owned_before.strip())
                # Under the production bound a small cache is kept intact...
                run(
                    "docker", "buildx", "prune", "--all", "--force",
                    "--keep-storage=10GB", "--builder", builder, env=buildx_env,
                )
                owned_bounded = run(
                    "docker", "buildx", "du", "--builder", builder,
                    "--format", du_format, env=buildx_env,
                ).stdout
                self.assertEqual(
                    len(owned_bounded.splitlines()), len(owned_before.splitlines())
                )
                # ...while a zero bound reclaims it completely.
                reclaim = run(
                    "docker", "buildx", "prune", "--all", "--force",
                    "--keep-storage=0", "--builder", builder, env=buildx_env,
                )
                self.assertTrue(reclaim.stdout or reclaim.stderr)
                owned_after = run(
                    "docker", "buildx", "du", "--builder", builder,
                    "--format", du_format, env=buildx_env,
                ).stdout
                unrelated_after = run(
                    "docker", "buildx", "du", "--builder", unrelated,
                    "--format", du_format, env=unrelated_env,
                ).stdout
                self.assertLess(len(owned_after.splitlines()), len(owned_before.splitlines()))
                self.assertEqual(unrelated_after, unrelated_before)
                reusable_output = root / "reusable.oci.tar"
                run(
                    "docker", "buildx", "build", "--builder", builder,
                    "--output", f"type=oci,dest={reusable_output}", str(context),
                    env=buildx_env,
                )
                self.assertGreater(reusable_output.stat().st_size, 0)
            finally:
                for name, env in ((builder, buildx_env), (unrelated, unrelated_env)):
                    run("docker", "buildx", "rm", name, check=False, env=env)
                    run("docker", "rm", "-f", f"buildx_buildkit_{name}0", check=False)
                    run("docker", "volume", "rm", "-f", f"buildx_buildkit_{name}0_state", check=False)
                    self.assertNotIn(name, run("docker", "buildx", "ls", env=env).stdout)
                    self.assertNotEqual(
                        run("docker", "volume", "inspect", f"buildx_buildkit_{name}0_state", check=False).returncode,
                        0,
                    )

    def test_dedicated_bind_root_is_visible_to_inner_bind(self) -> None:
        with _bind_tmp() as tmp:
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
                "-v", f"{tmp}:{tmp}",
                self.image, "bash", "-ceu", command,
            )
            self.assertEqual(result.stdout.strip(), "visible")

    def test_fixed_docker_host_reaches_published_port_but_loopback_does_not(self) -> None:
        container = run(
            "docker", "run", "--detach", "--publish", "127.0.0.1::80",
            PROBE_SERVICE_IMAGE,
        ).stdout.strip()
        try:
            port = run("docker", "port", container, "80/tcp").stdout.strip().rsplit(":", 1)[1]
            result = run(
                "docker", "run", "--rm",
                "--add-host", "aweb-docker.test:host-gateway",
                self.image, "bash", "-ceu",
                f"ready=; for _ in $(seq 1 30); do "
                f"curl -fsS http://aweb-docker.test:{port} >/dev/null && {{ ready=1; break; }}; "
                f"sleep 0.2; done; test -n \"$ready\"; "
                f"! curl -fsS --connect-timeout 1 http://127.0.0.1:{port} >/dev/null 2>&1",
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        finally:
            removed = run("docker", "rm", "-f", container, check=False)
            self.assertEqual(removed.returncode, 0, removed.stdout + removed.stderr)
            remains = run("docker", "container", "inspect", container, check=False)
            self.assertNotEqual(remains.returncode, 0, "probe container survived cleanup")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args, remaining = parser.parse_known_args()
    os.environ["CANDIDATE_GATE_TEST_IMAGE"] = args.image
    program = unittest.main(argv=[__file__, *remaining], exit=False)
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
