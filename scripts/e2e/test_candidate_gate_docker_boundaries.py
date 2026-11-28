#!/usr/bin/env python3
"""Focused real-Docker proof for the local gate's host-daemon boundaries."""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import tempfile
import time
import unittest
import uuid
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch


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


PROBE_SERVICE_IMAGE = "nginx:1.31.3-alpine@sha256:4a73073bd557c65b759505da037898b61f1be6cbcc3c2c3aeac22d2a470c1752"


def run(
    *args: str,
    check: bool = True,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        args, check=check, capture_output=True, text=True, env=env, timeout=timeout
    )


def wait_for_published_port(container: str, *, timeout: float = 10.0) -> str:
    """Wait for Docker Desktop to publish the requested loopback mapping."""
    deadline = time.monotonic() + timeout
    last = "no mapping observed"
    while time.monotonic() < deadline:
        try:
            result = run(
                "docker",
                "port",
                container,
                "80/tcp",
                check=False,
                timeout=max(0.001, deadline - time.monotonic()),
            )
        except subprocess.TimeoutExpired:
            last = "docker port timed out"
            break
        mapping = result.stdout.strip()
        if result.returncode == 0 and mapping:
            _, separator, port = mapping.rpartition(":")
            if separator and port.isdecimal() and 0 < int(port) <= 65535:
                return port
        last = f"exit {result.returncode}: {result.stderr.strip() or mapping or 'empty mapping'}"
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))

    try:
        inspection = run(
            "docker",
            "inspect",
            "--format",
            "{{json .State}}",
            container,
            check=False,
            timeout=1.0,
        )
        state = (
            inspection.stdout.strip()
            if inspection.returncode == 0
            else (
                f"unavailable (exit {inspection.returncode}): {inspection.stderr.strip()}"
            )
        )
    except subprocess.TimeoutExpired:
        state = "unavailable (docker inspect timed out)"
    raise AssertionError(
        f"Docker did not publish 80/tcp for container {container!r} within {timeout:g}s; "
        f"container state: {state}; last docker port result: {last}"
    )


class PublishedPortWaitTests(unittest.TestCase):
    def test_boundary_waits_for_delayed_published_mapping(self) -> None:
        port_reads = 0

        def docker(*args, check=True, **kwargs):
            nonlocal port_reads
            if args[:2] == ("docker", "port"):
                port_reads += 1
                if port_reads == 1:
                    result = subprocess.CompletedProcess(
                        args, 1, "", "mapping not published yet"
                    )
                elif port_reads == 2:
                    result = subprocess.CompletedProcess(args, 0, "", "")
                else:
                    result = subprocess.CompletedProcess(
                        args, 0, "127.0.0.1:32768\n", ""
                    )
            elif args[:3] == ("docker", "run", "--detach"):
                if "--name" in args:
                    result = subprocess.CompletedProcess(
                        args, 1, "", "port is already allocated"
                    )
                else:
                    result = subprocess.CompletedProcess(
                        args, 0, "delayed-mapping-container\n", ""
                    )
            elif args[:3] == ("docker", "container", "inspect"):
                result = subprocess.CompletedProcess(args, 1, "", "removed")
            else:
                result = subprocess.CompletedProcess(args, 0, "", "")
            if check and result.returncode:
                raise subprocess.CalledProcessError(
                    result.returncode, args, result.stdout, result.stderr
                )
            return result

        with patch(__name__ + ".run", side_effect=docker):
            self.assertEqual(
                wait_for_published_port("delayed-mapping-container"), "32768"
            )
        self.assertEqual(port_reads, 3)

    def test_missing_mapping_times_out_with_container_state(self) -> None:
        def docker(*args, **kwargs):
            if args[1] == "inspect":
                return subprocess.CompletedProcess(
                    args, 0, '{"Status":"exited","ExitCode":1}', ""
                )
            return subprocess.CompletedProcess(args, 1, "", "no public port")

        with patch(__name__ + ".run", side_effect=docker):
            with self.assertRaisesRegex(
                AssertionError,
                "container 'missing-port'.*container state:.*exited.*no public port",
            ):
                wait_for_published_port("missing-port", timeout=0.01)

    def test_hung_port_command_is_bounded_and_inspect_failure_is_reported(self) -> None:
        def docker(*args, **kwargs):
            self.assertGreater(kwargs["timeout"], 0)
            self.assertLessEqual(kwargs["timeout"], 1)
            raise subprocess.TimeoutExpired(args, kwargs["timeout"])

        with patch(__name__ + ".run", side_effect=docker):
            with self.assertRaisesRegex(
                AssertionError,
                "container 'hung-port'.*inspect timed out.*docker port timed out",
            ):
                wait_for_published_port("hung-port", timeout=0.01)

    def test_existing_mapping_returns_without_sleeping(self) -> None:
        with (
            patch(
                __name__ + ".run",
                return_value=subprocess.CompletedProcess(
                    (), 0, "127.0.0.1:32768\n", ""
                ),
            ),
            patch(__name__ + ".time.sleep") as sleep,
        ):
            self.assertEqual(wait_for_published_port("ready-port"), "32768")
        sleep.assert_not_called()


class DockerBoundaryTests(unittest.TestCase):
    image: str

    @classmethod
    def setUpClass(cls) -> None:
        cls.image = os.environ["CANDIDATE_GATE_TEST_IMAGE"]
        run("docker", "info")

    def socket_gid(self) -> str:
        return run(
            "docker",
            "run",
            "--rm",
            "-v",
            "/var/run/docker.sock:/var/run/docker.sock",
            self.image,
            "stat",
            "-c",
            "%g",
            "/var/run/docker.sock",
        ).stdout.strip()

    def test_runner_checkout_is_docker_owned_and_host_binds_are_narrow(self) -> None:
        runner = os.environ.get("CANDIDATE_RUNNER_NAME")
        if not runner:
            self.skipTest("requires the outer candidate runner")
        inspection = json.loads(run("docker", "inspect", runner).stdout)[0]
        mounts = inspection["Mounts"]
        workspace = str(Path(os.environ["CANDIDATE_CHECKOUT_ROOT"]).parent)
        volumes = [
            m for m in mounts if m["Type"] == "volume" and m["Destination"] == workspace
        ]
        self.assertEqual(len(volumes), 1, mounts)
        volume = json.loads(
            run("docker", "volume", "inspect", volumes[0]["Name"]).stdout
        )[0]
        self.assertEqual(
            volume["Labels"]["aweb.candidate-gate"],
            os.environ["AWEB_CANDIDATE_RESOURCE_LABEL"],
        )
        self.assertEqual(
            {m["Destination"] for m in mounts if m["Type"] == "bind"},
            {
                "/var/run/docker.sock",
                os.environ["AWEB_DOCKER_BIND_ROOT"],
                os.environ["CANDIDATE_LOG_DIR"],
            },
        )
        # The runner reaches Docker only through the socket group, never as root.
        user = inspection["Config"]["User"]
        self.assertNotIn(user.split(":")[0], ("", "0", "root"))
        self.assertEqual(inspection["HostConfig"]["GroupAdd"], [self.socket_gid()])
        self.assertFalse(inspection["HostConfig"]["Privileged"])

    def test_dedicated_bind_root_is_visible_to_inner_bind(self) -> None:
        with _bind_tmp() as tmp:
            probe = Path(tmp) / "host-visible"
            probe.write_text("visible\n")
            command = f"docker run --rm -v {probe}:{probe}:ro alpine:3.20 cat {probe}"
            result = run(
                "docker",
                "run",
                "--rm",
                "--init",
                "--user",
                f"{os.getuid()}:{os.getgid()}",
                "--group-add",
                self.socket_gid(),
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock",
                "-v",
                f"{tmp}:{tmp}",
                self.image,
                "bash",
                "-ceu",
                command,
            )
            self.assertEqual(result.stdout.strip(), "visible")


def read_published_response(port: str) -> str:
    # A proxy would prove a different route. This request must originate on
    # the Docker host, not in the bridge-network candidate runner.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open(f"http://127.0.0.1:{port}/", timeout=2) as response:
        return response.read(4096).decode("utf-8")


# A published socket can precede its service. urllib wraps connect errors
# in URLError, but response reads can raise ConnectionResetError directly
# (including http.client.RemoteDisconnected).
STARTUP_READ_ERRORS = (
    urllib.error.URLError,
    TimeoutError,
    ConnectionResetError,
    ConnectionRefusedError,
)


class HostPublishedPortTests(unittest.TestCase):
    """Only the host-side checks preflight invokes this real-socket test."""

    def test_initial_disconnect_waits_for_service_startup(self) -> None:
        self.assert_startup_disconnect_recovers()

    def test_initial_reset_waits_for_service_startup(self) -> None:
        self.assert_startup_disconnect_recovers(reset=True)

    def assert_startup_disconnect_recovers(self, *, reset: bool = False) -> None:
        real_run = run
        real_read = read_published_response
        original: str | None = None
        startup_errors: list[type[Exception]] = []

        def held_startup(
            *args: str,
            check: bool = True,
            env: dict[str, str] | None = None,
            timeout: float | None = None,
        ) -> subprocess.CompletedProcess[str]:
            nonlocal original
            if args[:2] == ("docker", "run"):
                name = args[args.index("--name") + 1]
                if name.startswith("aweb-publish-original-"):
                    original = name
                    args = (
                        *args[:-1],
                        "while [ ! -e /tmp/release-startup ]; do sleep 0.05; done; "
                        + args[-1],
                    )
            return real_run(*args, check=check, env=env, timeout=timeout)

        def read_from_resetting_peer() -> str:
            # Docker Desktop can turn a backend reset into EOF. Make the
            # first request to a real abortive TCP peer while nginx is held.
            # All later requests still use nginx's Docker-published port.
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
                listener.bind(("127.0.0.1", 0))
                listener.listen()
                listener.settimeout(2)

                def reset_peer() -> None:
                    peer, _ = listener.accept()
                    with peer:
                        peer.settimeout(2)
                        self.assertEqual(peer.recv(1), b"G")
                        peer.setsockopt(
                            socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)
                        )

                with ThreadPoolExecutor(max_workers=1) as executor:
                    done = executor.submit(reset_peer)
                    try:
                        return real_read(str(listener.getsockname()[1]))
                    finally:
                        done.result()

        def release_after_first_read(port: str) -> str:
            try:
                if reset and not startup_errors:
                    return read_from_resetting_peer()
                return real_read(port)
            except STARTUP_READ_ERRORS as error:
                if not startup_errors:
                    startup_errors.append(type(error))
                    if original is None:
                        raise AssertionError(
                            "original service was not launched"
                        ) from error
                    real_run(
                        "docker",
                        "exec",
                        original,
                        "touch",
                        "/tmp/release-startup",
                        timeout=10,
                    )
                raise

        # Release held nginx on the first transport error, then run every
        # competition assertion against the actual Docker-published socket.
        with patch.dict(
            globals(),
            run=held_startup,
            read_published_response=release_after_first_read,
        ):
            self.test_docker_assigned_published_port_is_reserved_by_its_service()
        self.assertEqual(len(startup_errors), 1)
        if reset:
            self.assertIs(startup_errors[0], ConnectionResetError)

    def test_docker_assigned_published_port_is_reserved_by_its_service(self) -> None:
        self.assertNotIn(
            "CANDIDATE_RUNNER_NAME",
            os.environ,
            "published loopback must be tested from the Docker host",
        )
        token = uuid.uuid4().hex[:12]
        original = f"aweb-publish-original-{token}"
        competitor = f"aweb-publish-competitor-{token}"
        expected = f"original-{token}"
        label = os.environ.get(
            "AWEB_CANDIDATE_RESOURCE_LABEL", f"acwx-published-{token}"
        )

        def launch(name: str, binding: str, response: str):
            return run(
                "docker",
                "run",
                "--detach",
                "--name",
                name,
                "--label",
                f"aweb.candidate-gate={label}",
                "--publish",
                binding,
                "--env",
                f"PROBE_RESPONSE={response}",
                "--entrypoint",
                "sh",
                PROBE_SERVICE_IMAGE,
                "-ceu",
                'printf "%s\\n" "$PROBE_RESPONSE" > /usr/share/nginx/html/index.html; '
                "exec nginx -g 'daemon off;'",
                check=False,
                timeout=30,
            )

        def snapshot(name: str):
            result = run("docker", "inspect", name, check=False, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            (info,) = json.loads(result.stdout)
            return {"state": info["State"], "ports": info["NetworkSettings"]["Ports"]}

        def owner(snapshot_value):
            self.assertTrue(snapshot_value["state"]["Running"], snapshot_value)
            self.assertIn(
                {"HostIp": "127.0.0.1", "HostPort": port},
                snapshot_value["ports"].get("80/tcp") or [],
                snapshot_value,
            )

        before = None
        try:
            created = launch(original, "127.0.0.1::80", expected)
            self.assertEqual(created.returncode, 0, created.stdout + created.stderr)
            port = wait_for_published_port(original)
            deadline = time.monotonic() + 10
            while True:
                try:
                    response = read_published_response(port)
                    break
                except STARTUP_READ_ERRORS as error:
                    if time.monotonic() >= deadline:
                        self.fail(
                            f"original host publication never became reachable: {error}"
                        )
                    time.sleep(0.1)
            self.assertEqual(response, expected + "\n")
            before = snapshot(original)
            owner(before)
            attempted = launch(
                competitor, f"127.0.0.1:{port}:80", f"competitor-{token}"
            )
            if attempted.returncode:
                self.assertRegex(
                    attempted.stderr.lower(),
                    "port is already allocated|address already in use|ports are not available",
                )
            else:
                # Desktop can start a container without installing its requested
                # conflicting binding. Successful startup is not publication.
                competing = snapshot(competitor)
                self.assertFalse(
                    any(
                        binding["HostPort"] == port
                        for bindings in competing["ports"].values()
                        for binding in (bindings or [])
                    ),
                    competing,
                )
            owner(snapshot(original))
            self.assertEqual(
                read_published_response(port),
                expected + "\n",
                "competitor displaced the original host response",
            )
            # Observe again after the actual request, including any asynchronous
            # publication that completed while the request was in flight.
            owner(snapshot(original))
            if attempted.returncode == 0:
                competing = snapshot(competitor)
                self.assertFalse(
                    any(
                        binding["HostPort"] == port
                        for bindings in competing["ports"].values()
                        for binding in (bindings or [])
                    ),
                    competing,
                )
            print(
                f"host publication PASS: original response retained; competitor "
                f"{'refused' if attempted.returncode else 'started without the reserved binding'}"
            )
        except Exception:
            print(f"original before competition: {before}")
            for name in (original, competitor):
                state = run(
                    "docker",
                    "inspect",
                    "--format",
                    "{{json .State}} {{json .NetworkSettings.Ports}}",
                    name,
                    check=False,
                    timeout=10,
                )
                logs = run(
                    "docker", "logs", "--tail", "30", name, check=False, timeout=10
                )
                print(
                    f"{name}: {state.stdout}{state.stderr}\nlogs: {logs.stdout}{logs.stderr}"
                )
            raise
        finally:
            for name in (competitor, original):
                run("docker", "rm", "-f", name, check=False, timeout=15)
            for name in (competitor, original):
                remains = run(
                    "docker", "container", "inspect", name, check=False, timeout=10
                )
                self.assertNotEqual(
                    remains.returncode, 0, "probe container survived cleanup"
                )
            run("docker", "info", timeout=10)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image", required=True)
    args, remaining = parser.parse_known_args()
    os.environ["CANDIDATE_GATE_TEST_IMAGE"] = args.image
    # The host socket proof is explicitly invoked by the outer gate. Never
    # execute it from this file's default in-runner boundary suite.
    program = unittest.main(
        argv=[__file__, *remaining],
        exit=False,
        defaultTest=[
            "DockerBoundaryTests",
            "PublishedPortWaitTests",
        ],
    )
    return 0 if program.result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
