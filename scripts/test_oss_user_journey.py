"""Focused command-stream and real Docker-port regressions for the OSS journey."""
from pathlib import Path
import ipaddress
import json
import os
import re
import subprocess
import tempfile
import unittest
import uuid


JOURNEY = Path(__file__).with_name("e2e-oss-user-journey.sh")


def function(name):
    match = re.search(rf"(?ms)^{name}\(\) \{{\n.*?^\}}", JOURNEY.read_text())
    if match is None:
        raise AssertionError(f"journey function {name} is missing")
    return match.group()


class CommandCaptureTests(unittest.TestCase):
    def capture(self, status=0):
        with tempfile.TemporaryDirectory() as directory:
            script = "\n".join([
                "set -euo pipefail", "pass=0; fail=0",
                function("assert_eq"), function("capture_success"),
                "child() {",
                "  printf 'called\\n' >>\"$1/calls\"",
                "  printf '%s' '{\"messages\":[{\"body\":\"delivered\"}]}'",
                "  printf '%s\\n' 'service temporarily unavailable, retrying 1/3 (GET /v1/messages/inbox)' >&2",
                f"  return {status}", "}",
                'capture_success captured inbox child "$1"',
                'printf "%s" "$captured" >"$1/captured"',
                'printf "%s" "$fail" >"$1/failures"',
            ])
            result = subprocess.run(["bash", "-c", script, "capture-test", directory],
                                    capture_output=True, text=True, check=True)
            root = Path(directory)
            return result, (root / "captured").read_text(), (root / "failures").read_text(), (root / "calls").read_text()

    def test_success_keeps_json_separate_from_legitimate_stderr_diagnostic(self):
        result, captured, failures, calls = self.capture()
        self.assertEqual(captured, '{"messages":[{"body":"delivered"}]}',
                         "successful CLI stderr contaminated the JSON consumed by the journey")
        self.assertIn("service temporarily unavailable", result.stderr)
        self.assertEqual(failures, "0")
        self.assertEqual(calls, "called\n", "capture must not retry the command")

    def test_nonzero_command_still_fails_and_discards_stdout(self):
        result, captured, failures, calls = self.capture(status=1)
        self.assertEqual(captured, "")
        self.assertEqual(failures, "1")
        self.assertIn("FAIL: inbox exit", result.stdout)
        self.assertIn("service temporarily unavailable", result.stderr)
        self.assertEqual(calls, "called\n")


class InboxParsingTests(unittest.TestCase):
    def parse(self, inbox):
        assignment = next(line for line in JOURNEY.read_text().splitlines()
                          if line.startswith('alice_join_message='))
        return subprocess.run(["bash", "-ec", assignment + '\nprintf "%s" "$alice_join_message"'],
                              env={**os.environ, "alice_join_inbox": inbox},
                              capture_output=True, text=True)

    def test_malformed_json_exposes_the_parse_failure(self):
        result = self.parse('diagnostic\n{"messages":[]}')
        self.assertNotEqual(result.returncode, 0, "inbox JSON errors must not become an empty message")
        self.assertIn("JSONDecodeError", result.stderr)

    def test_valid_inbox_without_the_message_still_reaches_the_body_assertion(self):
        result = self.parse('{"messages":[],"has_more":false}')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")


class ServicePortTests(unittest.TestCase):
    def test_explicit_ports_are_preserved_without_a_docker_allocation(self):
        script = "\n".join([
            "set -euo pipefail",
            function("allocate_service_ports"),
            'docker() { echo "unexpected docker call" >&2; exit 1; }',
            'AWEB_PORT=18100; AWID_PORT=18110; PORT_ALLOCATOR=""',
            'allocate_service_ports',
            'printf "%s %s" "$AWEB_PORT" "$AWID_PORT"',
        ])
        result = subprocess.run(["bash", "-c", script], capture_output=True,
                                text=True, check=True)
        self.assertEqual(result.stdout, "18100 18110")


@unittest.skipUnless(os.environ.get("AWEB_TEST_DOCKER_PORTS") == "1", "real Docker proof enabled by test-e2e")
class DockerServicePortTests(unittest.TestCase):
    image = "python:3.12-slim"

    def docker(self, *args, check=True):
        return subprocess.run(["docker", *args], capture_output=True, text=True,
                              check=check, timeout=60).stdout.strip()

    def setUp(self):
        self.project = "aw-journey-ports-" + uuid.uuid4().hex[:12]
        self.network = self.project
        self.addCleanup(self.docker, "network", "rm", self.network, check=False)
        self.docker("network", "create", self.network)
        subnet = ipaddress.ip_network(json.loads(self.docker("network", "inspect", self.network))[0]["IPAM"]["Config"][0]["Subnet"])
        self.addresses = [str(subnet[10]), str(subnet[11])]
        self.client = self.project + "-client"
        self.addCleanup(self.docker, "rm", "-fv", self.client, check=False)
        self.docker("run", "-d", "--name", self.client, "--network", self.network,
                    "--cpus", ".25", "--memory", "64m", "--pids-limit", "32",
                    "--add-host", "aweb-docker.test:host-gateway", self.image,
                    "python", "-c", "import time; time.sleep(600)")

    def allocate(self, suffix, aweb="", awid=""):
        project = self.project + suffix
        allocator = project + "-ports"
        self.addCleanup(self.docker, "rm", "-fv", allocator, check=False)
        script = "\n".join([
            "set -euo pipefail", function("allocate_service_ports"),
            'AWEB_E2E_PORT="$1"; AWID_E2E_PORT="$2"; PROJECT="$3"; PORT_ALLOCATOR=""',
            next(line for line in JOURNEY.read_text().splitlines() if line.startswith('AWEB_PORT=')),
            next(line for line in JOURNEY.read_text().splitlines() if line.startswith('AWID_PORT=')),
            'allocate_service_ports',
            'printf "%s %s %s" "$AWEB_PORT" "$AWID_PORT" "$PORT_ALLOCATOR"',
        ])
        result = subprocess.run(["bash", "-c", script, "ports", aweb, awid, project],
                                capture_output=True, text=True, check=True)
        fields = result.stdout.split()
        self.assertEqual(len(fields), 3, "journey defaults must allocate ports on the daemon")
        self.assertEqual(fields[2], allocator)
        ports = [int(port) for port in fields[:2]]
        self.assertNotEqual(*ports)
        self.docker("rm", "-fv", allocator)
        return ports

    def start_server(self, suffix, address, port):
        name = self.project + suffix
        self.addCleanup(self.docker, "rm", "-fv", name, check=False)
        # docker exec checks listener readiness locally, without warming the
        # host-gateway tuple that the client below must exercise exactly once.
        self.docker("run", "-d", "--name", name, "--network", self.network,
                    "--ip", address, "--cpus", ".25", "--memory", "64m", "--pids-limit", "32",
                    "-p", f"{port}:8000", self.image,
                    "python", "-m", "http.server", "8000")
        self.docker("exec", name, "python", "-c",
                    """
import socket, time
for _ in range(100):
    try:
        socket.create_connection(("127.0.0.1", 8000), .1).close()
        break
    except OSError:
        time.sleep(.02)
else:
    raise RuntimeError("server not listening")
""")
        return name

    def request(self, port):
        self.docker("exec", self.client, "python", "-c", """
import socket
s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.settimeout(3)
s.bind(('', 43123))
s.connect(('aweb-docker.test', int(__import__('sys').argv[1])))
s.sendall(b'GET / HTTP/1.0\\r\\nHost: probe\\r\\n\\r\\n')
data = b''
while chunk := s.recv(4096): data += chunk
s.close()
assert data.startswith(b'HTTP/1.0 200'), data[:120]
""", str(port))

    def test_new_journey_reaches_new_backend_with_the_same_client_source_port(self):
        first = self.allocate("-first")
        server = self.start_server("-first-server", self.addresses[0], first[0])
        self.request(first[0])
        self.docker("rm", "-fv", server)
        second = self.allocate("-second")
        self.assertTrue(set(first).isdisjoint(second),
                        "consecutive journeys reused published ports across backend replacement")
        self.start_server("-second-server", self.addresses[1], second[0])
        self.request(second[0])

    def test_one_explicit_port_keeps_its_value_and_allocates_the_other(self):
        selected = self.allocate("-select")[0]
        actual = self.allocate("-partial", aweb=str(selected))
        self.assertEqual(actual[0], selected)
        self.assertNotEqual(actual[1], selected)


if __name__ == "__main__":
    unittest.main()
